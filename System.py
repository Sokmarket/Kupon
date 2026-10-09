#!/usr/bin/env python3

import os
import json
import sqlite3
import shutil
import threading
import time
import csv
import io
import logging
import geoip2.database
import phonenumbers
from phonenumbers import carrier, number_type
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from ipaddress import ip_address

# --- SİSTEM KONFİQURASİYASI ---
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("ANALYTICS_DB", os.path.join(BASE_DIR, "..", "analytics.sqlite3"))
MAXMIND_DB_PATH = os.getenv("MAXMIND_DB_PATH", os.path.join(BASE_DIR, "..", "GeoLite2-City.mmdb"))
BACKUP_DIR = os.getenv("BACKUP_DIR", os.path.join(BASE_DIR, "..", "backups"))
LOG_PATH = os.getenv("LOG_PATH", os.path.join(BASE_DIR, "..", "system.log"))

# DDoS və Rate Limiting Tənzimləmələri
RATE_LIMIT_WINDOW = 10       
RATE_LIMIT_MAX_REQUESTS = 25 
request_records = {}
rate_lock = threading.Lock()

# Loglama Quraşdırması
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(threadName)s: %(message)s"
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(console_handler)

# --- VERİTABANI VƏ THREAD-SAFE İDARƏETMƏ ---
def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = get_db_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS clicks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event TEXT NOT NULL,
                target TEXT,
                page TEXT,
                ref TEXT,
                referer TEXT,
                consent INTEGER NOT NULL,
                client_ip TEXT,
                user_agent TEXT,
                app_package TEXT,
                phone TEXT,
                email TEXT,
                full_name TEXT,
                country TEXT,
                country_code TEXT,
                continent TEXT,
                continent_code TEXT,
                region TEXT,
                region_code TEXT,
                city TEXT,
                postal_code TEXT,
                latitude REAL,
                longitude REAL,
                accuracy_radius_km REAL,
                timezone TEXT,
                maxmind_success INTEGER DEFAULT 0,
                phone_valid INTEGER DEFAULT 0,
                phone_country_code INTEGER,
                phone_national_number TEXT,
                phone_carrier TEXT,
                phone_line_type TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_clicks_created ON clicks(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_clicks_ip ON clicks(client_ip)")
        conn.commit()
        logging.info("Veritabanı şeması (App Package OSINT daxil olmaqla) uğurla quruldu.")
    except Exception as e:
        logging.error(f"Veritabanı qurulum xətası: {e}")
        raise
    finally:
        conn.close()

# --- ARXA PLAN AVTOMATLAŞDIRMA VƏ TƏMİZLİK ---
def run_automations():
    while True:
        try:
            os.makedirs(BACKUP_DIR, exist_ok=True)
            if os.path.exists(DB_PATH):
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                backup_path = os.path.join(BACKUP_DIR, f"analytics_backup_{timestamp}.sqlite3")
                shutil.copy2(DB_PATH, backup_path)
                logging.info(f"Avtomatik yedək yaradıldı: {backup_path}")
                
                now = time.time()
                for f in os.listdir(BACKUP_DIR):
                    fp = os.path.join(BACKUP_DIR, f)
                    if os.path.isfile(fp) and (now - os.path.getmtime(fp) > 7 * 86400):
                        os.remove(fp)

            with rate_lock:
                current_time = time.time()
                ips_to_remove = []
                for ip, timestamps in request_records.items():
                    valid_ts = [t for t in timestamps if current_time - t < RATE_LIMIT_WINDOW]
                    if valid_ts:
                        request_records[ip] = valid_ts
                    else:
                        ips_to_remove.append(ip)
                for ip in ips_to_remove:
                    del request_records[ip]

        except Exception as e:
            logging.error(f"Avtomatlaşdırma xətası: {e}")
        
        time.sleep(3600)

def check_rate_limit(ip):
    current_time = time.time()
    with rate_lock:
        timestamps = request_records.get(ip, [])
        timestamps = [t for t in timestamps if current_time - t < RATE_LIMIT_WINDOW]
        if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
            request_records[ip] = timestamps
            return False
        timestamps.append(current_time)
        request_records[ip] = timestamps
        return True

# --- OSINT VƏ ANALİZ FUNksiyalari ---
def get_client_ip(handler):
    forwarded = handler.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return handler.client_address[0]

def clean_input(value, limit=1000):
    if value is None:
        return ""
    return str(value).replace("\x00", "").strip()[:limit]

def geoip_lookup(ip):
    try:
        obj = ip_address(ip)
        if obj.is_private or obj.is_loopback or obj.is_reserved:
            return {"maxmind_success": 0}
    except ValueError:
        return {"maxmind_success": 0}

    if not os.path.exists(MAXMIND_DB_PATH):
        return {"maxmind_success": 0}

    try:
        with geoip2.database.Reader(MAXMIND_DB_PATH) as reader:
            response = reader.city(ip)
            return {
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "continent": response.continent.name,
                "continent_code": response.continent.code,
                "region": response.subdivisions.most_specific.name if response.subdivisions else None,
                "region_code": response.subdivisions.most_specific.iso_code if response.subdivisions else None,
                "city": response.city.name,
                "postal_code": response.postal.code,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "accuracy_radius_km": response.location.accuracy_radius,
                "timezone": response.location.time_zone,
                "maxmind_success": 1
            }
    except Exception:
        return {"maxmind_success": 0}

def phone_intel_lookup(phone_str):
    if not phone_str:
        return {"phone_valid": 0}
    try:
        parsed = phonenumbers.parse(phone_str, None)
        is_valid = phonenumbers.is_valid_number(parsed)
        country_code = parsed.country_code
        national_number = str(parsed.national_number)
        
        car = carrier.name_for_number(parsed, "en")
        n_type = number_type(parsed)
        type_map = {
            phonenumbers.PhoneNumberType.MOBILE: "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed or Mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
            phonenumbers.PhoneNumberType.VOIP: "VoIP"
        }
        line_type = type_map.get(n_type, "Unknown")
        
        return {
            "phone_valid": 1 if is_valid else 0,
            "phone_country_code": country_code,
            "phone_national_number": national_number,
            "phone_carrier": car if car else "Unknown",
            "phone_line_type": line_type
        }
    except Exception:
        return {"phone_valid": 0}

def save_click_to_db(handler, data):
    client_ip = get_client_ip(handler)
    user_agent = clean_input(handler.headers.get("User-Agent", ""), 2000)
    geo = geoip_lookup(client_ip)
    
    raw_phone = clean_input(data.get("phone"))
    phone_intel = phone_intel_lookup(raw_phone)
    
    # WebView və ya tətbiq paket adı (məsələn: com.htmltoapk.osint)
    app_package = clean_input(data.get("app_package", "com.htmltoapk.osint"))
    
    now = datetime.now(timezone.utc).isoformat()
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO clicks (
                created_at, event, target, page, ref, referer, consent,
                client_ip, user_agent, app_package, phone, email, full_name, country, 
                country_code, continent, continent_code, region, region_code, 
                city, postal_code, latitude, longitude, accuracy_radius_km, 
                timezone, maxmind_success, phone_valid, phone_country_code, 
                phone_national_number, phone_carrier, phone_line_type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            now, clean_input(data.get("event", "click")), clean_input(data.get("target")),
            clean_input(data.get("page")), clean_input(data.get("ref")), clean_input(data.get("referer")),
            1 if data.get("consent", True) else 0, client_ip, user_agent, app_package,
            raw_phone, clean_input(data.get("email")), clean_input(data.get("full_name")),
            geo.get("country"), geo.get("country_code"), geo.get("continent"),
            geo.get("continent_code"), geo.get("region"), geo.get("region_code"),
            geo.get("city"), geo.get("postal_code"), geo.get("latitude"),
            geo.get("longitude"), geo.get("accuracy_radius_km"), geo.get("timezone"),
            geo.get("maxmind_success", 0), phone_intel.get("phone_valid", 0),
            phone_intel.get("phone_country_code"), phone_intel.get("phone_national_number"),
            phone_intel.get("phone_carrier"), phone_intel.get("phone_line_type")
        ))
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        logging.error(f"Veritabanına yazma xətası: {e}")
        raise
    finally:
        conn.close()

def fetch_all_records():
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT * FROM clicks ORDER BY id ASC").fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

# --- HTTP SERVER İDARƏETMƏSİ ---
class SystemHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logging.info(f"{self.client_address[0]} - {format % args}")

    def send_json(self, status, payload):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def send_csv(self):
        records = fetch_all_records()
        output = io.StringIO()
        if records:
            writer = csv.DictWriter(output, fieldnames=records[0].keys())
            writer.writeheader()
            for r in records:
                writer.writerow(r)
        csv_bytes = output.getvalue().encode("utf-8")
        
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", "attachment; filename=raw_analytics_export.csv")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(csv_bytes)

    def send_text(self):
        records = fetch_all_records()
        lines = []
        lines.append("=== REKLAMA CLICK LAB - APP & PHONE OSINT REPORT ===")
        lines.append(f"Cəmi qeyd sayı: {len(records)}")
        lines.append("-" * 90)
        for r in records:
            phone_info = f"Tel: {r['phone']} (Operator: {r['phone_carrier']}, Tip: {r['phone_line_type']})" if r['phone'] else "Tel: Yoxdur"
            lines.append(
                f"ID: {r['id']} | App: {r['app_package']} | IP: {r['client_ip']} | "
                f"Ölkə: {r['country']} | {phone_info}"
            )
        text_bytes = "\n".join(lines).encode("utf-8")
        
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(text_bytes)

    def do_POST(self):
        client_ip = get_client_ip(self)
        if not check_rate_limit(client_ip):
            self.send_json(429, {"error": "Həddindən artıq sorğu göndərildi (Rate Limit Exceeded)."})
            return

        parsed_path = urlparse(self.path).path
        if parsed_path == "/api/click":
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
                if content_length > 65536:
                    self.send_json(413, {"error": "Payload Too Large."})
                    return
                
                body_data = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
                parsed_json = json.loads(body_data)
                
                inserted_id = save_click_to_db(self, parsed_json)
                self.send_json(201, {"success": True, "id": inserted_id})
            except json.JSONDecodeError:
                self.send_json(400, {"error": "Yanlış JSON formatı."})
            except Exception as e:
                logging.error(f"POST /api/click xətası: {e}")
                self.send_json(500, {"error": "Daxili server xətası."})
        else:
            self.send_json(404, {"error": "Tapılmadı."})

    def do_GET(self):
        client_ip = get_client_ip(self)
        if not check_rate_limit(client_ip):
            self.send_json(429, {"error": "Həddindən artıq sorğu göndərildi (Rate Limit Exceeded)."})
            return

        parsed_path = urlparse(self.path).path
        try:
            if parsed_path == "/api/report.json":
                records = fetch_all_records()
                self.send_json(200, {"total": len(records), "data": records})
            elif parsed_path == "/api/report.txt":
                self.send_text()
            elif parsed_path == "/api/export.csv":
                self.send_csv()
            else:
                self.send_json(404, {"error": "Tapılmadı."})
        except Exception as e:
            logging.error(f"GET {parsed_path} xətası: {e}")
            self.send_json(500, {"error": "Daxili server xətası."})

def main():
    init_db()
    
    auto_thread = threading.Thread(target=run_automations, name="AutomationWorker", daemon=True)
    auto_thread.start()
    
    server = ThreadingHTTPServer((HOST, PORT), SystemHandler)
    logging.info(f"App OSINT System Server işə düşdü -> http://{HOST}:{PORT}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Server istifadəçi tərəfindən dayandırıldı.")
        server.server_close()

if __name__ == "__main__":
    main()
