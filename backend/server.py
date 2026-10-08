#!/usr/bin/env python3
import os, json, sqlite3, hashlib, hmac, urllib.request, urllib.parse, ipaddress, base64
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone

DB=os.getenv('DB_PATH','analytics.sqlite3')
PORT=int(os.getenv('PORT','8080'))
HOST=os.getenv('HOST','0.0.0.0')
HASH_SECRET=os.getenv('HASH_SECRET','change-me')
ADMIN_TOKEN=os.getenv('ADMIN_TOKEN','')
MAXMIND_URL=os.getenv('MAXMIND_URL','')
MAXMIND_LICENSE_KEY=os.getenv('MAXMIND_LICENSE_KEY','')
REPORT_DIR=os.getenv('REPORT_DIR','reports')
GITHUB_TOKEN=os.getenv('GITHUB_TOKEN','')
REPORT_REPO=os.getenv('REPORT_REPO','')
REPORT_BRANCH=os.getenv('REPORT_BRANCH','main')
MAX_BODY=16_384

FIELDS=['id','created_at','event','target','page','ref','ip_hash','country','country_code','region','city','timezone','latitude','longitude','accuracy_radius_km','asn','organization','network','user_agent_hash']

def db():
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    c.execute('''CREATE TABLE IF NOT EXISTS clicks(
      id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, event TEXT NOT NULL,
      target TEXT NOT NULL, page TEXT, ref TEXT, ip_hash TEXT,
      country TEXT, country_code TEXT, region TEXT, city TEXT, timezone TEXT,
      latitude REAL, longitude REAL, accuracy_radius_km REAL, asn INTEGER,
      organization TEXT, network TEXT, user_agent_hash TEXT)''')
    c.commit(); return c

def hashv(v):
    return hmac.new(HASH_SECRET.encode(), v.encode(), hashlib.sha256).hexdigest() if v else ''

def client_ip(h):
    if os.getenv('TRUST_PROXY','0')=='1' and h.headers.get('X-Forwarded-For'):
        return h.headers['X-Forwarded-For'].split(',')[0].strip()
    return h.client_address[0]

def geo(ip):
    try:
        obj=ipaddress.ip_address(ip)
        if not obj.is_global: return {}
    except Exception:
        return {}
    if not MAXMIND_URL: return {}
    try:
        q=MAXMIND_URL+'?'+urllib.parse.urlencode({'ip':ip,'license_key':MAXMIND_LICENSE_KEY})
        with urllib.request.urlopen(q,timeout=5) as r:
            return json.loads(r.read().decode())
    except Exception:
        return {}

def admin_ok(h):
    return bool(ADMIN_TOKEN) and hmac.compare_digest(h.headers.get('Authorization',''),'Bearer '+ADMIN_TOKEN)

def report_rows(limit=50000):
    c=db(); rows=[dict(x) for x in c.execute('SELECT * FROM clicks ORDER BY id ASC LIMIT ?', (limit,))]; c.close(); return rows

def esc(v):
    return ('' if v is None else str(v)).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')

def build_reports():
    rows=report_rows()
    generated=datetime.now(timezone.utc).isoformat()
    html='''<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Kupon Tıklama Raporu</title><style>body{font:15px system-ui;background:#101318;color:#eee;margin:0;padding:20px}main{max-width:1400px;margin:auto}h1{margin-top:0}.meta{color:#aaa;margin-bottom:16px}.table{overflow:auto;background:#181c22;border-radius:12px}table{border-collapse:collapse;width:100%;min-width:1300px}th,td{padding:9px;border-bottom:1px solid #30353d;text-align:left;vertical-align:top}th{position:sticky;top:0;background:#222831}code{word-break:break-all}</style></head><body><main><h1>Kupon Tıklama Raporu</h1>'''
    html+=f'<div class="meta">Olay sayısı: {len(rows)} | Oluşturulma: {esc(generated)}</div><div class="table"><table><thead><tr>'
    html+=''.join(f'<th>{esc(x)}</th>' for x in FIELDS)+'</tr></thead><tbody>'
    for r in rows:
        html+='<tr>'+''.join(f'<td><code>{esc(r.get(x,""))}</code></td>' for x in FIELDS)+'</tr>'
    html+='</tbody></table></div></main></body></html>\n'
    txt=['KUPON TIKLAMA RAPORU',f'Olay sayısı: {len(rows)}',f'Oluşturulma: {generated}','']
    for i,r in enumerate(rows,1):
        txt.append(f'--- OLAY {i} ---')
        for x in FIELDS: txt.append(f'{x}: {r.get(x,"")}')
        txt.append('')
    return html,'\n'.join(txt)

def github_put(path, content):
    if not (GITHUB_TOKEN and REPORT_REPO): return False
    data=base64.b64encode(content.encode('utf-8')).decode()
    url=f'https://api.github.com/repos/{REPORT_REPO}/contents/{urllib.parse.quote(path)}'
    headers={'Authorization':f'Bearer {GITHUB_TOKEN}','Accept':'application/vnd.github+json','User-Agent':'kupon-analytics','Content-Type':'application/json'}
    body={'message':f'Update report {path}','content':data,'branch':REPORT_BRANCH}
    try:
        req=urllib.request.Request(url,data=json.dumps(body).encode(),headers=headers,method='PUT')
        with urllib.request.urlopen(req,timeout=10) as r: return 200 <= r.status < 300
    except urllib.error.HTTPError as e:
        if e.code != 422: return False
        try:
            obj=json.loads(e.read().decode()); sha=obj.get('content',{}).get('sha')
            if not sha: return False
            body['sha']=sha
            req=urllib.request.Request(url,data=json.dumps(body).encode(),headers=headers,method='PUT')
            with urllib.request.urlopen(req,timeout=10) as r: return 200 <= r.status < 300
        except Exception: return False
    except Exception: return False

def publish_reports():
    html,txt=build_reports(); Path(REPORT_DIR).mkdir(parents=True,exist_ok=True)
    Path(REPORT_DIR,'click-report.html').write_text(html,encoding='utf-8')
    Path(REPORT_DIR,'click-report.txt').write_text(txt,encoding='utf-8')
    return {'local_html':True,'local_txt':True,'github_html':github_put('reports/click-report.html',html),'github_txt':github_put('reports/click-report.txt',txt)}

class H(BaseHTTPRequestHandler):
    def sendj(self,code,obj):
        b=json.dumps(obj,ensure_ascii=False).encode(); self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        path=self.path.split('?')[0]
        if path=='/health': return self.sendj(200,{'ok':True,'service':'kupon-analytics'})
        if path=='/api/report':
            if not admin_ok(self): return self.sendj(401,{'error':'unauthorized'})
            rows=report_rows(); return self.sendj(200,{'ok':True,'count':len(rows),'events':rows})
        if path in ('/api/report.html','/api/report.txt'):
            if not admin_ok(self): return self.sendj(401,{'error':'unauthorized'})
            html,txt=build_reports(); content=html if path.endswith('.html') else txt; b=content.encode()
            self.send_response(200); self.send_header('Content-Type',('text/html' if path.endswith('.html') else 'text/plain')+'; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b); return
        if path=='/api/report/publish':
            if not admin_ok(self): return self.sendj(401,{'error':'unauthorized'})
            return self.sendj(200,publish_reports())
        return self.sendj(404,{'error':'not_found'})
    def do_POST(self):
        if self.path.split('?')[0]!='/api/click': return self.sendj(404,{'error':'not_found'})
        try:
            n=min(int(self.headers.get('Content-Length','0')),MAX_BODY); data=json.loads(self.rfile.read(n) or b'{}')
            if data.get('consent') is not True: return self.sendj(400,{'error':'consent_required'})
            event=str(data.get('event','click'))[:80]; target=str(data.get('target',''))[:200]; page=str(data.get('page',''))[:500]; ref=str(data.get('ref',''))[:200]
            ip=client_ip(self); ua=self.headers.get('User-Agent',''); g=geo(ip); now=datetime.now(timezone.utc).isoformat()
            c=db(); c.execute('INSERT INTO clicks(created_at,event,target,page,ref,ip_hash,country,country_code,region,city,timezone,latitude,longitude,accuracy_radius_km,asn,organization,network,user_agent_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(now,event,target,page,ref,hashv(ip),g.get('country'),g.get('country_code'),g.get('region'),g.get('city'),g.get('timezone'),g.get('latitude'),g.get('longitude'),g.get('accuracy_radius_km'),g.get('asn'),g.get('organization'),g.get('network'),hashv(ua))); c.commit(); c.close(); publish_reports(); return self.sendj(202,{'ok':True})
        except Exception:
            return self.sendj(400,{'error':'invalid_request'})

if __name__=='__main__':
    db().close(); ThreadingHTTPServer((HOST,PORT),H).serve_forever()
