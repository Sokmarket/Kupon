const ALLOWED_ORIGIN = "https://sokmarket.github.io";
const MAX_BODY_BYTES = 2048;

function response(data, status = 200, origin = ALLOWED_ORIGIN) {
return new Response(JSON.stringify(data), {
status,
headers: {
"Content-Type": "application/json; charset=utf-8",
"Cache-Control": "no-store",
"Access-Control-Allow-Origin": origin,
"Access-Control-Allow-Methods": "POST, OPTIONS",
"Access-Control-Allow-Headers": "Content-Type",
"Vary": "Origin"
}
});
}

function safeText(value, max = 120) {
if (typeof value !== "string") return "";
return value.replace(/[\r\n\t]/g, " ").trim().slice(0, max);
}

export default {
async fetch(request, env) {
const origin = request.headers.get("Origin") || "";

if (origin !== ALLOWED_ORIGIN) {
  return response({ ok: false, error: "Origin not allowed" }, 403);
}

if (request.method === "OPTIONS") {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }
  });
}

// KUPON_GET_REPORTS: public repository'deki TXT click kayıtlarını oku.
if (request.method === "GET") {
  let listing;
  try {
    const url = `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/rapor?ref=${encodeURIComponent(env.GITHUB_BRANCH)}`;
    const r = await fetch(url, {headers:{
      "Authorization": `Bearer ${env.GITHUB_TOKEN}`,
      "Accept":"application/vnd.github+json",
      "X-GitHub-Api-Version":"2022-11-28",
      "User-Agent":"Kupon-Click-Report"
    }});
    if (!r.ok) {
      let detail = {};
      try { detail = await r.clone().json(); } catch {}
      const message = typeof detail.message === "string"
        ? detail.message.replace(/[\\r\\n\\t]/g, " ").slice(0, 180)
        : "No additional message";
      return response({
        ok: false,
        error: "GitHub report list failed",
        github_status: r.status,
        github_message: message,
        config_present: Boolean(env.GITHUB_OWNER && env.GITHUB_REPO && env.GITHUB_BRANCH)
      }, 502);
    }
    listing = await r.json();
  } catch {
    return response({ok:false,error:"GitHub connection failed"},502);
  }
  const files = Array.isArray(listing)
    ? listing.filter(x => x.type === "file" && /^tiklama-.*\.txt$/.test(x.name)).slice(-100)
    : [];
  const records = [];
  for (const file of files) {
    try {
      const url = `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/${file.path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(env.GITHUB_BRANCH)}`;
      const r = await fetch(url, {headers:{
      "Authorization": `Bearer ${env.GITHUB_TOKEN}`,
        "Accept":"application/vnd.github+json",
        "X-GitHub-Api-Version":"2022-11-28",
        "User-Agent":"Kupon-Click-Report"
      }});
      if (!r.ok) continue;
      const data = await r.json();
      if (!data.content) continue;
      const body = decodeURIComponent(escape(atob(data.content.replace(/\s/g,""))));
      const field = key => {
        const prefix = key + ":";
        const line = body.split(/\r?\n/).find(x => x.trimStart().startsWith(prefix));
        return line ? line.trimStart().slice(prefix.length).trim() : "";
      };
      records.push({
        id:file.name,
        timestamp:field("Zaman (UTC)"),
        event:field("Olay"),
        page:field("Sayfa"),
        action:field("İşlem"),
        coupon_code:field("Kupon kodu"),
        file:file.path
      });
    } catch {}
  }
  records.sort((a,b) => (b.timestamp || "").localeCompare(a.timestamp || ""));
  return response({ok:true,count:records.length,records,updated:new Date().toISOString()});
}

if (request.method !== "POST") {
  return response({ ok: false, error: "GET or POST required" }, 405);
}

if (!env.GITHUB_TOKEN) {
  return response({ ok: false, error: "Server secret missing" }, 500);
}

const contentType = request.headers.get("Content-Type") || "";
if (!contentType.includes("application/json")) {
  return response({ ok: false, error: "JSON required" }, 415);
}

const declaredSize = Number(request.headers.get("Content-Length") || 0);
if (declaredSize > MAX_BODY_BYTES) {
  return response({ ok: false, error: "Request too large" }, 413);
}

let input;
try {
  const raw = await request.text();
  if (new TextEncoder().encode(raw).length > MAX_BODY_BYTES) {
    return response({ ok: false, error: "Request too large" }, 413);
  }
  input = JSON.parse(raw);
} catch {
  return response({ ok: false, error: "Invalid JSON" }, 400);
}

// Yalnızca izin verilen alanları kaydet.
// IP adresi, çerez, user-agent ve kişisel profil kaydedilmez.
const now = new Date();
const event = {
  event: safeText(input.event, 60) === "page_visit" ? "page_visit" : "kupon_click",
  timestamp_utc: now.toISOString(),
  page: safeText(input.page, 200),
  action: safeText(input.action, 60) || "copy_coupon",
  coupon_code: safeText(input.coupon_code, 40)
};

const timestamp = now.toISOString()
  .replace(/[:.]/g, "-");
const randomId = crypto.randomUUID();
const filename = `tiklama-${timestamp}-${randomId}.txt`;
const path = `rapor/${filename}`;

const report = [
  "KUPON TIKLAMA RAPORU",
  "====================",
  `Zaman (UTC): ${event.timestamp_utc}`,
  `Olay: ${event.event}`,
  `Sayfa: ${event.page || "(belirtilmedi)"}`,
  `İşlem: ${event.action}`,
  `Kupon kodu: ${event.coupon_code || "(belirtilmedi)"}`,
  "",
  "Not: Bu dosya bir tıklama olayını kaydeder.",
  "IP adresi ve tarayıcı kimliği kaydedilmemiştir.",
  ""
].join("\n");

const apiUrl =
  `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}` +
  `/contents/${path.split("/").map(encodeURIComponent).join("/")}`;

let gh;
try {
  gh = await fetch(apiUrl, {
    method: "PUT",
    headers: {
      "Authorization": `Bearer ${env.GITHUB_TOKEN}`,
      "Accept": "application/vnd.github+json",
      "Content-Type": "application/json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "Kupon-Click-Report"
    },
    body: JSON.stringify({
      message: `Add click report ${randomId}`,
      content: btoa(unescape(encodeURIComponent(report))),
      branch: env.GITHUB_BRANCH
    })
  });
} catch {
  return response({ ok: false, error: "GitHub connection failed" }, 502);
}

if (!gh.ok) {
  // GitHub'ın token veya iç yanıtını ziyaretçiye açma.
  return response({
    ok: false,
    error: "GitHub report write failed",
    status: gh.status
  }, 502);
}

return response({
  ok: true,
  file: path,
  timestamp_utc: event.timestamp_utc
}, 201);

}
};
