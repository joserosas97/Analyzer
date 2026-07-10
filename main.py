import asyncio
import base64
import os
import secrets
import socket
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

load_dotenv()

app = FastAPI(title="URL Threat Analyzer")
app.mount("/static", StaticFiles(directory="static"), name="static")

VT_KEY      = os.getenv("VIRUSTOTAL_API_KEY", "")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

APP_USERNAME = os.getenv("APP_USERNAME", "admin")
APP_PASSWORD = os.getenv("APP_PASSWORD", "")

if not APP_PASSWORD:
    print(
        "[WARN] APP_PASSWORD no está configurada: la app está abierta sin autenticación. "
        "Define APP_USERNAME/APP_PASSWORD en .env antes de exponerla en red o Render."
    )


class BasicAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if not APP_PASSWORD:
            return await call_next(request)
        auth = request.headers.get("authorization", "")
        if auth.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth[6:]).decode("utf-8")
                user, _, pwd = decoded.partition(":")
            except Exception:
                user, pwd = "", ""
            if secrets.compare_digest(user, APP_USERNAME) and secrets.compare_digest(pwd, APP_PASSWORD):
                return await call_next(request)
        return Response(
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="ThreatScope"'},
        )


RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 10
RATE_LIMITED_PATHS = {"/api/scan", "/api/scan-ips"}
_rate_buckets: dict[str, deque] = defaultdict(deque)


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.method == "POST" and request.url.path in RATE_LIMITED_PATHS:
            client_ip = request.client.host if request.client else "unknown"
            now = time.monotonic()
            bucket = _rate_buckets[client_ip]
            while bucket and now - bucket[0] > RATE_LIMIT_WINDOW:
                bucket.popleft()
            if len(bucket) >= RATE_LIMIT_MAX:
                return JSONResponse(
                    {"error": "Demasiadas solicitudes. Intenta de nuevo en unos segundos."},
                    status_code=429,
                )
            bucket.append(now)
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data: https://urlscan.io; "
            "connect-src 'self'; "
            "script-src 'self'; "
            "frame-ancestors 'none'"
        )
        return response


# El orden importa: se ejecutan en orden inverso al de registro (el último
# agregado corre primero). Queremos: headers de seguridad en toda respuesta,
# luego auth, luego rate limit, luego la ruta.
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(BasicAuthMiddleware)


class ScanRequest(BaseModel):
    url: str

class IPListRequest(BaseModel):
    ips: list[str]

class KeysRequest(BaseModel):
    virustotal: str = ""
    urlscan: str = ""
    abuseipdb: str = ""


def resolve_ip(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


async def check_virustotal(url: str, client: httpx.AsyncClient) -> dict:
    if not VT_KEY:
        return {"error": "API key no configurada"}
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    headers = {"x-apikey": VT_KEY}
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=20,
        )
        if r.status_code == 404:
            submit = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers, data={"url": url}, timeout=20,
            )
            if submit.status_code not in (200, 201):
                return {"error": f"Error al enviar URL: {submit.status_code}"}
            analysis_id = submit.json().get("data", {}).get("id", "")
            await asyncio.sleep(5)
            r2 = await client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers, timeout=20,
            )
            attrs = r2.json().get("data", {}).get("attributes", {})
            stats = attrs.get("stats", {})
            engine_results = attrs.get("results", {})
        else:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            engine_results = attrs.get("last_analysis_results", {})

        detections = [
            {"engine": name, "result": info.get("result", ""), "category": info.get("category", "")}
            for name, info in engine_results.items()
            if info.get("category") in ("malicious", "suspicious")
        ]
        detections.sort(key=lambda x: x["category"])
        categories = attrs.get("categories", {})

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "detections": detections[:10],
            "categories": list(set(categories.values())),
            "tags": attrs.get("tags", []),
            "redirection": attrs.get("last_final_url", "") or None,
        }
    except Exception as e:
        return {"error": str(e)}


async def check_urlscan(url: str, client: httpx.AsyncClient) -> dict:
    if not URLSCAN_KEY:
        return {"error": "API key no configurada"}
    headers = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}

    def parse_result(res: dict, scan_uuid: str) -> dict:
        verdicts  = res.get("verdicts", {})
        overall   = verdicts.get("overall", {})
        urlscan_v = verdicts.get("urlscan", {})
        score     = max(overall.get("score", 0), urlscan_v.get("score", 0))
        malicious = bool(overall.get("malicious") or urlscan_v.get("malicious"))
        page  = res.get("page", {})
        meta  = res.get("meta", {})
        lists = res.get("lists", {})
        tech_raw = meta.get("processors", {}).get("wappa", {}).get("data", [])
        return {
            "malicious": malicious,
            "score": score,
            "categories": list(set(overall.get("categories", []) + urlscan_v.get("categories", []))),
            "brands": overall.get("brands", []),
            "page_title": page.get("title", ""),
            "server": page.get("server", ""),
            "mime_type": page.get("mimeType", ""),
            "technologies": [t.get("app", "") for t in tech_raw if t.get("app")],
            "ips_contacted": lists.get("ips", [])[:15],
            "domains_contacted": lists.get("domains", [])[:15],
            "countries_contacted": list(set(lists.get("countries", []))),
            "total_requests": res.get("stats", {}).get("total", 0),
            "screenshot": f"https://urlscan.io/screenshots/{scan_uuid}.png",
            "report_url": f"https://urlscan.io/result/{scan_uuid}/",
        }

    try:
        search = await client.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f'page.url:"{url}"', "size": 1},
            headers=headers, timeout=15,
        )
        if search.status_code == 200:
            results = search.json().get("results", [])
            if results:
                scan_uuid = results[0].get("task", {}).get("uuid", "")
                if scan_uuid:
                    r = await client.get(f"https://urlscan.io/api/v1/result/{scan_uuid}/", headers=headers, timeout=15)
                    if r.status_code == 200:
                        return parse_result(r.json(), scan_uuid)

        submit = await client.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers, json={"url": url, "visibility": "public"}, timeout=15,
        )
        if submit.status_code not in (200, 201):
            return {"error": f"Error al enviar: {submit.status_code}"}
        scan_uuid = submit.json().get("uuid", "")

        for _ in range(5):
            await asyncio.sleep(8)
            r = await client.get(f"https://urlscan.io/api/v1/result/{scan_uuid}/", headers=headers, timeout=20)
            if r.status_code == 200:
                return parse_result(r.json(), scan_uuid)

        return {
            "screenshot": f"https://urlscan.io/screenshots/{scan_uuid}.png",
            "report_url": f"https://urlscan.io/result/{scan_uuid}/",
            "error": "Scan en proceso, revisa el reporte en URLscan.io",
        }
    except Exception as e:
        return {"error": str(e)}


async def check_abuseipdb(ip: str, client: httpx.AsyncClient) -> dict:
    if not ABUSEIPDB_KEY:
        return {"error": "API key no configurada"}
    if not ip:
        return {"error": "IP vacía"}
    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=15,
        )
        data = r.json().get("data", {})
        return {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "usage_type": data.get("usageType", "N/A"),
            "total_reports": data.get("totalReports", 0),
            "distinct_users": data.get("numDistinctUsers", 0),
            "last_reported": data.get("lastReportedAt", ""),
            "is_tor": data.get("isTor", False),
        }
    except Exception as e:
        return {"error": str(e)}


def geo_from_abuse(abuse: dict) -> dict:
    """Deriva país/hosting a partir de AbuseIPDB en vez de consultar ip-api.com
    (que solo ofrece HTTPS en su plan pago, filtrando las IPs consultadas en
    texto plano)."""
    if not abuse or abuse.get("error"):
        return {}
    usage = (abuse.get("usage_type") or "").lower()
    is_hosting = any(
        k in usage
        for k in ("hosting", "data center", "datacenter", "colocation", "content delivery")
    )
    return {
        "country": abuse.get("country", ""),
        "is_hosting": is_hosting,
    }


async def check_whois(domain: str, client: httpx.AsyncClient) -> dict:
    if not domain:
        return {}
    try:
        tld = domain.rsplit(".", 1)[-1].lower()
        bootstrap = await client.get("https://data.iana.org/rdap/dns.json", timeout=10)
        rdap_base = None
        if bootstrap.status_code == 200:
            for entry in bootstrap.json().get("services", []):
                tlds, urls = entry
                if tld in tlds and urls:
                    rdap_base = urls[0].rstrip("/")
                    break
        if not rdap_base:
            rdap_base = "https://rdap.org"
        r = await client.get(f"{rdap_base}/domain/{domain}", timeout=10)
        if r.status_code != 200:
            r = await client.get(f"https://rdap.org/domain/{domain}", timeout=10)
        if r.status_code != 200:
            return {}
        data = r.json()
        events = {e.get("eventAction", "").lower(): e.get("eventDate", "") for e in data.get("events", [])}
        nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", [])]
        registrar = ""
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [None, []])[1]
                for field in vcard:
                    if isinstance(field, list) and field[0] == "fn":
                        registrar = field[3]
                        break
        return {
            "registered": events.get("registration", ""),
            "expires": events.get("expiration", ""),
            "last_changed": events.get("last changed", ""),
            "registrar": registrar,
            "nameservers": nameservers[:4],
            "status": data.get("status", []),
        }
    except Exception:
        return {}


async def analyze_contacted_ips(ips: list[str], main_ip: str, client: httpx.AsyncClient) -> list[dict]:
    if not ips or not ABUSEIPDB_KEY:
        return []
    targets = [ip for ip in ips if ip != main_ip][:10]
    if not targets:
        return []

    async def check_one(ip: str) -> dict:
        abuse = await check_abuseipdb(ip, client)
        geo = geo_from_abuse(abuse)
        return {
            "ip": ip,
            "abuse_score": abuse.get("abuse_score", 0),
            "total_reports": abuse.get("total_reports", 0),
            "isp": abuse.get("isp", ""),
            "usage_type": abuse.get("usage_type", ""),
            "is_tor": abuse.get("is_tor", False),
            "country": geo.get("country", ""),
            "org": abuse.get("isp", ""),
            "is_hosting": geo.get("is_hosting", False),
        }

    return list(await asyncio.gather(*[check_one(ip) for ip in targets]))


# ── API keys management ───────────────────────────────────────────────────────

@app.get("/api/keys")
async def get_keys():
    return {
        "virustotal": "✓" if VT_KEY else "",
        "urlscan":    "✓" if URLSCAN_KEY else "",
        "abuseipdb":  "✓" if ABUSEIPDB_KEY else "",
    }


@app.post("/api/keys")
async def save_keys(body: KeysRequest):
    global VT_KEY, URLSCAN_KEY, ABUSEIPDB_KEY
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    existing: dict[str, str] = {}
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    existing[k.strip()] = v.strip()
    mapping = {
        "VIRUSTOTAL_API_KEY": body.virustotal,
        "URLSCAN_API_KEY":    body.urlscan,
        "ABUSEIPDB_API_KEY":  body.abuseipdb,
    }
    for env_key, val in mapping.items():
        # Sin esto, un valor con saltos de línea podría inyectar variables
        # de entorno arbitrarias en el archivo .env (ej. "x\nAPP_PASSWORD=").
        val = val.replace("\n", "").replace("\r", "").strip()
        if val:
            existing[env_key] = val
    with open(env_path, "w", encoding="utf-8") as f:
        for k, v in existing.items():
            f.write(f"{k}={v}\n")
    VT_KEY        = existing.get("VIRUSTOTAL_API_KEY", "")
    URLSCAN_KEY   = existing.get("URLSCAN_API_KEY", "")
    ABUSEIPDB_KEY = existing.get("ABUSEIPDB_API_KEY", "")
    return {"ok": True}


# ── IP list scanner ───────────────────────────────────────────────────────────

@app.post("/api/scan-ips")
async def scan_ips(body: IPListRequest):
    # Clean and deduplicate, max 20
    ips = list(dict.fromkeys(ip.strip() for ip in body.ips if ip.strip()))[:20]
    if not ips:
        return {"results": []}

    async def check_one(ip: str, client: httpx.AsyncClient) -> dict:
        abuse = await check_abuseipdb(ip, client)
        geo = geo_from_abuse(abuse)
        return {
            "ip": ip,
            "abuse_score": abuse.get("abuse_score", 0),
            "total_reports": abuse.get("total_reports", 0),
            "distinct_users": abuse.get("distinct_users", 0),
            "isp": abuse.get("isp", ""),
            "usage_type": abuse.get("usage_type", ""),
            "is_tor": abuse.get("is_tor", False),
            "country": geo.get("country", ""),
            "org": abuse.get("isp", ""),
            "is_hosting": geo.get("is_hosting", False),
            "last_reported": abuse.get("last_reported", ""),
            "error": abuse.get("error", ""),
        }

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*[check_one(ip, client) for ip in ips])

    return {"results": list(results)}


# ── Main routes ───────────────────────────────────────────────────────────────

@app.get("/")
async def index():
    return FileResponse("static/index.html")


@app.post("/api/scan")
async def scan_url(body: ScanRequest):
    url = body.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""
    ip       = resolve_ip(hostname) if hostname else None

    async with httpx.AsyncClient() as client:
        vt, abuse, urlscan, whois = await asyncio.gather(
            check_virustotal(url, client),
            check_abuseipdb(ip or "", client),
            check_urlscan(url, client),
            check_whois(hostname, client),
        )
        geo = geo_from_abuse(abuse)
        contacted_ips_analysis = []
        if isinstance(urlscan, dict) and urlscan.get("ips_contacted"):
            contacted_ips_analysis = await analyze_contacted_ips(
                urlscan["ips_contacted"], ip or "", client
            )

    return {
        "url": url,
        "hostname": hostname,
        "ip": ip,
        "virustotal": vt,
        "abuseipdb": abuse,
        "urlscan": urlscan,
        "geo": geo,
        "whois": whois,
        "contacted_ips_analysis": contacted_ips_analysis,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
