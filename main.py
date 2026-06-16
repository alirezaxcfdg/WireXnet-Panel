import asyncio
import json
import os
import hashlib
import secrets
import time
import re
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
import psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("WireXnet-Gateway")

app = FastAPI(title="WireXnet", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connections: dict = {}
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

SESSION_COOKIE = "wirexnet_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
                logger.info("Keep-alive ping sent")
        except Exception:
            pass

@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    logger.info(f"WireXnet started on port {CONFIG['port']}")
    asyncio.create_task(keep_alive())

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def generate_vless_link(uuid: str, remark: str = "WireXnet", address: str = None) -> str:
    domain = get_domain()
    addr = address if address else domain
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            LINKS["Default"] = {"label": "Default", "limit_bytes": 0, "used_bytes": 0, "max_connections": 0, "created_at": datetime.now().isoformat(), "active": True}

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"

def count_connections_for_link(uid: str) -> int:
    return len(link_ip_map.get(uid, set()))

def remove_ip_from_link(uid: str, ip: str):
    if uid in link_ip_map:
        link_ip_map[uid].discard(ip)
        if not link_ip_map[uid]:
            link_ip_map.pop(uid, None)

async def close_connections_for_link(uid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    link_ip_map.pop(uid, None)

@app.get("/")
async def root():
    return {"service": "WireXnet", "version": "1.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": await is_valid_session(token)}

@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    online_count = len(set(ip for ips in link_ip_map.values() for ip in ips))
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "online_count": online_count,
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "hourly_traffic": dict(hourly_traffic),
    }


@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Inbound name must contain only English letters, numbers, and characters: - _ . space")
    if not label:
        raise HTTPException(status_code=400, detail="Inbound name is required")
    async with LINKS_LOCK:
        if label in LINKS:
            raise HTTPException(status_code=400, detail="An inbound with this name already exists")
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    max_conn = int(body.get("max_connections") or 0)
    if max_conn < 0:
        max_conn = 0
    uid = generate_uuid(label)
    async with LINKS_LOCK:
        LINKS[uid] = {"label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "max_connections": max_conn, "created_at": datetime.now().isoformat(), "active": True}
    return {"uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "max_connections": max_conn, "active": True, "created_at": LINKS[uid]["created_at"], "vless_link": generate_vless_link(uid, f"WireXnet-{label}")}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({"uuid": uid, "label": data["label"], "limit_bytes": data["limit_bytes"], "used_bytes": data["used_bytes"], "max_connections": data.get("max_connections", 0), "active": data["active"], "created_at": data["created_at"], "vless_link": generate_vless_link(uid, f"WireXnet-{data['label']}")})
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
        if "max_connections" in body:
            mc = int(body["max_connections"] or 0)
            LINKS[uid]["max_connections"] = mc if mc >= 0 else 0
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}


@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        return {"addresses": list(CUSTOM_ADDRESSES)}


@app.post("/api/addresses")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    address = (body.get("address") or "").strip()
    if not address:
        raise HTTPException(status_code=400, detail="Address is required")
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', address):
        raise HTTPException(status_code=400, detail="Address must contain only English letters, numbers, and characters: - _ .")
    async with CUSTOM_ADDRESSES_LOCK:
        if address in CUSTOM_ADDRESSES:
            raise HTTPException(status_code=400, detail="Address already exists")
        CUSTOM_ADDRESSES.append(address)
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}


@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            CUSTOM_ADDRESSES.pop(index)
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.get("/api/links/{uid}/sub")
async def get_subscription(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    vless_link = generate_vless_link(uid, remark=f"WireXnet-{link['label']}")
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    used_mb = round(used / (1024 * 1024), 2)
    limit_mb = round(limit / (1024 * 1024), 2) if limit > 0 else 0
    pct = round((used / limit) * 100, 1) if limit > 0 else 0
    remaining_mb = round((limit - used) / (1024 * 1024), 2) if limit > 0 else 0
    days_remaining = 0
    import base64
    sub_content = f"""# WireXnet Subscription
# Label: {link['label']}
# Used: {used_mb} MB / {limit_mb if limit > 0 else 'Unlimited'} MB
# Remaining: {remaining_mb if limit > 0 else 'Unlimited'} MB
# Usage: {pct}%
# Status: {'Active' if link['active'] else 'Disabled'}
# Expiry: Unlimited
{vless_link}"""
    encoded = base64.b64encode(sub_content.encode()).decode()
    return {
        "subscription_url": f"{get_domain()}/api/links/{uid}/sub",
        "config": vless_link,
        "label": link["label"],
        "used_bytes": used,
        "limit_bytes": limit,
        "used_mb": used_mb,
        "limit_mb": limit_mb,
        "remaining_mb": remaining_mb,
        "usage_percent": pct,
        "active": link["active"],
        "sub_base64": encoded,
        "sub_text": sub_content,
        "days_remaining": days_remaining,
    }


@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    import base64
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    if not link["active"]:
        raise HTTPException(status_code=403, detail="link disabled")
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    sub_links = []
    server_link = generate_vless_link(uid, remark=f"WireXnet-{link['label']}-Server")
    sub_links.append(server_link)
    for i, addr in enumerate(addresses):
        remark = f"WireXnet-{link['label']}-IP{i+1}"
        vless_link = generate_vless_link(uid, remark=remark, address=addr)
        sub_links.append(vless_link)
    sub_content = "\n".join(sub_links)
    encoded = base64.b64encode(sub_content.encode()).decode()
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": "attachment; filename=\"sub.txt\"",
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={link['limit_bytes']}; expire=0"
    }
    return Response(content=encoded, headers=headers)

RELAY_BUF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 0
    pos += 1; pos += 16
    addon_len = first_chunk[pos]; pos += 1; pos += addon_len
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None: return False
        if not link["active"]: return False
        if link["limit_bytes"] == 0: return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            writer.write(data); await writer.drain()
    except WebSocketDisconnect: pass
    finally:
        try: writer.write_eof()
        except: pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except: pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await ensure_default_link()
    await websocket.accept()
    writer = None
    conn_id = None
    client_ip = get_client_ip(websocket)
    try:
        async with LINKS_LOCK:
            link_data = LINKS.get(uuid)
            if link_data is None or not link_data["active"]:
                await websocket.close(code=1008, reason="link not found or disabled"); return
            max_conn = link_data.get("max_connections", 0)
        if max_conn > 0:
            already_connected = client_ip in link_ip_map.get(uuid, set())
            if not already_connected:
                current = count_connections_for_link(uuid)
                if current >= max_conn:
                    await websocket.close(code=1008, reason="connection limit reached"); return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = websocket
        link_ip_map[uuid].add(client_ip)
        size = len(first_chunk)
        stats["total_bytes"] += size; stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        hourly_traffic[datetime.now().strftime("%H:00")] += size
        await add_usage(uuid, size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            connections[conn_id]["bytes"] += p_size
            hourly_traffic[datetime.now().strftime("%H:00")] += p_size
            await add_usage(uuid, p_size)
            writer.write(initial_payload); await writer.drain()
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try: writer.close()
            except: pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                uid = info.get("uuid")
                ip = info.get("ip")
                if uid and ip:
                    has_other = any(c.get("uuid") == uid and c.get("ip") == ip for c in connections.values())
                    if not has_other:
                        remove_ip_from_link(uid, ip)


LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WireXnet Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
html[data-theme="dark"]{--bg:#0f0f12;--surface:rgba(25,25,32,0.95);--surface2:#1a1a24;--border:rgba(255,255,255,0.08);--text:rgba(255,255,255,0.95);--text2:rgba(255,255,255,0.6);--text3:rgba(255,255,255,0.3);--primary:#2563eb;--primary-glow:rgba(37,99,235,0.2);--success:#10b981;--error:#ef4444}
html[data-theme="light"]{--bg:#ffffff;--surface:rgba(255,255,255,0.95);--surface2:#f5f7fa;--border:rgba(0,0,0,0.08);--text:rgba(0,0,0,0.95);--text2:rgba(0,0,0,0.6);--text3:rgba(0,0,0,0.3);--primary:#2563eb;--primary-glow:rgba(37,99,235,0.15);--success:#10b981;--error:#ef4444}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);transition:background .3s,color .3s}
.login-container{width:100%;max-width:400px;padding:20px}
.login-card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px 32px;backdrop-filter:blur(40px);box-shadow:0 8px 32px rgba(0,0,0,0.1)}
.logo{text-align:center;margin-bottom:30px}
.logo-text{font-size:28px;font-weight:800;color:var(--primary);letter-spacing:-0.5px}
.logo-sub{font-size:12px;color:var(--text3);margin-top:4px;letter-spacing:0.5px}
.form-group{margin-bottom:16px}
.form-label{display:block;font-size:12px;font-weight:600;color:var(--text2);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px}
.form-input{width:100%;padding:11px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:14px;font-family:inherit;outline:none;transition:all .2s}
.form-input:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow)}
.login-btn{width:100%;padding:12px;background:var(--primary);border:none;border-radius:10px;color:#fff;font-size:14px;font-weight:600;font-family:inherit;cursor:pointer;transition:all .3s;margin-top:8px}
.login-btn:hover{filter:brightness(1.1);transform:translateY(-2px);box-shadow:0 4px 16px rgba(37,99,235,0.3)}
.login-btn:active{transform:translateY(0) scale(0.98)}
.error-box{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:var(--error);padding:10px 14px;border-radius:8px;font-size:13px;display:none;margin-bottom:16px}
.error-box.show{display:block}
</style>
</head>
<body>
<div class="login-container">
  <div class="login-card">
    <div class="logo">
      <div class="logo-text">WireXnet</div>
      <div class="logo-sub">PANEL v1.0</div>
    </div>
    <div class="error-box" id="err-box"></div>
    <form id="login-form">
      <div class="form-group">
        <label class="form-label">Password</label>
        <input type="password" class="form-input" id="password" placeholder="Enter password" autofocus>
      </div>
      <button type="submit" class="login-btn">Sign In</button>
    </form>
  </div>
</div>
<script>
document.getElementById('login-form').addEventListener('submit',async e=>{
  e.preventDefault();
  const err=document.getElementById('err-box');
  err.classList.remove('show');
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('password').value})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Failed');}
    location.href='/dashboard';
  }catch(e){err.textContent=e.message;err.classList.add('show');}
});
</script>
</body>
</html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WireXnet Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html[data-theme="dark"]{--bg:#0f0f12;--surface:#1a1a24;--surface2:#252533;--surface3:#323844;--border:rgba(255,255,255,0.08);--border2:rgba(255,255,255,0.12);--text:rgba(255,255,255,0.95);--text2:rgba(255,255,255,0.6);--text3:rgba(255,255,255,0.3);--primary:#2563eb;--primary-glow:rgba(37,99,235,0.15);--success:#10b981;--warning:#f59e0b;--danger:#ef4444;--primary-dim:rgba(37,99,235,0.08);--success-dim:rgba(16,185,129,0.08);--danger-dim:rgba(239,68,68,0.08)}
html[data-theme="light"]{--bg:#ffffff;--surface:#f9fafb;--surface2:#f3f4f6;--surface3:#e5e7eb;--border:rgba(0,0,0,0.06);--border2:rgba(0,0,0,0.1);--text:rgba(0,0,0,0.95);--text2:rgba(0,0,0,0.6);--text3:rgba(0,0,0,0.3);--primary:#2563eb;--primary-glow:rgba(37,99,235,0.1);--success:#10b981;--warning:#f59e0b;--danger:#ef4444;--primary-dim:rgba(37,99,235,0.08);--success-dim:rgba(16,185,129,0.08);--danger-dim:rgba(239,68,68,0.08)}
html,body{height:100%}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg);color:var(--text);display:flex;transition:background .3s,color .3s}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}

.sidebar{width:240px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100}
.sidebar-header{padding:20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.brand-name{font-size:16px;font-weight:800;color:var(--primary);letter-spacing:-0.5px}
.theme-toggle{width:32px;height:32px;border:1px solid var(--border);background:var(--surface2);border-radius:8px;color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s;font-size:16px}
.theme-toggle:hover{border-color:var(--primary);color:var(--primary)}
.sidebar-nav{flex:1;overflow-y:auto;padding:12px}
.nav-item{width:100%;padding:11px 14px;margin:4px 0;border-radius:10px;border:none;background:none;color:var(--text2);font-size:13px;font-weight:500;cursor:pointer;display:flex;align-items:center;gap:10px;transition:all .2s;font-family:inherit}
.nav-item:hover{background:var(--surface2);color:var(--text)}
.nav-item.active{background:var(--primary-dim);color:var(--primary);font-weight:600}
.nav-icon{width:18px;height:18px;flex-shrink:0}
.nav-badge{margin-left:auto;background:var(--danger-dim);color:var(--danger);font-size:10px;padding:2px 7px;border-radius:6px;font-weight:600}
.sidebar-footer{padding:12px;border-top:1px solid var(--border)}
.logout-btn{width:100%;padding:8px 12px;border:1px solid var(--border);background:none;border-radius:8px;color:var(--text2);font-size:12px;font-weight:600;cursor:pointer;font-family:inherit;transition:all .2s}
.logout-btn:hover{border-color:var(--danger);color:var(--danger);background:var(--danger-dim)}

.main{margin-left:240px;flex:1;padding:32px 40px;overflow-y:auto}
.page{display:none}
.page.active{display:block}
.page-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:32px}
.page-title{font-size:24px;font-weight:800;color:var(--text);letter-spacing:-0.5px}
.page-sub{font-size:12px;color:var(--text3);margin-top:4px}
.header-actions{display:flex;gap:8px}
.btn{font-family:inherit;font-size:12px;font-weight:600;border-radius:8px;padding:10px 16px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:all .2s;text-decoration:none}
.btn-primary{background:var(--primary);color:#fff}
.btn-primary:hover{filter:brightness(1.1);transform:translateY(-1px)}
.btn-secondary{background:var(--surface2);color:var(--text2);border:1px solid var(--border)}
.btn-secondary:hover{border-color:var(--primary);color:var(--primary)}
.btn-sm{padding:7px 12px;font-size:11px}

.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;transition:all .3s}
.stat-card:hover{border-color:var(--primary);transform:translateY(-2px)}
.stat-label{font-size:11px;color:var(--text3);font-weight:600;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px}
.stat-value{font-size:26px;font-weight:800;color:var(--text);letter-spacing:-0.5px}
.stat-unit{font-size:12px;color:var(--text3);font-weight:400}

.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:16px;transition:all .3s}
.card:hover{border-color:var(--primary)}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.card-title{font-size:14px;font-weight:700;color:var(--text);display:flex;align-items:center;gap:8px}

.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}

.chart-container{position:relative;height:280px;margin-bottom:8px}

.status-item{display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border)}
.status-item:last-child{border-bottom:none}
.status-key{color:var(--text2);font-size:13px}
.status-val{color:var(--text);font-weight:600;font-size:13px}

.sys-bar{height:6px;background:var(--surface2);border-radius:3px;overflow:hidden;margin-top:8px}
.sys-bar-fill{height:100%;border-radius:3px;transition:width .3s}

.table{width:100%;border-collapse:collapse}
.table th{text-align:left;font-size:11px;font-weight:600;color:var(--text3);padding:12px;text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid var(--border);background:var(--surface2)}
.table td{padding:12px;border-bottom:1px solid var(--border);font-size:13px}
.table tbody tr:hover td{background:var(--primary-dim)}

.tag{display:inline-flex;align-items:center;padding:4px 10px;border-radius:6px;font-size:10px;font-weight:700;letter-spacing:0.3px}
.tag-vless{background:var(--primary-dim);color:var(--primary)}
.tag-active{background:var(--success-dim);color:var(--success)}
.tag-disabled{background:var(--danger-dim);color:var(--danger)}

.toggle{width:40px;height:22px;border-radius:12px;background:var(--surface2);position:relative;cursor:pointer;transition:all .2s;border:1px solid var(--border)}
.toggle::after{content:'';position:absolute;width:16px;height:16px;border-radius:50%;background:var(--text3);top:2px;left:2px;transition:all .2s}
.toggle.on{background:var(--success);border-color:var(--success)}
.toggle.on::after{left:20px;background:#fff}

.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(6px)}
.modal-overlay.show{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:28px;width:100%;max-width:480px;position:relative;box-shadow:0 20px 60px rgba(0,0,0,0.3)}
.modal-title{font-size:16px;font-weight:700;margin-bottom:20px;color:var(--text)}
.modal-close{position:absolute;top:12px;right:12px;background:var(--surface2);border:1px solid var(--border);color:var(--text2);width:32px;height:32px;border-radius:8px;cursor:pointer;font-size:20px;display:flex;align-items:center;justify-content:center;transition:all .2s}
.modal-close:hover{background:var(--danger-dim);color:var(--danger);border-color:var(--danger)}

.form-group{display:flex;flex-direction:column;gap:6px;margin-bottom:14px}
.form-label{font-size:12px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:0.5px}
.form-input,.form-select{padding:10px 12px;border-radius:8px;border:1px solid var(--border);font-family:inherit;font-size:13px;outline:none;color:var(--text);background:var(--surface2);transition:all .2s}
.form-input:focus,.form-select:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow)}

.toast{position:fixed;bottom:24px;right:24px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:10px;padding:12px 16px;font-size:13px;display:none;z-index:300;animation:slideUp .3s ease}
.toast.show{display:block}
.toast.error{border-color:var(--danger);background:var(--danger-dim);color:var(--danger)}
@keyframes slideUp{from{transform:translateY(100px);opacity:0}to{transform:translateY(0);opacity:1}}

.empty{text-align:center;padding:40px;color:var(--text3)}
.empty-icon{font-size:40px;margin-bottom:12px}

@media(max-width:768px){.stats-grid{grid-template-columns:1fr 1fr}.grid-2{grid-template-columns:1fr}.sidebar{display:none}}
</style>
</head>
<body>

<div class="toast" id="toast"></div>

<aside class="sidebar">
  <div class="sidebar-header">
    <span class="brand-name">WireXnet</span>
    <button class="theme-toggle" onclick="toggleTheme()" id="theme-btn" title="Toggle theme">🌙</button>
  </div>
  <nav class="sidebar-nav">
    <button class="nav-item active" data-page="dashboard" onclick="switchPage('dashboard')">
      <span class="nav-icon">📊</span>
      <span>Dashboard</span>
    </button>
    <button class="nav-item" data-page="inbounds" onclick="switchPage('inbounds')">
      <span class="nav-icon">🔗</span>
      <span>Inbounds</span>
      <span class="nav-badge" id="links-badge">0</span>
    </button>
    <button class="nav-item" data-page="traffic" onclick="switchPage('traffic')">
      <span class="nav-icon">📈</span>
      <span>Traffic</span>
    </button>
    <button class="nav-item" data-page="security" onclick="switchPage('security')">
      <span class="nav-icon">🔒</span>
      <span>Security</span>
    </button>
  </nav>
  <div class="sidebar-footer">
    <button class="logout-btn" onclick="fetch('/api/logout',{method:'POST'}).then(()=>location.href='/login')">🚪 Logout</button>
  </div>
</aside>

<main class="main">

  <section class="page active" id="page-dashboard">
    <div class="page-header">
      <div>
        <div class="page-title">Dashboard</div>
        <div class="page-sub" id="last-update">Updated: --</div>
      </div>
      <div class="header-actions">
        <button class="btn btn-secondary btn-sm" onclick="quickCreate(0.5,'GB')">+ 0.5 GB</button>
        <button class="btn btn-primary btn-sm" onclick="quickCreate(1,'GB')">+ 1 GB</button>
      </div>
    </div>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Total Traffic</div>
        <div class="stat-value" id="s-traffic">--<span class="stat-unit"> MB</span></div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Total Inbounds</div>
        <div class="stat-value" id="s-links">--</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Online Users</div>
        <div class="stat-value" id="s-online">--</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Uptime</div>
        <div class="stat-value" id="s-uptime" style="font-size:18px">--</div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-header">
          <div class="card-title">CPU Usage</div>
          <span id="s-cpu-val" style="font-size:18px;font-weight:700;color:var(--primary)">--%</span>
        </div>
        <div class="sys-bar"><div class="sys-bar-fill" id="s-cpu-bar" style="width:0%;background:var(--primary)"></div></div>
      </div>
      <div class="card">
        <div class="card-header">
          <div class="card-title">Memory Usage</div>
          <span id="s-mem-val" style="font-size:18px;font-weight:700;color:var(--success)">--%</span>
        </div>
        <div class="sys-bar"><div class="sys-bar-fill" id="s-mem-bar" style="width:0%;background:var(--success)"></div></div>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title">Hourly Traffic</div></div>
      <div class="chart-container"><canvas id="trafficChart"></canvas></div>
    </div>
  </section>

  <section class="page" id="page-inbounds">
    <div class="page-header">
      <div>
        <div class="page-title">Inbounds</div>
        <div class="page-sub">VLESS over WebSocket</div>
      </div>
      <button class="btn btn-primary btn-sm" onclick="showAddModal()">+ Add Inbound</button>
    </div>
    <div class="card" style="border-radius:12px;overflow:hidden;padding:0">
      <div style="overflow-x:auto">
        <table class="table">
          <thead><tr>
            <th>Name</th>
            <th>Protocol</th>
            <th>Traffic</th>
            <th>Online IPs</th>
            <th>Status</th>
            <th>Actions</th>
          </tr></thead>
          <tbody id="links-tbody"></tbody>
        </table>
      </div>
      <div class="empty" id="links-empty" style="display:none">
        <div class="empty-icon">📭</div>
        <div>No inbounds found</div>
      </div>
    </div>
  </section>

  <section class="page" id="page-traffic">
    <div class="page-header"><div><div class="page-title">Traffic Statistics</div></div></div>
    <div class="card">
      <div class="status-item"><span class="status-key">Total Traffic</span><span class="status-val" id="t-traffic">-- MB</span></div>
      <div class="status-item"><span class="status-key">Total Requests</span><span class="status-val" id="t-reqs">--</span></div>
      <div class="status-item"><span class="status-key">Total Errors</span><span class="status-val" id="t-errors">--</span></div>
      <div class="status-item"><span class="status-key">Uptime</span><span class="status-val" id="t-uptime">--</span></div>
    </div>
  </section>

  <section class="page" id="page-security">
    <div class="page-header"><div><div class="page-title">Security</div><div class="page-sub">Change panel password</div></div></div>
    <div class="card" style="max-width:400px">
      <div class="form-group">
        <label class="form-label">Current Password</label>
        <input class="form-input" type="password" id="cur-pw" placeholder="Enter current password">
      </div>
      <div class="form-group">
        <label class="form-label">New Password</label>
        <input class="form-input" type="password" id="new-pw" placeholder="Min 4 characters">
      </div>
      <button class="btn btn-primary btn-sm" onclick="changePassword()" style="margin-top:8px">Update Password</button>
    </div>
  </section>

</main>

<div class="modal-overlay" id="add-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <button class="modal-close" onclick="$('#add-modal').classList.remove('show')">✕</button>
    <div class="modal-title">Add New Inbound</div>
    <div class="form-group">
      <label class="form-label">Name</label>
      <input class="form-input" id="new-label" placeholder="e.g. User 1">
    </div>
    <div style="display:grid;grid-template-columns:1fr 120px;gap:10px;margin-bottom:14px">
      <div class="form-group" style="margin-bottom:0">
        <label class="form-label">Traffic Limit</label>
        <input class="form-input" id="new-limit" type="number" min="0" step="0.1" placeholder="0 = Unlimited">
      </div>
      <div class="form-group" style="margin-bottom:0">
        <label class="form-label">Unit</label>
        <select class="form-select" id="new-unit"><option value="GB">GB</option></select>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">Max Connected IPs</label>
      <input class="form-input" id="new-maxconn" type="number" min="0" step="1" placeholder="0 = Unlimited">
    </div>
    <button class="btn btn-primary" onclick="createLink()" style="width:100%;justify-content:center;margin-top:8px">Create Inbound</button>
  </div>
</div>

<div class="modal-overlay" id="edit-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <button class="modal-close" onclick="$('#edit-modal').classList.remove('show')">✕</button>
    <div class="modal-title" id="edit-title">Edit Inbound</div>
    <input type="hidden" id="edit-uid">
    <div class="form-group">
      <label class="form-label">Name</label>
      <input class="form-input" id="edit-name" readonly style="opacity:0.6;cursor:not-allowed">
    </div>
    <div style="display:grid;grid-template-columns:1fr 120px;gap:10px;margin-bottom:14px">
      <div class="form-group" style="margin-bottom:0">
        <label class="form-label">Traffic Limit</label>
        <input class="form-input" id="edit-limit" type="number" min="0" step="0.1" placeholder="0 = Unlimited">
      </div>
      <div class="form-group" style="margin-bottom:0">
        <label class="form-label">Unit</label>
        <select class="form-select" id="edit-unit"><option value="GB">GB</option></select>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">Max Connected IPs</label>
      <input class="form-input" id="edit-maxconn" type="number" min="0" step="1" placeholder="0 = Unlimited">
    </div>
    <div style="display:flex;gap:8px;margin-top:14px">
      <button class="btn btn-primary btn-sm" onclick="saveEdit()" style="flex:1;justify-content:center">Save</button>
      <button class="btn btn-secondary btn-sm" onclick="resetEditTraffic()" style="justify-content:center">Reset</button>
    </div>
  </div>
</div>

<script>
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);
let theme = localStorage.getItem('wx_theme') || 'dark';
let allLinks = [];
let statsData = {};
let trafficChart = null;

function applyTheme(t) {
  theme = t;
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('wx_theme', t);
  const btn = $('#theme-btn');
  if (btn) btn.textContent = t === 'dark' ? '☀️' : '🌙';
}

function toggleTheme() {
  applyTheme(theme === 'dark' ? 'light' : 'dark');
}

function switchPage(id) {
  $$('.page').forEach(p => p.classList.remove('active'));
  $(`#page-${id}`)?.classList.add('active');
  $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.page === id));
}

function toast(msg, err = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast' + (err ? ' error' : '') + ' show';
  setTimeout(() => t.classList.remove('show'), 3000);
}

function fmtBytes(b) {
  return b > 1073741824 ? (b / 1073741824).toFixed(2) + ' GB' : b > 1048576 ? (b / 1048576).toFixed(2) + ' MB' : (b / 1024).toFixed(1) + ' KB';
}

function fmtLimit(b) {
  if (b === 0) return 'Unlimited';
  const gb = b / 1073741824;
  return (gb % 1 === 0 ? gb.toFixed(0) : gb.toFixed(1)) + ' GB';
}

async function loadStats() {
  try {
    const r = await fetch('/stats');
    if (!r.ok) throw new Error();
    statsData = await r.json();
    $('#s-traffic').innerHTML = statsData.total_traffic_mb + '<span class="stat-unit"> MB</span>';
    $('#s-links').textContent = statsData.links_count;
    $('#s-online').textContent = statsData.online_count;
    $('#s-uptime').textContent = statsData.uptime;
    $('#s-cpu-val').textContent = statsData.cpu_percent.toFixed(1) + '%';
    $('#s-cpu-bar').style.width = Math.min(100, statsData.cpu_percent) + '%';
    $('#s-mem-val').textContent = statsData.memory_percent.toFixed(1) + '%';
    $('#s-mem-bar').style.width = Math.min(100, statsData.memory_percent) + '%';
    $('#links-badge').textContent = statsData.links_count;
    $('#last-update').textContent = 'Updated: ' + new Date().toLocaleTimeString();
    if ($('#t-traffic')) $('#t-traffic').textContent = statsData.total_traffic_mb + ' MB';
    if ($('#t-reqs')) $('#t-reqs').textContent = statsData.total_requests.toLocaleString();
    if ($('#t-errors')) $('#t-errors').textContent = statsData.total_errors;
    if ($('#t-uptime')) $('#t-uptime').textContent = statsData.uptime;
    updateChart();
  } catch (e) {}
}

async function loadLinks() {
  try {
    const r = await fetch('/api/links');
    if (!r.ok) throw new Error();
    const d = await r.json();
    allLinks = d.links || [];
    renderLinks();
  } catch (e) {}
}

function renderLinks() {
  const tbody = $('#links-tbody');
  const empty = $('#links-empty');
  if (!allLinks.length) {
    tbody.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';
  let idx = allLinks.length;
  tbody.innerHTML = allLinks.map(l => {
    const u = l.used_bytes, lim = l.limit_bytes;
    const uF = fmtBytes(u), lF = fmtLimit(lim);
    const pct = lim > 0 ? Math.min(100, (u / lim) * 100) : 0;
    const maxConn = l.max_connections || 0;
    const online = Object.values(link_ip_map).reduce((sum, ips) => sum + (ips.has ? 1 : 0), 0) || 0;
    return `<tr>
      <td style="font-weight:600">${l.label}</td>
      <td><span class="tag tag-vless">VLESS</span></td>
      <td><div style="display:flex;align-items:center;gap:8px"><div style="flex:1;background:var(--surface2);height:4px;border-radius:2px"><div style="width:${pct}%;height:100%;background:var(--primary);border-radius:2px;transition:width .3s"></div></div><span style="font-size:11px;color:var(--text3);min-width:40px">${pct.toFixed(0)}%</span></div><div style="font-size:11px;color:var(--text3);margin-top:4px">${uF} / ${lF}</div></td>
      <td style="text-align:center">${online} / ${maxConn || '∞'}</td>
      <td><span class="tag ${l.active ? 'tag-active' : 'tag-disabled'}">${l.active ? 'On' : 'Off'}</span></td>
      <td><div style="display:flex;gap:4px">
        <button class="toggle ${l.active ? 'on' : ''}" data-uid="${l.uuid}" onclick="toggleLink(this)" title="Toggle"></button>
        <button class="btn btn-secondary btn-sm" onclick="showEditModal('${l.uuid}')" title="Edit">✎</button>
        <button class="btn btn-secondary btn-sm" onclick="copyLink('${l.vless_link}')" title="Copy">📋</button>
        <button class="btn btn-secondary btn-sm" onclick="deleteLink('${l.uuid}')" title="Delete">🗑️</button>
      </div></td>
    </tr>`;
  }).join('');
}

async function toggleLink(el) {
  const uid = el.dataset.uid;
  const link = allLinks.find(l => l.uuid === uid);
  if (!link) return;
  try {
    await fetch(`/api/links/${uid}`, {method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({active: !link.active})});
    link.active = !link.active;
    renderLinks();
    loadStats();
  } catch (e) {}
}

function showAddModal() {
  $('#new-label').value = '';
  $('#new-limit').value = '';
  $('#new-maxconn').value = '';
  $('#add-modal').classList.add('show');
}

async function createLink() {
  const label = $('#new-label').value.trim() || 'New Link';
  const val = parseFloat($('#new-limit').value) || 0;
  const unit = 'GB';
  const maxconn = parseInt($('#new-maxconn').value) || 0;
  if (!/^[a-zA-Z0-9\-_. ]+$/.test(label)) {
    toast('Only English letters allowed', true);
    return;
  }
  try {
    const r = await fetch('/api/links', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({label, limit_value: val, limit_unit: unit, max_connections: maxconn})});
    if (!r.ok) throw new Error();
    toast('Inbound created');
    $('#add-modal').classList.remove('show');
    await loadLinks();
    await loadStats();
  } catch (e) {
    toast('Error', true);
  }
}

function showEditModal(uid) {
  const l = allLinks.find(x => x.uuid === uid);
  if (!l) return;
  $('#edit-uid').value = uid;
  $('#edit-name').value = l.label;
  const gb = l.limit_bytes / 1073741824;
  $('#edit-limit').value = l.limit_bytes > 0 ? gb : '';
  $('#edit-unit').value = 'GB';
  $('#edit-maxconn').value = l.max_connections > 0 ? l.max_connections : '';
  $('#edit-title').textContent = 'Edit: ' + l.label;
  $('#edit-modal').classList.add('show');
}

async function saveEdit() {
  const uid = $('#edit-uid').value;
  const val = parseFloat($('#edit-limit').value) || 0;
  const unit = $('#edit-unit').value;
  const maxconn = parseInt($('#edit-maxconn').value) || 0;
  try {
    const r = await fetch(`/api/links/${uid}`, {method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({limit_value: val, limit_unit: unit, max_connections: maxconn})});
    if (!r.ok) throw new Error();
    toast('Updated');
    $('#edit-modal').classList.remove('show');
    await loadLinks();
  } catch (e) {
    toast('Error', true);
  }
}

async function resetEditTraffic() {
  const uid = $('#edit-uid').value;
  if (!confirm('Reset traffic usage to zero?')) return;
  try {
    const r = await fetch(`/api/links/${uid}`, {method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({reset_usage: true})});
    if (!r.ok) throw new Error();
    toast('Traffic reset');
    await loadLinks();
  } catch (e) {
    toast('Error', true);
  }
}

async function deleteLink(uid) {
  if (!confirm('Delete this inbound?')) return;
  try {
    await fetch(`/api/links/${uid}`, {method: 'DELETE'});
    toast('Deleted');
    await loadLinks();
    await loadStats();
  } catch (e) {
    toast('Error', true);
  }
}

function copyLink(txt) {
  navigator.clipboard.writeText(txt).then(() => toast('Copied')).catch(() => toast('Failed', true));
}

async function changePassword() {
  const cur = $('#cur-pw').value;
  const nw = $('#new-pw').value;
  if (!cur || !nw) {
    toast('Fill all fields', true);
    return;
  }
  try {
    const r = await fetch('/api/change-password', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({current_password: cur, new_password: nw})});
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      throw new Error(d.detail || 'Failed');
    }
    toast('Password updated');
    $('#cur-pw').value = '';
    $('#new-pw').value = '';
  } catch (e) {
    toast(e.message, true);
  }
}

function quickCreate(limit, unit) {
  const names = ['Ali', 'Sara', 'Reza', 'Nima', 'Mina', 'Arash', 'Yalda'];
  const name = names[Math.floor(Math.random() * names.length)];
  $('#new-label').value = name;
  $('#new-limit').value = limit;
  $('#new-unit').value = unit;
  $('#new-maxconn').value = '';
  $('#add-modal').classList.add('show');
}

function initChart() {
  const ctx = document.getElementById('trafficChart');
  if (!ctx) return;
  trafficChart = new Chart(ctx, {
    type: 'line',
    data: {labels: [], datasets: [{label: 'MB', data: [], borderColor: '#2563eb', backgroundColor: 'rgba(37,99,235,0.08)', borderWidth: 2, fill: true, tension: 0.4, pointBackgroundColor: '#2563eb', pointBorderColor: '#fff', pointBorderWidth: 2, pointRadius: 4, pointHoverRadius: 6}]},
    options: {responsive: true, maintainAspectRatio: false, plugins: {legend: {display: false}}, scales: {y: {beginAtZero: true, grid: {color: 'rgba(255,255,255,0.05)'}, ticks: {color: 'rgba(255,255,255,0.5)'}}, x: {grid: {display: false}, ticks: {color: 'rgba(255,255,255,0.5)'}}}}
  });
}

function updateChart() {
  if (!trafficChart || !statsData.hourly_traffic) return;
  const ht = statsData.hourly_traffic;
  const sorted = Object.entries(ht).sort((a, b) => a[0].localeCompare(b[0])).slice(-12);
  const labels = sorted.map(e => e[0]);
  const data = sorted.map(e => Math.round(e[1] / 1048576));
  trafficChart.data.labels = labels;
  trafficChart.data.datasets[0].data = data;
  trafficChart.update();
}

applyTheme(theme);
initChart();
loadStats();
loadLinks();
setInterval(() => {loadStats()}, 10000);
setInterval(() => {loadLinks()}, 30000);
</script>
</body>
</html>"""

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
