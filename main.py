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
logger = logging.getLogger("WireXnet-Panel")

app = FastAPI(title="WireXnet Panel", docs_url=None, redoc_url=None)

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

def generate_uuid() -> str:
    """Generate random UUID v4"""
    return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(4) + "-" + secrets.token_hex(4) + "-" + secrets.token_hex(4) + "-" + secrets.token_hex(12)

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
    logger.info(f"WireXnet Panel started on port {CONFIG['port']}")
    asyncio.create_task(keep_alive())

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

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

def format_bytes(bytes_val: int) -> str:
    if bytes_val >= 1073741824:
        return f"{bytes_val / 1073741824:.2f} GB"
    elif bytes_val >= 1048576:
        return f"{bytes_val / 1048576:.2f} MB"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.2f} KB"
    return f"{bytes_val} B"

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            uid = generate_uuid()
            LINKS[uid] = {
                "label": "Default", 
                "limit_bytes": 0, 
                "used_bytes": 0, 
                "max_connections": 0, 
                "created_at": datetime.now().isoformat(), 
                "active": True, 
                "uuid": uid
            }

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"

def count_connections_for_link(uid: str) -> int:
    return len(link_ip_map.get(uid, set()))

def count_total_users() -> int:
    return len(LINKS)

def count_online_users() -> int:
    active_ips = set()
    for ips in link_ip_map.values():
        active_ips.update(ips)
    return len(active_ips)

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
    return {"service": "WireXnet Panel", "version": "2.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    return {
        "status": "ok", 
        "connections": len(connections),
        "total_users": count_total_users(),
        "online_users": count_online_users(),
        "uptime": uptime()
    }

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
    return {
        "active_connections": len(connections),
        "total_traffic_gb": round(stats["total_bytes"] / (1024 * 1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "total_users": count_total_users(),
        "online_users": count_online_users(),
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
    
    uid = generate_uuid()
    async with LINKS_LOCK:
        # Check if UUID already exists (extremely unlikely)
        while uid in LINKS:
            uid = generate_uuid()
        LINKS[uid] = {
            "label": label, 
            "limit_bytes": 0, 
            "used_bytes": 0, 
            "max_connections": 0, 
            "created_at": datetime.now().isoformat(), 
            "active": True, 
            "uuid": uid
        }
    
    return {
        "uuid": uid, 
        "label": label, 
        "limit_bytes": 0, 
        "used_bytes": 0, 
        "max_connections": 0, 
        "active": True, 
        "created_at": LINKS[uid]["created_at"], 
        "vless_link": generate_vless_link(uid, remark=f"WireXnet-{label}")
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({
                "uuid": uid, 
                "label": data["label"], 
                "limit_bytes": data["limit_bytes"], 
                "used_bytes": data["used_bytes"], 
                "max_connections": data.get("max_connections", 0), 
                "active": data["active"], 
                "created_at": data["created_at"], 
                "current_connections": count_connections_for_link(uid), 
                "vless_link": generate_vless_link(uid, remark=f"WireXnet-{data['label']}")
            })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
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
    used_gb = round(used / (1024 * 1024 * 1024), 2)
    limit_gb = round(limit / (1024 * 1024 * 1024), 2) if limit > 0 else 0
    pct = round((used / limit) * 100, 1) if limit > 0 else 0
    remaining_gb = round((limit - used) / (1024 * 1024 * 1024), 2) if limit > 0 else 0
    
    # Calculate remaining days (unlimited = 3650 days = 10 years)
    remaining_days = 3650 if limit == 0 else 0
    
    import base64
    sub_content = f"""# WireXnet Subscription
# Label: {link['label']}
# Used: {used_gb} GB / {limit_gb if limit > 0 else 'Unlimited'} GB
# Remaining: {remaining_gb if limit > 0 else 'Unlimited'} GB
# Usage: {pct}%
# Status: {'Active' if link['active'] else 'Disabled'}
# Remaining Days: {remaining_days if limit > 0 else 'Unlimited'}
{vless_link}"""
    encoded = base64.b64encode(sub_content.encode()).decode()
    
    return {
        "subscription_url": f"https://{get_domain()}/sub/{uid}",
        "config": vless_link,
        "label": link["label"],
        "used_bytes": used,
        "limit_bytes": limit,
        "used_gb": used_gb,
        "limit_gb": limit_gb,
        "remaining_gb": remaining_gb,
        "usage_percent": pct,
        "active": link["active"],
        "remaining_days": remaining_days,
        "sub_base64": encoded,
        "sub_text": sub_content,
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
    server_link = generate_vless_link(uid, remark=f"WireXnet-{link['label']}")
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
    pos += 1  # skip version
    pos += 16  # skip uuid
    addon_len = first_chunk[pos]
    pos += 1
    pos += addon_len
    command = first_chunk[pos]
    pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big")
    pos += 2
    addr_type = first_chunk[pos]
    pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]
        pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]
        pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]
        pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None: 
            return False
        if not link["active"]: 
            return False
        if link["limit_bytes"] == 0: 
            return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": 
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: 
                continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break
            stats["total_bytes"] += size
            stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            writer.write(data)
            await writer.drain()
    except WebSocketDisconnect:
        pass
    finally:
        try:
            writer.write_eof()
        except:
            pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: 
                break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break
            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except:
        pass

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
                await websocket.close(code=1008, reason="link not found or disabled")
                return
            max_conn = link_data.get("max_connections", 0)
        
        if max_conn > 0:
            already_connected = client_ip in link_ip_map.get(uuid, set())
            if not already_connected:
                current = count_connections_for_link(uuid)
                if current >= max_conn:
                    await websocket.close(code=1008, reason="connection limit reached")
                    return
        
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return
        
        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {
            "uuid": uuid, 
            "ip": client_ip, 
            "connected_at": datetime.now().isoformat(), 
            "bytes": 0
        }
        connection_sockets[conn_id] = websocket
        link_ip_map[uuid].add(client_ip)
        
        size = len(first_chunk)
        stats["total_bytes"] += size
        stats["total_requests"] += 1
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
            writer.write(initial_payload)
            await writer.drain()
        
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait(
            {task_up, task_down}, 
            return_when=asyncio.FIRST_COMPLETED
        )
        for t in pending:
            t.cancel()
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try:
                writer.close()
            except:
                pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                uid = info.get("uuid")
                ip = info.get("ip")
                if uid and ip:
                    has_other = any(
                        c.get("uuid") == uid and c.get("ip") == ip 
                        for c in connections.values()
                    )
                    if not has_other:
                        remove_ip_from_link(uid, ip)

# HTML Templates
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireXnet Panel - Login</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #f5f5f5;
            color: #1a1a1a;
            transition: background 0.3s, color 0.3s;
        }
        body.dark {
            background: #0d0d0d;
            color: #e8e8e8;
        }
        .login-container {
            width: 100%;
            max-width: 400px;
            padding: 20px;
        }
        .login-card {
            background: #ffffff;
            border-radius: 20px;
            padding: 48px 36px 36px;
            box-shadow: 0 4px 24px rgba(0,0,0,0.06);
            border: 1px solid rgba(0,0,0,0.04);
            transition: background 0.3s, border 0.3s;
        }
        body.dark .login-card {
            background: #1a1a1a;
            border-color: rgba(255,255,255,0.06);
            box-shadow: 0 4px 24px rgba(0,0,0,0.3);
        }
        .brand {
            text-align: center;
            margin-bottom: 36px;
        }
        .brand-icon {
            width: 56px;
            height: 56px;
            border-radius: 14px;
            background: #1a1a1a;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 16px;
            color: #fff;
            font-weight: 800;
            font-size: 18px;
        }
        body.dark .brand-icon {
            background: #2a2a2a;
            color: #e8e8e8;
        }
        .brand h1 {
            font-size: 22px;
            font-weight: 700;
            letter-spacing: -0.02em;
        }
        .brand p {
            font-size: 13px;
            color: #888;
            margin-top: 4px;
            font-weight: 400;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            font-size: 12px;
            font-weight: 600;
            color: #666;
            margin-bottom: 6px;
            letter-spacing: 0.02em;
        }
        body.dark .form-group label {
            color: #999;
        }
        .form-group input {
            width: 100%;
            padding: 12px 16px;
            background: #f8f8f8;
            border: 1.5px solid #e8e8e8;
            border-radius: 12px;
            font-family: inherit;
            font-size: 14px;
            color: #1a1a1a;
            outline: none;
            transition: all 0.2s;
        }
        body.dark .form-group input {
            background: #222;
            border-color: #333;
            color: #e8e8e8;
        }
        .form-group input:focus {
            border-color: #1a1a1a;
            box-shadow: 0 0 0 3px rgba(0,0,0,0.05);
        }
        body.dark .form-group input:focus {
            border-color: #555;
            box-shadow: 0 0 0 3px rgba(255,255,255,0.05);
        }
        .login-btn {
            width: 100%;
            padding: 13px;
            background: #1a1a1a;
            color: #fff;
            border: none;
            border-radius: 12px;
            font-family: inherit;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        body.dark .login-btn {
            background: #2a2a2a;
            color: #e8e8e8;
        }
        .login-btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.1);
        }
        body.dark .login-btn:hover {
            background: #333;
        }
        .error-msg {
            background: #fef2f2;
            border: 1px solid #fecaca;
            color: #dc2626;
            padding: 10px 14px;
            border-radius: 10px;
            font-size: 13px;
            display: none;
            margin-bottom: 16px;
            text-align: center;
        }
        body.dark .error-msg {
            background: #2a1215;
            border-color: #3a1a1d;
            color: #f87171;
        }
        .error-msg.show { display: block; }
        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            width: 40px;
            height: 40px;
            border-radius: 12px;
            border: 1px solid rgba(0,0,0,0.06);
            background: #fff;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s;
            font-size: 18px;
        }
        body.dark .theme-toggle {
            background: #1a1a1a;
            border-color: rgba(255,255,255,0.06);
        }
        .theme-toggle:hover {
            transform: scale(1.05);
        }
        .footer-text {
            text-align: center;
            font-size: 12px;
            color: #aaa;
            margin-top: 20px;
        }
        body.dark .footer-text {
            color: #555;
        }
    </style>
</head>
<body>
    <button class="theme-toggle" onclick="toggleTheme()">🌓</button>
    <div class="login-container">
        <div class="login-card">
            <div class="brand">
                <div class="brand-icon">W</div>
                <h1>WireXnet</h1>
                <p>Panel v2.0</p>
            </div>
            <div class="error-msg" id="err-box"></div>
            <form id="login-form">
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="password" placeholder="Enter password" autofocus>
                </div>
                <button type="submit" class="login-btn">Sign In</button>
            </form>
            <div class="footer-text">Secure • Private • Fast</div>
        </div>
    </div>
    <script>
        let theme = localStorage.getItem('wirexnet_theme') || 'light';
        function applyTheme(t) {
            theme = t;
            document.body.classList.toggle('dark', t === 'dark');
            localStorage.setItem('wirexnet_theme', t);
        }
        function toggleTheme() {
            applyTheme(theme === 'dark' ? 'light' : 'dark');
        }
        applyTheme(theme);

        document.getElementById('login-form').addEventListener('submit', async e => {
            e.preventDefault();
            const err = document.getElementById('err-box');
            err.classList.remove('show');
            try {
                const r = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: document.getElementById('password').value })
                });
                if (!r.ok) {
                    const d = await r.json().catch(() => ({}));
                    throw new Error(d.detail || 'Invalid password');
                }
                location.href = '/dashboard';
            } catch(e) {
                err.textContent = e.message;
                err.classList.add('show');
            }
        });
    </script>
</body>
</html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireXnet Panel - Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        :root {
            --bg: #f5f5f5;
            --surface: #ffffff;
            --surface2: #f8f8f8;
            --surface3: #f0f0f0;
            --border: rgba(0,0,0,0.06);
            --text: #1a1a1a;
            --text2: #666;
            --text3: #999;
            --primary: #1a1a1a;
            --primary-dim: rgba(0,0,0,0.04);
            --green: #22c55e;
            --green-dim: rgba(34,197,94,0.08);
            --red: #ef4444;
            --red-dim: rgba(239,68,68,0.06);
            --yellow: #f59e0b;
        }
        .dark {
            --bg: #0d0d0d;
            --surface: #1a1a1a;
            --surface2: #222;
            --surface3: #2a2a2a;
            --border: rgba(255,255,255,0.06);
            --text: #e8e8e8;
            --text2: #888;
            --text3: #555;
            --primary: #e8e8e8;
            --primary-dim: rgba(255,255,255,0.04);
        }
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            transition: background 0.3s, color 0.3s;
        }
        .app {
            display: flex;
            min-height: 100vh;
        }
        .sidebar {
            width: 220px;
            background: var(--surface);
            border-right: 1px solid var(--border);
            padding: 20px 12px;
            display: flex;
            flex-direction: column;
            position: fixed;
            left: 0;
            top: 0;
            bottom: 0;
            z-index: 100;
            transition: background 0.3s, border 0.3s;
        }
        .sidebar-brand {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 0 8px 16px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 16px;
        }
        .sidebar-brand .icon {
            width: 36px;
            height: 36px;
            border-radius: 10px;
            background: var(--primary);
            color: var(--bg);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 14px;
        }
        .dark .sidebar-brand .icon {
            color: #0d0d0d;
        }
        .sidebar-brand .name {
            font-weight: 700;
            font-size: 16px;
            letter-spacing: -0.02em;
        }
        .sidebar-nav {
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        .nav-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 12px;
            border-radius: 10px;
            color: var(--text2);
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            border: none;
            background: none;
            width: 100%;
            text-align: left;
            transition: all 0.15s;
            font-family: inherit;
        }
        .nav-item:hover {
            background: var(--primary-dim);
            color: var(--text);
        }
        .nav-item.active {
            background: var(--primary-dim);
            color: var(--text);
            font-weight: 600;
        }
        .nav-item .badge {
            margin-left: auto;
            background: var(--surface3);
            color: var(--text3);
            font-size: 10px;
            padding: 2px 8px;
            border-radius: 8px;
            font-weight: 600;
        }
        .nav-section {
            font-size: 10px;
            font-weight: 700;
            color: var(--text3);
            text-transform: uppercase;
            letter-spacing: 0.06em;
            padding: 16px 12px 6px;
        }
        .sidebar-footer {
            padding-top: 16px;
            border-top: 1px solid var(--border);
        }
        .sidebar-footer .logout {
            width: 100%;
            padding: 8px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: none;
            color: var(--text3);
            font-family: inherit;
            font-size: 12px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
        }
        .sidebar-footer .logout:hover {
            background: var(--red-dim);
            border-color: rgba(239,68,68,0.2);
            color: var(--red);
        }
        .sidebar-footer .version {
            text-align: center;
            font-size: 10px;
            color: var(--text3);
            margin-top: 10px;
        }
        .main {
            margin-left: 220px;
            flex: 1;
            padding: 24px 32px 48px;
        }
        .page {
            display: none;
            animation: fadeIn 0.3s ease;
        }
        .page.active { display: block; }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .page-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        .page-title {
            font-size: 20px;
            font-weight: 700;
            letter-spacing: -0.02em;
        }
        .page-sub {
            font-size: 13px;
            color: var(--text2);
            margin-top: 2px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 18px 20px;
            transition: all 0.2s;
        }
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.03);
        }
        .stat-label {
            font-size: 11px;
            color: var(--text3);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .stat-value {
            font-size: 24px;
            font-weight: 700;
            margin-top: 6px;
            letter-spacing: -0.02em;
        }
        .stat-value .unit {
            font-size: 14px;
            font-weight: 400;
            color: var(--text3);
            margin-left: 2px;
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
            margin-bottom: 12px;
        }
        .card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 14px;
        }
        .card-title {
            font-size: 14px;
            font-weight: 600;
        }
        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
        }
        .sys-bar {
            height: 6px;
            background: var(--surface3);
            border-radius: 3px;
            overflow: hidden;
        }
        .sys-bar-fill {
            height: 100%;
            border-radius: 3px;
            transition: width 0.4s;
        }
        .table-wrap { overflow-x: auto; }
        .table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        .table th {
            text-align: left;
            font-size: 11px;
            font-weight: 600;
            color: var(--text3);
            padding: 10px 12px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            border-bottom: 1px solid var(--border);
        }
        .table td {
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
        }
        .table tr:last-child td { border-bottom: none; }
        .table tbody tr:hover td { background: var(--primary-dim); }
        .tag {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 6px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }
        .tag-vless { background: var(--primary-dim); color: var(--text); }
        .tag-active { background: var(--green-dim); color: var(--green); }
        .tag-disabled { background: var(--red-dim); color: var(--red); }
        .toggle {
            width: 34px;
            height: 18px;
            border-radius: 10px;
            background: var(--surface3);
            position: relative;
            cursor: pointer;
            border: 1px solid var(--border);
            transition: all 0.3s;
        }
        .toggle::after {
            content: '';
            position: absolute;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: var(--text3);
            top: 2px;
            left: 2px;
            transition: all 0.3s;
        }
        .toggle.on {
            background: var(--green);
            border-color: var(--green);
        }
        .toggle.on::after {
            left: 18px;
            background: #fff;
        }
        .usage-pill {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 2px 8px;
            border-radius: 999px;
            background: var(--surface3);
            font-size: 11px;
            color: var(--text2);
        }
        .usage-pill .bar {
            flex: 1;
            height: 4px;
            background: var(--bg);
            border-radius: 2px;
            min-width: 40px;
        }
        .usage-pill .fill {
            height: 100%;
            border-radius: 2px;
            transition: width 0.3s;
        }
        .btn {
            font-family: inherit;
            font-size: 12px;
            font-weight: 600;
            padding: 7px 14px;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            transition: all 0.15s;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }
        .btn-primary {
            background: var(--primary);
            color: var(--bg);
        }
        .dark .btn-primary {
            color: #0d0d0d;
        }
        .btn-primary:hover { filter: brightness(0.9); }
        .btn-secondary {
            background: var(--surface3);
            color: var(--text2);
            border: 1px solid var(--border);
        }
        .btn-secondary:hover {
            border-color: var(--text);
            color: var(--text);
        }
        .btn-danger {
            background: var(--red-dim);
            color: var(--red);
            border: 1px solid rgba(239,68,68,0.1);
        }
        .btn-danger:hover { background: rgba(239,68,68,0.15); }
        .btn-sm { padding: 4px 10px; font-size: 11px; }
        .modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.5);
            z-index: 200;
            display: none;
            align-items: center;
            justify-content: center;
            backdrop-filter: blur(4px);
        }
        .modal-overlay.show { display: flex; }
        .modal {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 28px;
            max-width: 440px;
            width: 100%;
            animation: modalIn 0.3s ease;
        }
        @keyframes modalIn {
            from { transform: scale(0.95); opacity: 0; }
            to { transform: scale(1); opacity: 1; }
        }
        .modal-title { font-size: 16px; font-weight: 700; margin-bottom: 18px; }
        .modal-close {
            float: right;
            background: none;
            border: none;
            font-size: 20px;
            cursor: pointer;
            color: var(--text3);
        }
        .form-group {
            margin-bottom: 14px;
        }
        .form-group label {
            display: block;
            font-size: 12px;
            font-weight: 600;
            color: var(--text2);
            margin-bottom: 4px;
        }
        .form-group input, .form-group select {
            width: 100%;
            padding: 10px 14px;
            background: var(--surface2);
            border: 1px solid var(--border);
            border-radius: 10px;
            font-family: inherit;
            font-size: 13px;
            color: var(--text);
            outline: none;
            transition: all 0.2s;
        }
        .form-group input:focus, .form-group select:focus {
            border-color: var(--primary);
        }
        .form-row {
            display: flex;
            gap: 10px;
        }
        .form-row .form-group { flex: 1; margin-bottom: 0; }
        .toast {
            position: fixed;
            bottom: 24px;
            left: 50%;
            transform: translateX(-50%) translateY(20px);
            background: var(--surface);
            color: var(--text);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 12px 24px;
            font-size: 13px;
            font-weight: 500;
            opacity: 0;
            transition: all 0.3s cubic-bezier(0.4,0,0.2,1);
            z-index: 999;
            box-shadow: 0 8px 24px rgba(0,0,0,0.08);
        }
        .toast.show {
            opacity: 1;
            transform: translateX(-50%) translateY(0);
        }
        .toast.error {
            border-color: var(--red-dim);
            color: var(--red);
        }
        .empty {
            text-align: center;
            padding: 40px 16px;
            color: var(--text3);
        }
        .inline-actions { display: flex; gap: 4px; align-items: center; flex-wrap: wrap; }
        .mobile-header { display: none; }
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
                width: 240px;
            }
            .sidebar.open { transform: translateX(0); }
            .main { margin-left: 0; padding: 16px; }
            .mobile-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 12px 16px;
                background: var(--surface);
                border-bottom: 1px solid var(--border);
                position: sticky;
                top: 0;
                z-index: 50;
            }
            .mobile-header .menu-btn {
                background: none;
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 6px 12px;
                font-size: 18px;
                cursor: pointer;
                color: var(--text);
            }
            .stats-grid { grid-template-columns: 1fr 1fr; }
            .grid-2 { grid-template-columns: 1fr; }
            .table-wrap { display: none; }
            .inbound-cards { display: flex; flex-direction: column; gap: 8px; }
        }
        .inbound-cards { display: none; }
        @media (max-width: 768px) {
            .inbound-cards { display: flex; }
        }
        .inbound-card {
            background: var(--surface2);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .inbound-card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .inbound-card-name { font-weight: 600; font-size: 14px; }
        .inbound-card-actions { display: flex; gap: 4px; flex-wrap: wrap; }
        .sidebar-overlay {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.4);
            z-index: 99;
        }
        .sidebar-overlay.show { display: block; }
        @media (min-width: 769px) {
            .sidebar-overlay { display: none !important; }
        }
        .qr-box {
            text-align: center;
            padding: 20px;
            background: var(--surface2);
            border-radius: 12px;
            margin-top: 12px;
        }
        .qr-box img { max-width: 200px; border-radius: 8px; }
        .detail-value {
            padding: 8px 12px;
            background: var(--surface2);
            border-radius: 8px;
            font-size: 12px;
            word-break: break-all;
            font-family: monospace;
        }
        .detail-row { display: flex; gap: 12px; flex-wrap: wrap; }
        .detail-col { flex: 1; min-width: 120px; }
        .detail-label { font-size: 10px; font-weight: 700; color: var(--text3); text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 4px; }
    </style>
</head>
<body>
    <div class="toast" id="toast"></div>

    <div class="mobile-header">
        <span style="font-weight:700;font-size:15px">WireXnet</span>
        <button class="menu-btn" onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebar-overlay').classList.toggle('show')">☰</button>
    </div>
    <div class="sidebar-overlay" id="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('show')"></div>

    <aside class="sidebar" id="sidebar">
        <div class="sidebar-brand">
            <div class="icon">W</div>
            <span class="name">WireXnet</span>
        </div>
        <nav class="sidebar-nav">
            <div class="nav-section">Main</div>
            <button class="nav-item active" data-page="dashboard">
                <span>📊</span> Dashboard
            </button>
            <button class="nav-item" data-page="inbounds">
                <span>📡</span> Inbounds
                <span class="badge" id="links-badge">0</span>
            </button>
            <button class="nav-item" data-page="traffic">
                <span>📈</span> Traffic
            </button>
            <button class="nav-item" data-page="addresses">
                <span>🌐</span> Clean IP
            </button>
            <div class="nav-section">System</div>
            <button class="nav-item" data-page="security">
                <span>🔒</span> Security
            </button>
        </nav>
        <div class="sidebar-footer">
            <button class="logout" onclick="fetch('/api/logout',{method:'POST'}).then(()=>location.href='/login')">🚪 Logout</button>
            <div class="version">v2.0</div>
        </div>
    </aside>

    <main class="main">
        <!-- Dashboard Page -->
        <section class="page active" id="page-dashboard">
            <div class="page-header">
                <div>
                    <div class="page-title">Dashboard</div>
                    <div class="page-sub" id="last-update">Loading...</div>
                </div>
                <button class="btn btn-primary" onclick="showAddModal()">+ New Inbound</button>
            </div>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Traffic</div>
                    <div class="stat-value" id="s-traffic">-- <span class="unit">GB</span></div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Users</div>
                    <div class="stat-value" id="s-users">--</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Online</div>
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
                        <span class="card-title">CPU</span>
                        <span id="s-cpu-val" style="font-weight:700;font-size:18px">--%</span>
                    </div>
                    <div class="sys-bar"><div class="sys-bar-fill" id="s-cpu-bar" style="width:0%;background:var(--primary)"></div></div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Memory</span>
                        <span id="s-mem-val" style="font-weight:700;font-size:18px;color:var(--green)">--%</span>
                    </div>
                    <div class="sys-bar"><div class="sys-bar-fill" id="s-mem-bar" style="width:0%;background:var(--green)"></div></div>
                </div>
            </div>
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Traffic Chart</span>
                </div>
                <div style="height:200px"><canvas id="trafficChart"></canvas></div>
            </div>
        </section>

        <!-- Inbounds Page -->
        <section class="page" id="page-inbounds">
            <div class="page-header">
                <div>
                    <div class="page-title">Inbounds</div>
                    <div class="page-sub">VLESS over WebSocket</div>
                </div>
                <button class="btn btn-primary" onclick="showAddModal()">+ Add</button>
            </div>
            <div class="card" style="padding:0;overflow:hidden">
                <div class="table-wrap">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Name</th>
                                <th>Type</th>
                                <th>Traffic</th>
                                <th>IPs</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="links-tbody"></tbody>
                    </table>
                </div>
                <div class="inbound-cards" id="inbound-cards"></div>
                <div class="empty" id="links-empty" style="display:none">No inbounds found</div>
            </div>
        </section>

        <!-- Traffic Page -->
        <section class="page" id="page-traffic">
            <div class="page-header"><div><div class="page-title">Traffic</div><div class="page-sub">Statistics overview</div></div></div>
            <div class="card">
                <div class="card-header"><span class="card-title">Overview</span></div>
                <div style="display:flex;flex-direction:column;gap:10px">
                    <div style="display:flex;justify-content:space-between"><span style="color:var(--text2)">Total Traffic</span><span style="font-weight:600" id="t-traffic">-- GB</span></div>
                    <div style="display:flex;justify-content:space-between"><span style="color:var(--text2)">Total Requests</span><span style="font-weight:600" id="t-reqs">--</span></div>
                    <div style="display:flex;justify-content:space-between"><span style="color:var(--text2)">Uptime</span><span style="font-weight:600" id="t-uptime">--</span></div>
                </div>
            </div>
        </section>

        <!-- Addresses Page -->
        <section class="page" id="page-addresses">
            <div class="page-header">
                <div><div class="page-title">Clean IP</div><div class="page-sub">IPs for subscription configs</div></div>
                <button class="btn btn-primary" onclick="showAddAddressModal()">+ Add IP</button>
            </div>
            <div class="card">
                <div class="card-header"><span class="card-title">IP List</span></div>
                <div id="address-list"></div>
            </div>
        </section>

        <!-- Security Page -->
        <section class="page" id="page-security">
            <div class="page-header"><div><div class="page-title">Security</div><div class="page-sub">Change password</div></div></div>
            <div class="card" style="max-width:400px">
                <div class="form-group"><label>Current Password</label><input class="form-input" type="password" id="cur-pw" placeholder="Enter current password"></div>
                <div class="form-group"><label>New Password</label><input class="form-input" type="password" id="new-pw" placeholder="Min 4 characters"></div>
                <button class="btn btn-primary" onclick="changePassword()">Update Password</button>
            </div>
        </section>
    </main>

    <!-- Modals -->
    <div class="modal-overlay" id="add-modal" onclick="if(event.target===this)this.classList.remove('show')">
        <div class="modal">
            <button class="modal-close" onclick="document.getElementById('add-modal').classList.remove('show')">✕</button>
            <div class="modal-title">Add Inbound</div>
            <div class="form-group"><label>Name</label><input class="form-input" id="new-label" placeholder="e.g. User 1"></div>
            <button class="btn btn-primary" onclick="createLink()" style="width:100%;justify-content:center">Create</button>
        </div>
    </div>

    <div class="modal-overlay" id="detail-modal" onclick="if(event.target===this)this.classList.remove('show')">
        <div class="modal" style="max-width:500px">
            <button class="modal-close" onclick="document.getElementById('detail-modal').classList.remove('show')">✕</button>
            <div class="modal-title" id="detail-title">Details</div>
            <div id="detail-content"></div>
        </div>
    </div>

    <div class="modal-overlay" id="add-address-modal" onclick="if(event.target===this)this.classList.remove('show')">
        <div class="modal">
            <button class="modal-close" onclick="document.getElementById('add-address-modal').classList.remove('show')">✕</button>
            <div class="modal-title">Add Clean IP</div>
            <div class="form-group"><label>IP or Domain</label><input class="form-input" id="new-address" placeholder="e.g. 8.8.8.8"></div>
            <button class="btn btn-primary" onclick="addAddress()" style="width:100%;justify-content:center">Add</button>
        </div>
    </div>

    <script>
        const $ = s => document.querySelector(s);
        const $$ = s => document.querySelectorAll(s);
        let allLinks = [], allAddresses = [], statsData = {}, trafficChart = null;

        function toast(msg, err = false) {
            const t = $('#toast');
            t.textContent = msg;
            t.className = 'toast' + (err ? ' error' : '') + ' show';
            clearTimeout(t._timeout);
            t._timeout = setTimeout(() => t.classList.remove('show'), 3000);
        }

        function esc(s) { return String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

        function fmtBytes(b) {
            if (b >= 1073741824) return (b/1073741824).toFixed(2) + ' GB';
            if (b >= 1048576) return (b/1048576).toFixed(2) + ' MB';
            if (b >= 1024) return (b/1024).toFixed(1) + ' KB';
            return b + ' B';
        }

        $$('.nav-item').forEach(el => {
            el.addEventListener('click', () => {
                $$('.nav-item').forEach(n => n.classList.remove('active'));
                el.classList.add('active');
                $$('.page').forEach(p => p.classList.remove('active'));
                const pg = $('#page-' + el.dataset.page);
                if (pg) pg.classList.add('active');
                document.getElementById('sidebar').classList.remove('open');
                document.getElementById('sidebar-overlay').classList.remove('show');
            });
        });

        async function loadStats() {
            try {
                const r = await fetch('/stats');
                if (!r.ok) throw new Error();
                statsData = await r.json();
                $('#s-traffic').innerHTML = (statsData.total_traffic_gb || 0) + ' <span class="unit">GB</span>';
                $('#s-users').textContent = statsData.total_users || 0;
                $('#s-online').textContent = statsData.online_users || 0;
                $('#s-uptime').textContent = statsData.uptime || '--';
                $('#links-badge').textContent = statsData.links_count || 0;
                $('#last-update').textContent = 'Updated: ' + new Date().toLocaleTimeString();
                if ($('#t-traffic')) $('#t-traffic').textContent = (statsData.total_traffic_gb || 0) + ' GB';
                if ($('#t-reqs')) $('#t-reqs').textContent = (statsData.total_requests || 0).toLocaleString();
                if ($('#t-uptime')) $('#t-uptime').textContent = statsData.uptime || '--';

                if (statsData.cpu_percent !== undefined) {
                    const c = statsData.cpu_percent;
                    $('#s-cpu-val').textContent = c.toFixed(1) + '%';
                    $('#s-cpu-bar').style.width = c + '%';
                }
                if (statsData.memory_percent !== undefined) {
                    const m = statsData.memory_percent;
                    $('#s-mem-val').textContent = m.toFixed(1) + '%';
                    $('#s-mem-bar').style.width = m + '%';
                }
                updateChart();
            } catch(e) { /* ignore */ }
        }

        async function loadLinks() {
            try {
                const r = await fetch('/api/links');
                if (!r.ok) throw new Error();
                const d = await r.json();
                allLinks = d.links || [];
                renderLinks(allLinks);
            } catch(e) { /* ignore */ }
        }

        function renderLinks(links) {
            const tbody = $('#links-tbody');
            const empty = $('#links-empty');
            const cards = $('#inbound-cards');
            if (!links || !links.length) {
                tbody.innerHTML = '';
                cards.innerHTML = '';
                empty.style.display = 'block';
                return;
            }
            empty.style.display = 'none';
            let idx = links.length;
            const rows = links.map(l => {
                const u = l.used_bytes || 0, lim = l.limit_bytes || 0;
                const uF = fmtBytes(u);
                const lF = lim > 0 ? fmtBytes(lim) : 'Unlimited';
                const pct = lim > 0 ? Math.min(100, (u/lim)*100) : 0;
                const col = pct > 90 ? 'var(--red)' : pct > 70 ? 'var(--yellow)' : 'var(--primary)';
                const i = idx--;
                return { l, uF, lF, pct, col, i, maxConn: l.max_connections || 0, curConn: l.current_connections || 0 };
            });

            tbody.innerHTML = rows.map(r => `
                <tr>
                    <td style="color:var(--text3);font-size:12px">${r.i}</td>
                    <td style="font-weight:600">${esc(r.l.label)}</td>
                    <td><span class="tag tag-vless">VLESS</span></td>
                    <td><div class="usage-pill"><span class="used">${r.uF}</span><div class="bar"><div class="fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="limit">${r.lF}</span></div></td>
                    <td style="font-size:12px;font-weight:600;color:${r.maxConn > 0 && r.curConn >= r.maxConn ? 'var(--red)' : 'var(--text2)'}">${r.curConn}/${r.maxConn || '∞'}</td>
                    <td><span class="tag ${r.l.active ? 'tag-active' : 'tag-disabled'}">${r.l.active ? 'On' : 'Off'}</span></td>
                    <td><div class="inline-actions">
                        <button class="toggle ${r.l.active ? 'on' : ''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)"></button>
                        <button class="btn btn-secondary btn-sm" onclick="showDetail('${r.l.uuid}')">📋</button>
                        <button class="btn btn-secondary btn-sm" onclick="copyConfig('${r.l.uuid}')">📄</button>
                        <button class="btn btn-secondary btn-sm" onclick="copySub('${r.l.uuid}')">🔗</button>
                        <button class="btn btn-danger btn-sm" onclick="deleteLink('${r.l.uuid}')">✕</button>
                    </div></td>
                </tr>
            `).join('');

            cards.innerHTML = rows.map(r => `
                <div class="inbound-card">
                    <div class="inbound-card-header">
                        <div><span class="inbound-card-name">${esc(r.l.label)}</span> <span class="tag tag-vless">VLESS</span></div>
                        <button class="toggle ${r.l.active ? 'on' : ''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)"></button>
                    </div>
                    <div class="usage-pill"><span class="used">${r.uF}</span><div class="bar"><div class="fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="limit">${r.lF}</span></div>
                    <div style="display:flex;gap:4px;flex-wrap:wrap">
                        <button class="btn btn-secondary btn-sm" onclick="showDetail('${r.l.uuid}')">📋</button>
                        <button class="btn btn-secondary btn-sm" onclick="copyConfig('${r.l.uuid}')">📄</button>
                        <button class="btn btn-secondary btn-sm" onclick="copySub('${r.l.uuid}')">🔗</button>
                        <button class="btn btn-danger btn-sm" onclick="deleteLink('${r.l.uuid}')">✕</button>
                    </div>
                </div>
            `).join('');
        }

        async function toggleLink(el) {
            const uid = el.dataset.uid;
            const link = allLinks.find(l => l.uuid === uid);
            if (!link) return;
            const newActive = !link.active;
            try {
                await fetch(`/api/links/${uid}`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ active: newActive })
                });
                link.active = newActive;
                renderLinks(allLinks);
                loadStats();
            } catch(e) { toast('Error', true); }
        }

        async function deleteLink(uid) {
            if (!confirm('Delete this inbound?')) return;
            try {
                await fetch(`/api/links/${uid}`, { method: 'DELETE' });
                toast('Deleted');
                await loadLinks();
                await loadStats();
            } catch(e) { toast('Error', true); }
        }

        function showAddModal() { 
            document.getElementById('add-modal').classList.add('show'); 
            document.getElementById('new-label').focus();
        }

        async function createLink() {
            const label = document.getElementById('new-label').value.trim() || 'User-' + Math.floor(Math.random() * 1000);
            try {
                const r = await fetch('/api/links', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ label })
                });
                if (!r.ok) throw new Error();
                toast('Created: ' + label);
                document.getElementById('new-label').value = '';
                document.getElementById('add-modal').classList.remove('show');
                await loadLinks();
                await loadStats();
            } catch(e) { toast('Error', true); }
        }

        function showDetail(uid) {
            const l = allLinks.find(x => x.uuid === uid);
            if (!l) return;
            const u = l.used_bytes || 0, lim = l.limit_bytes || 0;
            const pct = lim > 0 ? Math.min(100, (u/lim)*100) : 0;
            const col = pct > 90 ? 'var(--red)' : pct > 70 ? 'var(--yellow)' : 'var(--primary)';
            document.getElementById('detail-title').textContent = l.label;
            document.getElementById('detail-content').innerHTML = `
                <div style="margin-bottom:12px"><div class="detail-label">UUID</div><div class="detail-value">${l.uuid}</div></div>
                <div class="detail-row">
                    <div class="detail-col"><div class="detail-label">Used</div><div class="detail-value">${fmtBytes(u)}</div></div>
                    <div class="detail-col"><div class="detail-label">Limit</div><div class="detail-value">${lim > 0 ? fmtBytes(lim) : 'Unlimited'}</div></div>
                    <div class="detail-col"><div class="detail-label">Usage</div><div class="detail-value">${pct.toFixed(1)}%</div></div>
                </div>
                <div class="sys-bar" style="margin-bottom:12px"><div class="sys-bar-fill" style="width:${pct}%;background:${col}"></div></div>
                <div style="margin-bottom:0"><div class="detail-label">VLESS Link</div><div class="detail-value" style="font-size:11px">${esc(l.vless_link || '')}</div></div>
                <div style="display:flex;gap:6px;margin-top:12px;flex-wrap:wrap">
                    <button class="btn btn-secondary btn-sm" onclick="copyText('${esc(l.vless_link || '')}')">📄 Copy</button>
                    <button class="btn btn-secondary btn-sm" onclick="copySub('${l.uuid}')">🔗 Subscription</button>
                </div>
            `;
            document.getElementById('detail-modal').classList.add('show');
        }

        function copyText(text) {
            navigator.clipboard.writeText(text).then(() => toast('Copied')).catch(() => toast('Failed', true));
        }

        async function copyConfig(uid) {
            const l = allLinks.find(x => x.uuid === uid);
            if (!l || !l.vless_link) return;
            copyText(l.vless_link);
        }

        async function copySub(uid) {
            const domain = location.host;
            const url = `https://${domain}/sub/${uid}`;
            copyText(url);
        }

        async function loadAddresses() {
            try {
                const r = await fetch('/api/addresses');
                if (!r.ok) throw new Error();
                const d = await r.json();
                allAddresses = d.addresses || [];
                const list = $('#address-list');
                if (!allAddresses.length) {
                    list.innerHTML = '<div style="color:var(--text3);padding:8px 0">No addresses added</div>';
                    return;
                }
                list.innerHTML = allAddresses.map((a, i) => `
                    <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 12px;background:var(--surface2);border-radius:8px;margin-bottom:6px">
                        <span>${esc(a)}</span>
                        <button class="btn btn-danger btn-sm" onclick="deleteAddress(${i})">✕</button>
                    </div>
                `).join('');
            } catch(e) { /* ignore */ }
        }

        function showAddAddressModal() {
            document.getElementById('new-address').value = '';
            document.getElementById('add-address-modal').classList.add('show');
        }

        async function addAddress() {
            const addr = document.getElementById('new-address').value.trim();
            if (!addr) { toast('Enter an IP or domain', true); return; }
            try {
                const r = await fetch('/api/addresses', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ address: addr })
                });
                if (!r.ok) throw new Error();
                toast('Added');
                document.getElementById('add-address-modal').classList.remove('show');
                await loadAddresses();
            } catch(e) { toast('Error', true); }
        }

        async function deleteAddress(index) {
            if (!confirm('Delete this address?')) return;
            try {
                await fetch(`/api/addresses/${index}`, { method: 'DELETE' });
                toast('Deleted');
                await loadAddresses();
            } catch(e) { toast('Error', true); }
        }

        async function changePassword() {
            const cur = document.getElementById('cur-pw').value;
            const nw = document.getElementById('new-pw').value;
            if (!cur || !nw) { toast('Fill all fields', true); return; }
            try {
                const r = await fetch('/api/change-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ current_password: cur, new_password: nw })
                });
                if (!r.ok) { const d = await r.json().catch(()=>({})); throw new Error(d.detail || 'Error'); }
                toast('Password updated');
                document.getElementById('cur-pw').value = '';
                document.getElementById('new-pw').value = '';
            } catch(e) { toast(e.message, true); }
        }

        function initChart() {
            const ctx = document.getElementById('trafficChart');
            if (!ctx) return;
            trafficChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'GB',
                        data: [],
                        borderColor: 'var(--primary)',
                        backgroundColor: 'var(--primary-dim)',
                        fill: true,
                        tension: 0.3,
                        pointRadius: 3,
                        pointBackgroundColor: 'var(--primary)',
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { grid: { display: false }, ticks: { color: 'var(--text3)', font: { size: 10 } } },
                        y: { grid: { color: 'var(--border)' }, ticks: { color: 'var(--text3)', font: { size: 10 }, callback: v => v + ' GB' }, beginAtZero: true }
                    }
                }
            });
        }
        initChart();

        function updateChart() {
            if (!trafficChart || !statsData.hourly_traffic) return;
            const ht = statsData.hourly_traffic;
            const sorted = Object.entries(ht).sort((a,b) => a[0].localeCompare(b[0])).slice(-12);
            const labels = sorted.map(e => e[0]);
            const data = sorted.map(e => Math.round(e[1] / 1073741824 * 100) / 100);
            trafficChart.data.labels = labels;
            trafficChart.data.datasets[0].data = data;
            trafficChart.update();
        }

        // Initial load
        loadStats();
        loadLinks();
        loadAddresses();
        setInterval(loadStats, 10000);

        // Close modals on escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal-overlay.show').forEach(el => el.classList.remove('show'));
            }
        });
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
