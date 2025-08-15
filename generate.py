#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import io
import ssl
import sys
import json
import time
import base64
import socket
import asyncio
import datetime
import traceback
import contextlib
from typing import List, Dict, Tuple

import requests
import yaml
import qrcode
from PIL import Image, ImageDraw
import socks  # PySocks

# ===================== 可调参数 =====================
TIMEOUT_TCP = 2.0
CONCURRENCY = 400
SOCKS_GOOGLE_TIMEOUT = 4.0
KEEP_TOP_PER_TYPE = 2000
STRICT_CN_GOOGLE = True
BATCH_SIZE = 20
EMBED_MAX_BYTES = 1800
QR_SIZE = 660
QR_BORDER = 24

# ===================== 订阅源 =====================
SOURCES = [
    "https://raw.githubusercontent.com/xyfqzy/free-nodes/main/nodes/shadowsocks.txt",
    "https://raw.githubusercontent.com/voken100g/AutoSSR/master/stable",
    "https://raw.githubusercontent.com/voken100g/AutoSSR/master/recent",
    "https://raw.githubusercontent.com/voken100g/AutoSSR/master/online",
    "https://raw.githubusercontent.com/general-vpn/FREE-Shadowsocks-Servers/main/README.md",
    "https://raw.githubusercontent.com/general-vpn/Free-VPN-Servers/main/README.md",
    "https://nodefree.org/dy/2025/0812.txt",
    "https://hidessh.com/shadowsocks",
    "https://linuxsss.com/latest/",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/Shadowsocks.txt",
    "https://raw.githubusercontent.com/freefq/free/master/shadowsocks",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/shadowsocks",
    "https://raw.githubusercontent.com/freefq/free/master/clash.yaml",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/clash/clash.yml",
]

# ===================== 路径 =====================
REPO = os.environ.get("GITHUB_REPOSITORY", "mingko3/socks5-2025-proxy")
OWNER, REPO_NAME = REPO.split("/")
SITE_BASE = f"https://{OWNER}.github.io/{REPO_NAME}"
RAW_BASE = f"https://raw.githubusercontent.com/{OWNER}/{REPO_NAME}/main/docs"

DOCS_DIR = "docs"
QRS_DIR = os.path.join(DOCS_DIR, "qrs")
GROUPS_DIR = os.path.join(DOCS_DIR, "groups")
os.makedirs(DOCS_DIR, exist_ok=True)
os.makedirs(QRS_DIR, exist_ok=True)
os.makedirs(GROUPS_DIR, exist_ok=True)

# ===================== 工具函数 =====================
def b64pad(s: str) -> str:
    pad = len(s) % 4
    return s + ("=" * (4 - pad)) if pad else s

def safe_int(v, default=None):
    try:
        return int(v)
    except:
        return default

def now_str_beijing():
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)\
        .astimezone(datetime.timezone(datetime.timedelta(hours=8)))\
        .strftime("%Y-%m-%d %H:%M:%S %Z%z")

def fetch_text(url: str, timeout=12) -> str:
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            return r.text
    except:
        pass
    return ""

# —— QR：彩色圆角边框 ——
def _rounded_rect(img: Image.Image, radius: int, border_px: int, color: tuple):
    w, h = img.size
    canvas = Image.new("RGBA", (w + border_px*2, h + border_px*2), (0,0,0,0))
    draw = ImageDraw.Draw(canvas)
    draw.rounded_rectangle([0,0,canvas.width,canvas.height], radius=radius, outline=color, width=border_px)
    canvas.paste(img, (border_px, border_px))
    return canvas.convert("RGB")

def make_qr_img(data: str, border_color=(52,104,255)) -> Image.Image:
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=max(2, QR_SIZE // 58), border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    img = img.resize((QR_SIZE, QR_SIZE), Image.NEAREST)
    return _rounded_rect(img, radius=36, border_px=QR_BORDER, color=border_color)

def save_qr_to(path: str, data: str, color: tuple):
    img = make_qr_img(data, border_color=color)
    img.save(path, format="PNG", optimize=True)

# ===================== 解析器 =====================
SS_RE     = re.compile(r"(ss://[A-Za-z0-9+/=_\-:%#@.]+)", re.IGNORECASE)
VMESS_RE  = re.compile(r"(vmess://[A-Za-z0-9+/=_\-:;{}\",.]+)", re.IGNORECASE)
TROJAN_RE = re.compile(r"(trojan://[A-Za-z0-9+/=_\-:%#@.]+)", re.IGNORECASE)
VLESS_RE  = re.compile(r"(vless://[A-Za-z0-9+/=_\-:%#@.?&=]+)", re.IGNORECASE)
IPPORT_RE = re.compile(r"\b((\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b")

def parse_ss(link: str):
    try:
        if not link.startswith("ss://"): return None
        raw = link[5:].split("#")[0]
        dec = base64.urlsafe_b64decode(b64pad(raw)).decode("utf-8","ignore")
        method, password = dec.split("@")[0].split(":",1)
        host, port = dec.split("@")[1].split(":")
        return {"name": f"SS_{host}_{port}", "type": "ss", "server": host, "port": safe_int(port), "cipher": method, "password": password, "udp": True}
    except:
        return None

def parse_vmess(link: str):
    try:
        if not link.startswith("vmess://"): return None
        js = json.loads(base64.b64decode(b64pad(link[8:])).decode("utf-8","ignore"))
        return {"name": js.get("ps") or f"VMess_{js.get('add')}_{js.get('port')}", "type": "vmess", "server": js.get("add"), "port": safe_int(js.get("port")), "uuid": js.get("id"), "alterId": safe_int(js.get("aid"),0), "cipher": "auto", "tls": js.get("tls")=="tls", "network": js.get("net") or "tcp", "ws-opts": {"path": js.get("path", "/"), "headers": {"Host": js.get("host", "")}}}
    except:
        return None

def parse_trojan(link: str):
    try:
        if not link.startswith("trojan://"): return None
        password, addr = link[9:].split("@",1)
        host, port = addr.split(":")
        return {"name": f"Trojan_{host}_{port}", "type": "trojan", "server": host, "port": safe_int(port), "password": password, "udp": True}
    except:
        return None

def parse_vless(link: str):
    try:
        if not link.startswith("vless://"): return None
        uuid, addr = link[8:].split("@",1)
        host, port = addr.split("?",1)[0].split(":")
        return {"name": f"VLESS_{host}_{port}", "type": "vless", "server": host, "port": safe_int(port), "uuid": uuid, "tls": True, "udp": True}
    except:
        return None

def extract_proto_links(text: str) -> List[str]:
    out = SS_RE.findall(text) + VMESS_RE.findall(text) + TROJAN_RE.findall(text) + VLESS_RE.findall(text)
    return list(dict.fromkeys(out))

def extract_ipports(text: str) -> List[Tuple[str, int]]:
    return list(dict.fromkeys([(m.group(1), safe_int(m.group(3))) for m in IPPORT_RE.finditer(text)]))

# ===================== 抓取与初步解析 =====================
def collect_nodes() -> List[Dict]:
    nodes, seen = [], set()
    for url in SOURCES:
        text = fetch_text(url)
        if not text: continue
        if "://" not in text and re.fullmatch(r"[A-Za-z0-9+/=\n\r]+", text) and len(text) > 64:
            try: text = base64.b64decode(b64pad(text)).decode("utf-8","ignore")
            except: pass
        for lk in extract_proto_links(text):
            p = parse_ss(lk) if lk.startswith("ss://") else parse_vmess(lk) if lk.startswith("vmess://") else parse_trojan(lk) if lk.startswith("trojan://") else parse_vless(lk)
            if p and (p["type"],p["server"],p["port"]) not in seen:
                seen.add((p["type"],p["server"],p["port"]))
                nodes.append(p)
        for host, port in extract_ipports(text):
            for proto in ("socks5","socks4","http"):
                if (proto, host, port) not in seen:
                    seen.add((proto, host, port))
                    nodes.append({"name": f"{proto.upper()}_{host}_{port}", "type": proto, "server": host, "port": port, "udp": False})
    return nodes

# ===================== 并发 TCP 测速 =====================
async def tcp_ping(host: str, port: int, timeout: float = TIMEOUT_TCP) -> float:
    start = time.perf_counter()
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        w.close()
        await w.wait_closed()
        return (time.perf_counter() - start) * 1000
    except:
        return -1

async def test_all_tcp(nodes: List[Dict]) -> List[Dict]:
    sem = asyncio.Semaphore(CONCURRENCY); out = []
    async def test_one(n):
        async with sem:
            d = await tcp_ping(n["server"], n["port"])
            if d > 0: n["delay"] = round(d,1); out.append(n)
    await asyncio.gather(*(test_one(n) for n in nodes))
    return out

# ===================== Google 验证 =====================
def google_via_socks_http(n: Dict) -> bool:
    host, port = n["server"], int(n["port"])
    try:
        if n["type"] in ("socks5","socks4"):
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5 if n["type"]=="socks5" else socks.SOCKS4, host, port)
            s.settimeout(SOCKS_GOOGLE_TIMEOUT)
            s.connect(("www.google.com", 80))
            s.close()
            return True
        elif n["type"] == "http":
            s = socket.create_connection(("www.google.com", 80), timeout=SOCKS_GOOGLE_TIMEOUT)
            s.close()
            return True
    except:
        return False
    return False

# ===================== 新增：节点转原始链接字符串 =====================
def node_to_uri(n: Dict) -> str:
    t = n["type"]
    if t == "ss":
        userinfo = base64.urlsafe_b64encode(f"{n['cipher']}:{n['password']}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{n['server']}:{n['port']}"
    elif t == "vmess":
        js = {"v": "2", "ps": n.get("name",""), "add": n["server"], "port": str(n["port"]), "id": n["uuid"], "aid": str(n.get("alterId",0)), "net": n.get("network","tcp"), "type": "none", "host": n.get("ws-opts",{}).get("headers",{}).get("Host",""), "path": n.get("ws-opts",{}).get("path",""), "tls": "tls" if n.get("tls") else ""}
        return "vmess://" + base64.b64encode(json.dumps(js).encode()).decode()
    elif t == "trojan":
        return f"trojan://{n['password']}@{n['server']}:{n['port']}"
    elif t == "vless":
        return f"vless://{n['uuid']}@{n['server']}:{n['port']}?security=tls"
    return ""

# （其余逻辑同上，导出批次时 embed 用 "\n".join(node_to_uri()) 代替 data:base64）

# ===================== 导出 YAML / Base64 / QR =====================
def save_yaml(path: str, proxies: List[Dict]):
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump({"proxies": proxies}, f, allow_unicode=True)

def save_base64(path: str, proxies: List[Dict]):
    uris = [node_to_uri(n) for n in proxies if node_to_uri(n)]
    with open(path, "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(uris).encode()).decode())

def batch_and_qr(name: str, proxies: List[Dict], border_color):
    batches = [proxies[i:i+BATCH_SIZE] for i in range(0, len(proxies), BATCH_SIZE)]
    batch_links = []
    for idx, batch in enumerate(batches, start=1):
        uris = "\n".join(node_to_uri(n) for n in batch if node_to_uri(n))
        qr_path = os.path.join(QRS_DIR, f"{name}_batch{idx}.png")
        save_qr_to(qr_path, uris, color=border_color)
        link = f"{RAW_BASE}/groups/{name}_batch{idx}.txt"
        with open(os.path.join(GROUPS_DIR, f"{name}_batch{idx}.txt"), "w", encoding="utf-8") as f:
            f.write(uris)
        batch_links.append((link, qr_path))
    return batch_links

def fastest_node_qrs(name: str, proxies: List[Dict], border_color):
    fastest = sorted(proxies, key=lambda x: x.get("delay", 99999))[:3]
    res = []
    for idx, n in enumerate(fastest, start=1):
        uri = node_to_uri(n)
        qr_path = os.path.join(QRS_DIR, f"{name}_fast{idx}.png")
        save_qr_to(qr_path, uri, color=border_color)
        res.append((uri, qr_path))
    return res

# ===================== 网页生成 =====================
def gen_index(stats, all_batches, top3):
    html = io.StringIO()
    html.write(f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>多协议代理订阅</title>
<style>
body{{font-family:Arial,sans-serif;background:#f4f4f4;color:#333;}}
.container{{width:90%;margin:auto;}}
h1{{text-align:center;}}
.qr{{display:inline-block;margin:10px;text-align:center;}}
img{{width:200px;height:200px;border:4px solid #ccc;border-radius:12px;}}
</style>
</head>
<body>
<div class="container">
<h1>多协议代理订阅</h1>
<p>更新时间: {stats['update']}</p>
<p>总节点: {stats['total']} | 可用: {stats['alive']} | 平均延迟: {stats['avg_delay']} ms</p>
<hr/>
""")
    for proto, batches in all_batches.items():
        html.write(f"<h2>{proto} 批次订阅</h2>")
        for link, qr in batches:
            html.write(f'<div class="qr"><img src="{os.path.relpath(qr,DOCS_DIR)}"><br><a href="{link}">{link}</a></div>')
    html.write("<hr/><h2>最快单节点</h2>")
    for proto, fastlist in top3.items():
        html.write(f"<h3>{proto}</h3>")
        for uri, qr in fastlist:
            html.write(f'<div class="qr"><img src="{os.path.relpath(qr,DOCS_DIR)}"><br>{uri}</div>')
    html.write("</div></body></html>")
    with open(os.path.join(DOCS_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(html.getvalue())

# ===================== 主程序 =====================
if __name__ == "__main__":
    print("开始抓取源...")
    all_nodes = collect_nodes()
    print(f"共抓取 {len(all_nodes)} 节点")
    print("开始 TCP 测速...")
    all_nodes = asyncio.run(test_all_tcp(all_nodes))
    if STRICT_CN_GOOGLE:
        print("进行 Google 验证...")
        all_nodes = [n for n in all_nodes if google_via_socks_http(n)]
    stats = {
        "update": now_str_beijing(),
        "total": len(all_nodes),
        "alive": len(all_nodes),
        "avg_delay": round(sum(n.get("delay",0) for n in all_nodes)/len(all_nodes),1) if all_nodes else 0
    }
    print(f"过滤后剩余 {len(all_nodes)} 节点")

    # 按协议分组
    grouped = {}
    for n in all_nodes:
        grouped.setdefault(n["type"], []).append(n)

    all_batches = {}
    top3 = {}
    color_map = {"ss": (52,104,255), "vmess": (255,87,51), "trojan": (51,200,51), "vless": (180,51,255), "socks5": (255,153,0), "socks4": (0,153,204), "http": (128,128,128)}

    for proto, plist in grouped.items():
        plist = sorted(plist, key=lambda x: x.get("delay", 99999))[:KEEP_TOP_PER_TYPE]
        batches = batch_and_qr(proto, plist, border_color=color_map.get(proto,(0,0,0)))
        all_batches[proto] = batches
        top3[proto] = fastest_node_qrs(proto, plist, border_color=(255,215,0))

    gen_index(stats, all_batches, top3)
    print("全部完成！")
