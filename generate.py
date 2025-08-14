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
import textwrap
import datetime
import traceback
from typing import List, Dict, Tuple
import contextlib

import requests
import yaml
import qrcode
from PIL import Image
import socks  # PySocks

# ===================== 用户可调参数 =====================
TIMEOUT_TCP = 2.0           # TCP 测速超时(秒)
CONCURRENCY = 400           # 并发数量
SOCKS_GOOGLE_TIMEOUT = 4.0  # 通过 SOCKS 代理连 Google 的超时(秒)
KEEP_TOP_PER_TYPE = 2000    # 每种协议最多保留数量
STRICT_CN_GOOGLE = True     # 是否生成 proxy_cn_google.yaml
MAX_NODES_PER_QR = 20       # 每个二维码最多节点数（批次拆分）

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

# ===================== 路径设置 =====================
REPO = os.environ.get("GITHUB_REPOSITORY", "mingko3/socks5-2025-proxy")
OWNER, REPO_NAME = REPO.split("/")
SITE_BASE = f"https://{OWNER}.github.io/{REPO_NAME}"
RAW_BASE  = f"https://raw.githubusercontent.com/{OWNER}/{REPO_NAME}/main/docs"

DOCS_DIR = "docs"
os.makedirs(DOCS_DIR, exist_ok=True)

# ===================== 工具函数 =====================
def b64pad(s: str) -> str:
    pad = len(s) % 4
    return s + ("=" * (4 - pad)) if pad else s

def safe_int(v, default=None):
    try:
        return int(v)
    except:
        return default

def now_str():
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)\
        .astimezone(datetime.timezone(datetime.timedelta(hours=8)))\
        .strftime("%Y-%m-%d %H:%M:%S %Z%z")

def strict_qr(url: str, out_path: str):
    img = qrcode.make(url)
    img.save(out_path)

def fetch_text(url: str, timeout=12) -> str:
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            return r.text
    except:
        pass
    return ""

# ===================== 协议正则 =====================
SS_RE = re.compile(r"(ss://[A-Za-z0-9+/=_\-:%#@.]+)", re.IGNORECASE)
VMESS_RE = re.compile(r"(vmess://[A-Za-z0-9+/=_\-:;{}\",.]+)", re.IGNORECASE)
TROJAN_RE = re.compile(r"(trojan://[A-Za-z0-9+/=_\-:%#@.]+)", re.IGNORECASE)
VLESS_RE = re.compile(r"(vless://[A-Za-z0-9+/=_\-:%#@.?&=]+)", re.IGNORECASE)
IPPORT_RE = re.compile(r"\b((\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b")

# ===================== 协议解析 =====================
def parse_ss(link: str):
    try:
        if not link.startswith("ss://"): return None
        raw = link[5:].split("#")[0]
        raw = b64pad(raw)
        decoded = base64.urlsafe_b64decode(raw).decode("utf-8", "ignore")
        if "@" not in decoded or ":" not in decoded: return None
        auth, hostport = decoded.split("@", 1)
        method, password = auth.split(":", 1)
        host, port = hostport.split(":", 1)
        port_i = safe_int(port)
        if not port_i: return None
        return {"name": f"SS_{host}_{port_i}", "type": "ss", "server": host, "port": port_i, "cipher": method, "password": password, "udp": True}
    except:
        return None

def parse_vmess(link: str):
    try:
        if not link.startswith("vmess://"): return None
        data = b64pad(link[8:])
        js = json.loads(base64.b64decode(data).decode("utf-8", "ignore"))
        host = js.get("add") or js.get("host")
        port_i = safe_int(js.get("port"))
        if not host or not port_i: return None
        return {"name": js.get("ps") or f"VMess_{host}_{port_i}", "type": "vmess", "server": host, "port": port_i,
                "uuid": js.get("id"), "alterId": safe_int(js.get("aid"), 0), "cipher": "auto",
                "tls": bool(js.get("tls")) or js.get("tls") == "tls", "network": js.get("net") or "tcp",
                "ws-opts": {"path": js.get("path", "/"), "headers": {"Host": js.get("host", "")}}}
    except:
        return None

def parse_trojan(link: str):
    try:
        if not link.startswith("trojan://"): return None
        rest = link[9:]
        password, addr = rest.split("@", 1)
        addr = addr.split("#")[0]
        host, port = addr.split(":")
        port_i = safe_int(port)
        if not port_i: return None
        return {"name": f"Trojan_{host}_{port_i}", "type": "trojan", "server": host, "port": port_i, "password": password, "udp": True}
    except:
        return None

def parse_vless(link: str):
    try:
        if not link.startswith("vless://"): return None
        temp = link[8:]
        if "@" not in temp or ":" not in temp: return None
        uuid, addr = temp.split("@", 1)
        host_port = addr.split("?", 1)[0]
        host, port = host_port.split(":")
        port_i = safe_int(port)
        if not port_i: return None
        return {"name": f"VLESS_{host}_{port_i}", "type": "vless", "server": host, "port": port_i, "uuid": uuid, "tls": True, "flow": "", "udp": True}
    except:
        return None

# ===================== 抓取与解析 =====================
def extract_proto_links(text: str) -> List[str]:
    out = []
    out += SS_RE.findall(text)
    out += VMESS_RE.findall(text)
    out += TROJAN_RE.findall(text)
    out += VLESS_RE.findall(text)
    return list(dict.fromkeys(out))

def extract_ipports(text: str) -> List[Tuple[str, int]]:
    ips = []
    for m in IPPORT_RE.finditer(text):
        host = m.group(1)
        port = safe_int(m.group(3))
        if port:
            ips.append((host, port))
    return list(dict.fromkeys(ips))

def collect_nodes() -> List[Dict]:
    nodes = []
    seen = set()
    for url in SOURCES:
        print(f"[Fetch] {url}")
        text = fetch_text(url)
        if not text: continue
        if "://" not in text and re.search(r"^[A-Za-z0-9+/=\n\r]+$", text) and len(text) > 64:
            try: text = base64.b64decode(b64pad(text)).decode("utf-8", "ignore")
            except: pass
        links = extract_proto_links(text)
        for lk in links:
            p = None
            if lk.startswith("ss://"): p = parse_ss(lk)
            elif lk.startswith("vmess://"): p = parse_vmess(lk)
            elif lk.startswith("trojan://"): p = parse_trojan(lk)
            elif lk.startswith("vless://"): p = parse_vless(lk)
            if p and (p["type"], p["server"], p["port"]) not in seen:
                seen.add((p["type"], p["server"], p["port"]))
                nodes.append(p)
        if "proxies:" in text or url.endswith((".yaml", ".yml")):
            try:
                data = yaml.safe_load(text)
                if isinstance(data, dict) and "proxies" in data:
                    for p in data["proxies"]:
                        t = p.get("type"); host = p.get("server"); port = safe_int(p.get("port"))
                        if t and host and port and (t, host, port) not in seen:
                            seen.add((t, host, port))
                            nodes.append(p)
            except: pass
        for host, port in extract_ipports(text):
            for proto in ("socks5", "socks4", "http"):
                if (proto, host, port) not in seen:
                    seen.add((proto, host, port))
                    nodes.append({"name": f"{proto.upper()}_{host}_{port}", "type": proto, "server": host, "port": port, "udp": False})
    print(f"[Collect] 初步收集：{len(nodes)}")
    return nodes

# ===================== TCP 测速 =====================
async def tcp_ping(host: str, port: int, timeout: float = TIMEOUT_TCP) -> float:
    start = time.perf_counter()
    try:
        fut = asyncio.open_connection(host=host, port=int(port))
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        with contextlib.suppress(Exception): await writer.wait_closed()
        return (time.perf_counter() - start) * 1000.0
    except:
        return -1.0

async def test_all_tcp(nodes: List[Dict]) -> List[Dict]:
    sem = asyncio.Semaphore(CONCURRENCY)
    out = []
    async def test_one(n):
        async with sem:
            d = await tcp_ping(n["server"], n["port"])
            if d > 0:
                n["delay"] = round(d, 1)
                out.append(n)
    await asyncio.gather(*(test_one(n) for n in nodes))
    return out

# ===================== Google 验证 =====================
def google_via_socks_http(n: Dict) -> bool:
    host, port = n["server"], int(n["port"])
    try:
        if n["type"].lower() in ("socks5", "socks4"):
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5 if n["type"]=="socks5" else socks.SOCKS4, host, port)
            s.settimeout(SOCKS_GOOGLE_TIMEOUT)
            s.connect(("www.google.com", 80))
            s.close()
            return True
        elif n["type"].lower() == "http":
            s = socket.create_connection(("www.google.com", 80), timeout=SOCKS_GOOGLE_TIMEOUT)
            s.close()
            return True
    except:
        return False
    return False

# ===================== YAML 生成 =====================
def to_clash_proxies(nodes: List[Dict]) -> List[Dict]:
    return nodes

def write_yaml(path: str, proxies: List[Dict]):
    data = {"proxies": proxies}
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)

def write_base64_sub(path: str, yaml_bytes: bytes):
    b64 = base64.b64encode(yaml_bytes).decode("utf-8")
    with open(path, "w", encoding="utf-8") as f:
        f.write(b64)

# ===================== HTML 生成 =====================
def build_index_html(summary: Dict, links_html: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>订阅聚合 - {REPO}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial;line-height:1.5;margin:0;background:#0b1220;color:#e6edf3}}
a{{color:#6ea8fe;text-decoration:none}}
.container{{max-width:980px;margin:0 auto;padding:24px}}
.card{{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:16px;margin:12px 0}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}}
.qr img{{width:160px;height:160px}}
.badge{{background:#1d4ed8;color:#fff;border-radius:999px;padding:2px 10px;font-size:12px;margin-left:6px}}
</style>
</head>
<body>
<div class="container">
  <h1>订阅聚合</h1>
  <p>更新时间：{summary.get('updated')}</p>
  <div>初步收集：{summary.get('collected')} | TCP可用：{summary.get('tcp_ok')} | Google可用：{summary.get('google_ok')} | 平均延迟(ms)：{summary.get('avg_delay')}</div>
  {links_html}
</div>
</body>
</html>"""

# ===================== 主流程 =====================
def main():
    nodes = collect_nodes()
    collected = len(nodes)
    loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
    tested = loop.run_until_complete(test_all_tcp(nodes))
    by_type = {}
    for n in tested:
        by_type.setdefault(n["type"].lower(), []).append(n)
    for t in by_type:
        by_type[t] = sorted(by_type[t], key=lambda x: x.get("delay", 999999))[:KEEP_TOP_PER_TYPE]
    tcp_ok_nodes = [x for lst in by_type.values() for x in lst]
    avg_ms = round(sum(n["delay"] for n in tcp_ok_nodes)/len(tcp_ok_nodes), 1) if tcp_ok_nodes else 0
    links_html = ""

    # 保存批次函数
    def save_group(name, lst):
        nonlocal links_html
        if not lst: return
        total = len(lst)
        batches = [lst[i:i+MAX_NODES_PER_QR] for i in range(0, total, MAX_NODES_PER_QR)]
        links_html += f"<div class='card'><h3>{name}（共{total}节点，{len(batches)}批）</h3><div class='grid'>"
        for idx, batch in enumerate(batches, 1):
            fname = f"{name}_part{idx}.yaml"
            path = os.path.join(DOCS_DIR, fname)
            write_yaml(path, to_clash_proxies(batch))
            url = f"{SITE_BASE}/{fname}"
            qrfile = os.path.join(DOCS_DIR, f"qrcode_{name}_part{idx}.png")
            strict_qr(url, qrfile)
            links_html += f"<div><p>批次{idx}</p><div class='qr'><img src='{SITE_BASE}/qrcode_{name}_part{idx}.png'/></div><a href='{url}' target='_blank'>YAML</a></div>"
        links_html += "</div></div>"

    # 按协议分组批次保存
    for proto in ["ss", "vmess", "trojan", "vless", "socks4", "socks5", "http"]:
        save_group(proto, by_type.get(proto, []))

    # 主订阅
    write_yaml(os.path.join(DOCS_DIR, "proxy.yaml"), tcp_ok_nodes)
    with open(os.path.join(DOCS_DIR, "proxy.yaml"), "rb") as f:
        write_base64_sub(os.path.join(DOCS_DIR, "sub"), f.read())
    strict_qr(f"{SITE_BASE}/sub", os.path.join(DOCS_DIR, "qrcode_main.png"))

    # Google 验证订阅
    google_ok = []
    if STRICT_CN_GOOGLE:
        for n in by_type.get("socks4", []) + by_type.get("socks5", []) + by_type.get("http", []):
            if google_via_socks_http(n): google_ok.append(n)
        write_yaml(os.path.join(DOCS_DIR, "proxy_cn_google.yaml"), google_ok)
        strict_qr(f"{SITE_BASE}/proxy_cn_google.yaml", os.path.join(DOCS_DIR, "qrcode_google.png"))

    # 生成 HTML
    summary = {"updated": now_str(), "collected": collected, "tcp_ok": len(tcp_ok_nodes),
               "google_ok": len(google_ok), "avg_delay": avg_ms}
    html = build_index_html(summary, links_html)
    with open(os.path.join(DOCS_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)

if __name__ == "__main__":
    main()
