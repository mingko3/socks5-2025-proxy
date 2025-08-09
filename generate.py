#!/usr/bin/env python3
# generate.py
# 功能：抓取多个免费订阅源 -> 解析 SS/VMess/Trojan/SOCKS -> 去重/并发测速/可用性过滤 -> 生成 Clash YAML、订阅文件、二维码、网页（含搜索/过滤/复制）

import os
import re
import json
import time
import socket
import base64
import yaml
import html
import threading
import concurrent.futures
from pathlib import Path
from datetime import datetime
from urllib.parse import quote
import requests
import qrcode

# -------------- CONFIG --------------
OUT = Path("docs")
QRS = OUT / "qrs"
OUT.mkdir(parents=True, exist_ok=True)
QRS.mkdir(parents=True, exist_ok=True)

# GitHub Pages 显示地址（替换成你的）
GITHUB_PAGES_BASE = "https://mingko3.github.io/socks5-2025-proxy"
MAIN_SUB_URL = f"{GITHUB_PAGES_BASE}/sub"
MAIN_PROXY_YAML = f"{GITHUB_PAGES_BASE}/proxy.yaml"

# 并发线程数（测速时）
THREAD_WORKERS = 80

# TCP 连接超时（s）
TCP_TIMEOUT = 1.5

# 源列表（我已加入你关心/常见的源）
# 你可以随时在此列表添加更多 "raw" 或 "list" 链接
SOURCES = [
    # 用户/社区常见
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/Shadowsocks.txt",
    "https://raw.githubusercontent.com/freefq/free/master/shadowsocks",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/shadowsocks",
    "https://raw.githubusercontent.com/freefq/free/master/clash.yaml",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/clash/clash.yml",

    # roosterkid / openproxylist raw files
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",

    # proxyscrape API (public endpoints, may change)
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=5000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=5000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",

    # openproxy.space lists (if available)
    "https://openproxy.space/list?type=all",
    "https://openproxy.space/list?type=v2ray",
]

# 是否对 IP 做地理查找（默认 True，但免费接口有限速）
DO_GEO_LOOKUP = True

# ---------------- utilities ----------------
def safe_b64decode(s: str) -> bytes:
    """宽松 base64 解码，自动补 '='；如果失败抛异常"""
    s = s.strip().replace("\n", "")
    s = s.replace("-", "+").replace("_", "/")
    padding = (-len(s)) % 4
    if padding:
        s += "=" * padding
    return base64.b64decode(s)

def tcp_connect_latency(host: str, port: int, timeout: float = TCP_TIMEOUT):
    """尝试与 host:port 建立 TCP 连接，返回延迟 ms 或 None"""
    try:
        start = time.time()
        with socket.create_connection((host, int(port)), timeout=timeout):
            return int((time.time() - start) * 1000)
    except Exception:
        return None

def make_strict_qrcode(data: str, filename: str, version=None, box_size=8, border=4):
    """生成兼容性好的二维码（高纠错、明确边框），保存为 png"""
    qr = qrcode.QRCode(
        version=version,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)

def ip_to_country(ip: str) -> str:
    """尽可能查国家（免费服务，有速率限制），失败返回 '未知'"""
    if not DO_GEO_LOOKUP:
        return "未知"
    try:
        # ip-api.com 非商业免费接口，带速率限制，但不需要 key
        r = requests.get(f"http://ip-api.com/line/{ip}?fields=country", timeout=6)
        if r.status_code == 200:
            c = r.text.strip()
            if c:
                return c
    except Exception:
        pass
    return "未知"

# ---------------- parsers ----------------
def parse_ss(line: str):
    """解析 ss 链接，返回 dict 或 None"""
    try:
        # remove fragment
        if "#" in line:
            line = line.split("#", 1)[0]
        if line.startswith("ss://"):
            payload = line[5:]
        else:
            payload = line

        # if payload contains '@' after decode then it's method:pass@host:port
        # try base64 decode
        try:
            decoded = safe_b64decode(payload).decode(errors="ignore")
        except Exception:
            decoded = payload  # maybe not base64

        if "@" in decoded and ":" in decoded.split("@")[-1]:
            method_pass, hostport = decoded.rsplit("@", 1)
            method, password = method_pass.split(":", 1)
            host, port = hostport.split(":", 1)
            return {"proto": "ss", "server": host, "port": int(port), "cipher": method, "password": password}
        # else could be "method:pass" + base64(host:port) pattern. ignore for now.
    except Exception:
        pass
    return None

def parse_vmess(line: str):
    """解析 vmess://base64 -> dict"""
    try:
        payload = line[len("vmess://"):] if line.startswith("vmess://") else line
        b = safe_b64decode(payload)
        conf = json.loads(b.decode(errors="ignore"))
        server = conf.get("add") or conf.get("server") or conf.get("host")
        port = int(conf.get("port") or 0)
        return {"proto": "vmess", "server": server, "port": port, "uuid": conf.get("id"), "raw": conf}
    except Exception:
        return None

def parse_trojan(line: str):
    try:
        s = line[len("trojan://"):] if line.startswith("trojan://") else line
        pwd, rest = s.split("@", 1)
        hostport = rest.split("#", 1)[0]
        host, port = hostport.split(":", 1)
        return {"proto": "trojan", "server": host, "port": int(port), "password": pwd}
    except Exception:
        return None

# ---------------- fetch sources ----------------
def fetch_source(url: str, timeout=15):
    """抓取单个源并尝试解析成行列表"""
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            return []
        text = r.text.strip()
        if not text:
            return []
        # If it's a base64 blob (looks like no scheme and mostly base64 chars), try decode
        first_chunk = text[:200].strip()
        if ("ss://" not in text and "vmess://" not in text and "trojan://" not in text) and re.fullmatch(r"[A-Za-z0-9+/=\s]+", first_chunk):
            try:
                decoded = safe_b64decode(text).decode(errors="ignore")
                lines = [l.strip() for l in decoded.splitlines() if l.strip()]
                return lines
            except Exception:
                # fallback to raw lines
                return [l.strip() for l in text.splitlines() if l.strip()]
        else:
            return [l.strip() for l in text.splitlines() if l.strip()]
    except Exception:
        return []

# ---------------- main flow ----------------
def main():
    print("Start fetch sources:", datetime.utcnow().isoformat())
    raw_lines = []

    # fetch all sources sequentially but parsing is fast; we do network in threads to speed up
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(fetch_source, src): src for src in SOURCES}
        for fut in concurrent.futures.as_completed(futures):
            src = futures[fut]
            try:
                lines = fut.result()
                if lines:
                    print(f"Fetched {len(lines)} lines from {src}")
                    raw_lines.extend(lines)
                else:
                    print(f"No lines from {src}")
            except Exception as e:
                print("Fetch error", src, e)

    print("Total raw lines collected:", len(raw_lines))

    # extract protocol lines and ip:port lines
    raw_nodes = []
    for line in raw_lines:
        if not line:
            continue
        # common protocol markers
        if any(line.startswith(p) for p in ("ss://","vmess://","trojan://","socks5://","socks4://")):
            raw_nodes.append(line)
            continue
        # lines from roosterkid often contain ip:port at start - capture those
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})", line)
        if m:
            ip = m.group(1); port = m.group(2)
            # treat as socks5 by default (we'll label socks5)
            raw_nodes.append(f"socks5://{ip}:{port}")
            continue
        # sometimes vmess base64 is alone, detect long base64 line and prefix vmess://
        if re.fullmatch(r"[A-Za-z0-9+/=]+", line) and len(line) > 100:
            # guess vmess base64
            raw_nodes.append("vmess://" + line)
            continue
        # else ignore unknown lines
    print("Raw nodes after normalization:", len(raw_nodes))

    # parse raw_nodes into structured nodes with dedupe
    nodes = []
    seen = set()
    for raw in raw_nodes:
        n = None
        if raw.startswith("ss://"):
            n = parse_ss(raw)
            if n:
                key = f"ss|{n['server']}|{n['port']}"
                if key in seen: continue
                seen.add(key)
                entry = {"proto":"ss","server":n["server"],"port":n["port"],"cipher":n.get("cipher",""),"password":n.get("password","")}
                nodes.append(entry)
        elif raw.startswith("vmess://"):
            n = parse_vmess(raw)
            if n and n.get("server"):
                key = f"vmess|{n['server']}|{n['port']}"
                if key in seen: continue
                seen.add(key)
                entry = {"proto":"vmess","server":n["server"],"port":n["port"],"uuid":n.get("uuid",""),"raw":n.get("raw",{})}
                nodes.append(entry)
        elif raw.startswith("trojan://"):
            n = parse_trojan(raw)
            if n:
                key = f"trojan|{n['server']}|{n['port']}"
                if key in seen: continue
                seen.add(key)
                entry = {"proto":"trojan","server":n["server"],"port":n["port"],"password":n.get("password","")}
                nodes.append(entry)
        elif raw.startswith(("socks5://","socks4://")):
            try:
                part = raw.split("://",1)[1]
                host, port = part.split(":",1)
                proto = "socks5" if raw.startswith("socks5://") else "socks4"
                key = f"{proto}|{host}|{port}"
                if key in seen: continue
                seen.add(key)
                entry = {"proto":proto,"server":host,"port":int(port)}
                nodes.append(entry)
            except:
                pass
    print("Structured nodes (deduped):", len(nodes))

    # concurrent TCP test + geo
    def check_node(n, idx):
        server = n.get("server")
        port = n.get("port")
        latency = None
        ok = False
        try:
            latency = tcp_connect_latency(server, port)
            ok = latency is not None
        except Exception:
            latency = None
            ok = False
        n["latency_ms"] = latency if latency is not None else -1
        n["ok"] = ok
        # country lookup lightly (non-blocking if heavy)
        n["country"] = ip_to_country(server) if DO_GEO_LOOKUP else "未知"
        n["id"] = f"{n['proto']}_{idx}"
        return n

    print("Start concurrent testing of nodes...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREAD_WORKERS) as ex:
        futures = [ex.submit(check_node, n, i+1) for i,n in enumerate(nodes)]
        nodes = [f.result() for f in concurrent.futures.as_completed(futures)]

    print("Testing finished. Available nodes:", sum(1 for n in nodes if n["ok"]))

    # sort nodes: ok first then by latency asc
    nodes.sort(key=lambda x: (0 if x.get("ok") else 1, x.get("latency_ms") if x.get("latency_ms")>=0 else 99999))

    # build clash proxies list
    clash_proxies = []
    for n in nodes:
        if n["proto"] == "ss":
            name = f"SS_{n['server']}_{n['port']}"
            clash_proxies.append({"name": name, "type": "ss", "server": n["server"], "port": n["port"], "cipher": n.get("cipher",""), "password": n.get("password",""), "udp": True})
            n["name"] = name
        elif n["proto"] == "vmess":
            name = f"VMess_{n['server']}_{n['port']}"
            clash_proxies.append({"name": name, "type": "vmess", "server": n["server"], "port": n["port"], "uuid": n.get("uuid",""), "alterId": 0, "cipher": "auto", "tls": bool(n.get("raw",{}).get("tls", False))})
            n["name"] = name
        elif n["proto"] == "trojan":
            name = f"Trojan_{n['server']}_{n['port']}"
            clash_proxies.append({"name": name, "type": "trojan", "server": n["server"], "port": n["port"], "password": n.get("password",""), "udp": True})
            n["name"] = name
        elif n["proto"] in ("socks5","socks4"):
            name = f"{n['proto'].upper()}_{n['server']}_{n['port']}"
            clash_proxies.append({"name": name, "type": n["proto"], "server": n["server"], "port": n["port"], "udp": False})
            n["name"] = name

    clash_conf = {
        "mixed-port": 0,
        "allow-lan": False,
        "log-level": "info",
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": [p["name"] for p in clash_proxies] + ["DIRECT"]}
        ],
        "rules": ["MATCH,🚀 自动选择"]
    }

    # write proxy.yaml
    with open(OUT / "proxy.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash_conf, f, allow_unicode=True, default_flow_style=False)

    # build subscription lines (plain per-node links) and protocol files
    lines = []
    for n in nodes:
        if n["proto"] == "ss":
            raw = f"{n.get('cipher','')}:{n.get('password','')}@{n['server']}:{n['port']}"
            enc = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
            s = f"ss://{enc}#{quote(n.get('name',''))}"
            lines.append(s)
            n["sub_link"] = s
        elif n["proto"] == "vmess":
            conf = n.get("raw", {})
            conf2 = {"v":"2","ps":n.get("name", f"VMESS_{n['server']}"), "add":n["server"], "port":str(n["port"]), "id":n.get("uuid",""), "aid":"0", "net":conf.get("net","tcp"), "type":"none", "host":conf.get("host",""), "path":conf.get("path",""), "tls":conf.get("tls","")}
            s = "vmess://" + base64.b64encode(json.dumps(conf2, separators=(",",":")).encode()).decode()
            lines.append(s)
            n["sub_link"] = s
        elif n["proto"] == "trojan":
            s = f"trojan://{n.get('password','')}@{n['server']}:{n['port']}#{quote(n.get('name',''))}"
            lines.append(s)
            n["sub_link"] = s
        elif n["proto"] in ("socks5","socks4"):
            s = f"{n['proto']}://{n['server']}:{n['port']}#{quote(n.get('name',''))}"
            lines.append(s)
            n["sub_link"] = s

    # write sub and per-protocol files
    with open(OUT / "sub", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    with open(OUT / "ss.txt", "w", encoding="utf-8") as f:
        f.write("\n".join([l for l in lines if l.startswith("ss://")]))
    with open(OUT / "vmess.txt", "w", encoding="utf-8") as f:
        f.write("\n".join([l for l in lines if l.startswith("vmess://")]))
    with open(OUT / "trojan.txt", "w", encoding="utf-8") as f:
        f.write("\n".join([l for l in lines if l.startswith("trojan://")]))

    # generate main QR (strict)
    try:
        make_strict_qrcode(MAIN_SUB_URL, str(OUT / "qrcode.png"))
    except Exception as e:
        print("Main QR generation error:", e)

    # generate per-node QR, attach path
    for n in nodes:
        try:
            s = n.get("sub_link")
            fname = f"{n['proto']}_{n['server'].replace('.','_')}_{n['port']}.png"
            path = QRS / fname
            if s:
                make_strict_qrcode(s, str(path))
                n["qr"] = f"qrs/{fname}"
            else:
                n["qr"] = ""
        except Exception as e:
            n["qr"] = ""
            print("QR error for", n.get("server"), e)

    # generate index.html (with simple search/filter JS and copy buttons)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_lines = []
    html_lines.append("<!doctype html>")
    html_lines.append("<html lang='zh'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>")
    html_lines.append("<title>订阅中心</title>")
    html_lines.append("<style>")
    html_lines.append("body{font-family:Arial,Helvetica,sans-serif;background:#f7f9fb;color:#222;padding:18px}")
    html_lines.append(".card{background:#fff;border-radius:8px;padding:14px;box-shadow:0 2px 8px rgba(0,0,0,0.06);margin-bottom:14px}")
    html_lines.append(".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;margin-top:12px}")
    html_lines.append(".node{border:1px solid #eee;padding:8px;border-radius:6px;background:#fff;text-align:center}")
    html_lines.append(".node img{max-width:160px}")
    html_lines.append(".controls{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}")
    html_lines.append(".copy{cursor:pointer;color:#0366d6;text-decoration:underline}")
    html_lines.append(".stat{display:inline-block;padding:4px 8px;background:#f0f4ff;color:#0366d6;border-radius:12px;margin-right:6px}")
    html_lines.append("</style></head><body>")
    html_lines.append("<div class='card'><h2>订阅中心</h2>")
    html_lines.append(f"<p>Base64 订阅：<a href='{MAIN_SUB_URL}' target='_blank'>{MAIN_SUB_URL}</a></p>")
    html_lines.append(f"<p>Clash YAML：<a href='{MAIN_PROXY_YAML}' target='_blank'>{MAIN_PROXY_YAML}</a></p>")
    html_lines.append(f"<div><img src='qrcode.png' style='width:220px'></div>")
    html_lines.append(f"<p class='stat'>节点总数: {len(nodes)}</p> <p class='stat'>可用: {sum(1 for n in nodes if n['ok'])}</p> <p class='stat'>不可用: {sum(1 for n in nodes if not n['ok'])}</p>")
    html_lines.append(f"<p style='color:#666'>最后更新：{now}</p></div>")

    # controls
    html_lines.append("<div class='card'><div class='controls'><label>搜索：<input id='q' placeholder='搜索 IP/国家/协议' oninput='filter()' /></label>")
    html_lines.append("<label>协议：<select id='proto' onchange='filter()'><option value='all'>全部</option><option value='ss'>SS</option><option value='vmess'>VMess</option><option value='trojan'>Trojan</option><option value='socks5'>Socks5</option><option value='socks4'>Socks4</option></select></label>")
    html_lines.append("<label>可用：<select id='ok' onchange='filter()'><option value='all'>全部</option><option value='1'>仅可用</option><option value='0'>仅不可用</option></select></label>")
    html_lines.append("</div><div id='list' class='grid'>")

    # each node card
    for n in nodes:
        safe_name = html.escape(n.get("name", f"{n.get('server')}:{n.get('port')}"))
        server = html.escape(n.get("server",""))
        port = n.get("port")
        country = html.escape(n.get("country","未知"))
        latency = n.get("latency_ms", -1)
        ok = "1" if n.get("ok") else "0"
        qr = n.get("qr","")
        sub_link = html.escape(n.get("sub_link",""))
        proto = n.get("proto","")
        html_lines.append(f"<div class='node' data-proto='{proto}' data-ok='{ok}' data-text='{server} {country} {proto}'>")
        html_lines.append(f"<strong>{safe_name}</strong><br>")
        if qr:
            html_lines.append(f"<img src='{qr}' alt='qr'><br>")
        html_lines.append(f"<div style='font-size:13px;color:#666'>地址: {server}:{port}<br>国家: {country} <br> 延迟: {latency if latency>=0 else '不可用'} ms</div>")
        html_lines.append(f"<div style='margin-top:6px'><span class='copy' onclick=\"copyText('{sub_link}')\">复制链接</span> &nbsp; ")
        if qr:
            html_lines.append(f"<a href='{qr}' download>下载二维码</a>")
        html_lines.append("</div></div>")

    html_lines.append("</div></div>")

    # scripts
    html_lines.append("""
<script>
function copyText(t){navigator.clipboard.writeText(t).then(()=>alert('已复制'),()=>alert('复制失败'))}
function filter(){
  var q = document.getElementById('q').value.toLowerCase();
  var proto = document.getElementById('proto').value;
  var ok = document.getElementById('ok').value;
  document.querySelectorAll('#list .node').forEach(function(el){
    var text = el.getAttribute('data-text').toLowerCase();
    var p = el.getAttribute('data-proto');
    var o = el.getAttribute('data-ok');
    var show = true;
    if(q && text.indexOf(q)===-1) show=false;
    if(proto!=='all' && p!==proto) show=false;
    if(ok!=='all' && o!==ok) show=false;
    el.style.display = show ? 'block' : 'none';
  });
}
</script>
""")

    html_lines.append("</body></html>")

    with open(OUT / "index.html", "w", encoding="utf-8") as f:
        f.write("\n".join(html_lines))

    print("Generation complete. Files written to docs/: proxy.yaml, sub, ss.txt, vmess.txt, trojan.txt, qrcode.png, qrs/*.png, index.html")

if __name__ == "__main__":
    main()
