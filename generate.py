#!/usr/bin/env python3
# generate.py
# 修复 HTML 源解析 + 并发 TCP 测试 + 可用性过滤 -> 生成订阅与网页

import os
import re
import json
import time
import socket
import base64
import yaml
import asyncio
import qrcode
from pathlib import Path
from datetime import datetime
from urllib.parse import quote
import aiohttp

# ----------------- 配置区 -----------------
OUT_DIR = Path("docs")
QRS_DIR = OUT_DIR / "qrs"
OUT_DIR.mkdir(parents=True, exist_ok=True)
QRS_DIR.mkdir(parents=True, exist_ok=True)

# GitHub Pages base (用于二维码/页面上的链接)
GITHUB_PAGES_BASE = "https://mingko3.github.io/socks5-2025-proxy"
MAIN_SUB_URL = f"{GITHUB_PAGES_BASE}/sub"
MAIN_PROXY_YAML = f"{GITHUB_PAGES_BASE}/proxy.yaml"

# 并发/超时设置
MAX_CONCURRENCY = 200           # 并发 TCP 连接数（根据 Actions 限制调节）
TCP_TIMEOUT = 3.0               # TCP 连接超时(s)
FETCH_TIMEOUT = 15              # 抓源超时(s)
KEEP_ONLY_ALIVE = True          # 是否只保留能连通的节点
MAX_ACCEPTABLE_DELAY_MS = 2000  # 如果需要可保留阈值（ms），超过视为不理想但仍可保留若 ok True

# 你之前使用和希望纳入的多个源（包含 openproxylist 的 raw 链接等）
SOURCES = [
    # roosterkid openproxylist raw files
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",

    # community aggregated sources you used before
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/Shadowsocks.txt",
    "https://raw.githubusercontent.com/freefq/free/master/shadowsocks",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/shadowsocks",
    "https://raw.githubusercontent.com/freefq/free/master/clash.yaml",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/clash/clash.yml",

    # openproxylist HTML pages (we will fetch and parse HTML too)
    "https://openproxylist.com/proxy/",
    "https://openproxylist.com/v2ray/",

    # proxyscrape public endpoints (may change over time)
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=5000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=5000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
]

# ----------------- 工具函数 -----------------
def safe_b64decode(s: str) -> bytes:
    """宽松 base64 解码（自动补齐）"""
    s = s.strip().replace("\n", "")
    s = s.replace("-", "+").replace("_", "/")
    padding = (-len(s)) % 4
    if padding:
        s += "=" * padding
    return base64.b64decode(s)

def is_probable_base64(s: str) -> bool:
    s = s.strip()
    if len(s) < 16:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/=\s]+", s[:200]) is not None

def extract_ip_port_from_text(text: str):
    """从任意文本中抽取 ip:port 列表（例如 HTML）"""
    results = []
    for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})", text):
        ip = m.group(1)
        port = m.group(2)
        # 基本校验端口范围
        try:
            p = int(port)
            if 1 <= p <= 65535:
                results.append(f"{ip}:{p}")
        except:
            continue
    return results

def extract_protocol_links(text: str):
    """从文本中抽取 vmess:// ss:// trojan:// 链接"""
    links = []
    for proto in ("vmess://", "ss://", "trojan://"):
        for m in re.finditer(rf"{proto}[A-Za-z0-9+/=:_\-\.\%#@]+", text):
            links.append(m.group(0).strip())
    return links

async def fetch_text(session: aiohttp.ClientSession, url: str):
    """抓取单个 URL 的文本内容（HTML 或 raw）"""
    try:
        async with session.get(url, timeout=FETCH_TIMEOUT) as resp:
            txt = await resp.text()
            return txt
    except Exception as e:
        # print("fetch error", url, e)
        return ""

# ----------------- 解析与收集 -----------------
def parse_raw_lines_to_nodes(lines):
    """
    lines: iterable of strings (each line may be ip:port or protocol link)
    返回 nodes: list of dict: {proto, server, port, raw, extra...}
    proto: ss/vmess/trojan/socks5/socks4/http
    """
    nodes = []
    for line in lines:
        if not line or not isinstance(line, str):
            continue
        line = line.strip()
        # skip comments or short tokens
        if len(line) < 6:
            continue
        # protocol links
        if line.startswith("ss://") or line.startswith("vmess://") or line.startswith("trojan://"):
            nodes.append({"proto_link": line})
            continue
        # ip:port pattern
        m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$", line)
        if m:
            ip = m.group(1); port = m.group(2)
            # heuristics: treat as socks5 by default for raw ip:port lists
            nodes.append({"proto": "socks5", "server": ip, "port": int(port), "raw": line})
            continue
        # some lines could be html fragments like "<td>1.2.3.4:1080</td>"
        ipports = extract_ip_port_from_text(line)
        if ipports:
            for ipport in ipports:
                ip, port = ipport.split(":")
                nodes.append({"proto": "socks5", "server": ip, "port": int(port), "raw": ipport})
            continue
        # long base64 -> maybe vmess base64 only
        if is_probable_base64(line) and len(line) > 120:
            # assume vmess base64 blob
            nodes.append({"proto_link": "vmess://" + line})
            continue
        # else ignore
    return nodes

def decode_proto_link(link):
    """
    对于 ss:// vmess:// trojan:// 的 link，尝试解析出结构化字段并返回节点 dict
    返回形如： {"proto":"ss","server":"x","port":p,"raw":link,...}
    如果解析失败，返回 {"proto_link": link}（保留原始链接）
    """
    try:
        if link.startswith("ss://"):
            # 移除 fragment 后解码
            core = link.split("#",1)[0][5:]
            try:
                decoded = safe_b64decode(core).decode(errors="ignore")
            except Exception:
                # 有些 ss:// 是 method:pass@host:port 直接形式
                decoded = core
            if "@" in decoded and ":" in decoded.split("@")[-1]:
                method_pass, hostport = decoded.rsplit("@",1)
                method, password = method_pass.split(":",1)
                host, port = hostport.split(":",1)
                return {"proto":"ss","server":host,"port":int(port),"cipher":method,"password":password,"raw":link}
            # fallback -> keep as raw link
            return {"proto_link": link}
        elif link.startswith("vmess://"):
            b64 = link[8:]
            try:
                conf_bytes = safe_b64decode(b64)
                conf = json.loads(conf_bytes.decode(errors="ignore"))
                server = conf.get("add") or conf.get("server") or conf.get("host")
                port = int(conf.get("port") or 0)
                uuid = conf.get("id") or conf.get("uuid")
                return {"proto":"vmess","server":server,"port":port,"uuid":uuid,"raw":link,"raw_conf":conf}
            except Exception:
                # maybe link is vmess://jsonEncoded (rare)
                return {"proto_link": link}
        elif link.startswith("trojan://"):
            s = link[9:]
            # format: password@host:port#name
            try:
                pwd, rest = s.split("@",1)
                hostport = rest.split("#",1)[0]
                host, port = hostport.split(":",1)
                return {"proto":"trojan","server":host,"port":int(port),"password":pwd,"raw":link}
            except Exception:
                return {"proto_link": link}
    except Exception:
        return {"proto_link": link}

# ----------------- 并发 TCP 测试 -----------------
async def tcp_connect_latency(host: str, port: int, timeout: float = TCP_TIMEOUT):
    """异步 TCP 连接测试，返回延迟 ms 或 None"""
    try:
        start = time.time()
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        # close immediately
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return int((time.time() - start) * 1000)
    except Exception:
        return None

async def test_nodes_concurrent(nodes, max_workers=200):
    """并发测试节点连通性，nodes 是 list of dict，返回 nodes（带 alive/delay 字段）"""
    sem = asyncio.Semaphore(max_workers)
    results = []

    async def _test(n, idx):
        async with sem:
            try:
                proto = n.get("proto")
                # if node is proto_link (raw vmess/ss/trojan string), try decode first
                if "proto_link" in n:
                    dec = decode_proto_link(n["proto_link"])
                    # merge parsed fields into n
                    n.update(dec)
                # need server and port
                srv = n.get("server")
                port = n.get("port")
                if not srv or not port:
                    n["alive"] = False
                    n["delay"] = None
                    results.append(n)
                    return
                # only test TCP connect to server:port
                delay = await tcp_connect_latency(srv, int(port), timeout=TCP_TIMEOUT)
                if delay is not None:
                    n["alive"] = True
                    n["delay"] = delay
                else:
                    n["alive"] = False
                    n["delay"] = None
            except Exception:
                n["alive"] = False
                n["delay"] = None
            results.append(n)

    tasks = [asyncio.create_task(_test(n, i)) for i, n in enumerate(nodes)]
    await asyncio.gather(*tasks)
    return results

# ----------------- 输出生成 -----------------
def generate_clash_yaml(nodes, out_path: Path):
    proxies = []
    for n in nodes:
        proto = n.get("proto")
        name = n.get("name") or f"{proto.upper()}_{n.get('server')}_{n.get('port')}"
        if proto == "ss":
            proxies.append({
                "name": name,
                "type": "ss",
                "server": n.get("server"),
                "port": int(n.get("port")),
                "cipher": n.get("cipher",""),
                "password": n.get("password",""),
                "udp": True
            })
        elif proto == "vmess":
            proxies.append({
                "name": name,
                "type": "vmess",
                "server": n.get("server"),
                "port": int(n.get("port")),
                "uuid": n.get("uuid",""),
                "alterId": 0,
                "cipher": "auto",
                "tls": bool(n.get("raw_conf",{}).get("tls", False))
            })
        elif proto == "trojan":
            proxies.append({
                "name": name,
                "type": "trojan",
                "server": n.get("server"),
                "port": int(n.get("port")),
                "password": n.get("password",""),
                "udp": True
            })
        elif proto in ("socks5","socks4","http"):
            proxies.append({
                "name": name,
                "type": proto,
                "server": n.get("server"),
                "port": int(n.get("port")),
                "udp": False
            })
    clash_conf = {
        "mixed-port": 0,
        "allow-lan": False,
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "AUTO", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": [p["name"] for p in proxies] + ["DIRECT"]}
        ],
        "rules": ["MATCH,AUTO"]
    }
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.dump(clash_conf, f, allow_unicode=True, default_flow_style=False)

def generate_sub_files(nodes, out_dir: Path):
    lines = []
    ss_lines = []
    vmess_lines = []
    trojan_lines = []
    for n in nodes:
        if n.get("proto") == "ss":
            raw = f"{n.get('cipher','')}:{n.get('password','')}@{n.get('server')}:{n.get('port')}"
            enc = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
            s = f"ss://{enc}#{quote(n.get('name',''))}"
            lines.append(s); ss_lines.append(s); n["sub_link"] = s
        elif n.get("proto") == "vmess":
            conf = n.get("raw_conf") or {}
            conf2 = {"v":"2","ps": n.get("name") or f"VMESS_{n.get('server')}_{n.get('port')}", "add": n.get("server"), "port": str(n.get("port")), "id": n.get("uuid",""), "aid":"0", "net": conf.get("net","tcp"), "type":"none", "host": conf.get("host",""), "path": conf.get("path",""), "tls": conf.get("tls","")}
            enc = base64.b64encode(json.dumps(conf2, separators=(",",":")).encode()).decode()
            s = f"vmess://{enc}"
            lines.append(s); vmess_lines.append(s); n["sub_link"] = s
        elif n.get("proto") == "trojan":
            s = f"trojan://{n.get('password','')}@{n.get('server')}:{n.get('port')}#{quote(n.get('name',''))}"
            lines.append(s); trojan_lines.append(s); n["sub_link"] = s
        elif n.get("proto") in ("socks5","socks4","http"):
            s = f"{n.get('proto')}://{n.get('server')}:{n.get('port')}#{quote(n.get('name',''))}"
            lines.append(s); n["sub_link"] = s
        else:
            # fallback: if original proto_link exists, keep
            if "proto_link" in n:
                lines.append(n["proto_link"]); n["sub_link"] = n["proto_link"]
    # write files
    with open(out_dir / "sub", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    with open(out_dir / "ss.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(ss_lines))
    with open(out_dir / "vmess.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(vmess_lines))
    with open(out_dir / "trojan.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(trojan_lines))

def generate_qr_images(nodes, out_dir: Path):
    # main subscription QR
    try:
        qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=8, border=4)
        qr.add_data(MAIN_SUB_URL)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(out_dir / "qrcode.png")
    except Exception as e:
        print("Main QR error:", e)
    # per-node QR
    for n in nodes:
        s = n.get("sub_link")
        if not s:
            continue
        name = f"{n.get('proto')}_{n.get('server','unknown').replace('.','_')}_{n.get('port')}.png"
        try:
            qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=6, border=4)
            qr.add_data(s)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(QRS_DIR / name)
            n["qr"] = f"qrs/{name}"
        except Exception as e:
            n["qr"] = ""
            # print("node qr error", e)

def generate_index_html(nodes, out_dir: Path):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    total = len(nodes)
    alive = sum(1 for n in nodes if n.get("alive"))
    avg_delay = int(sum(n["delay"] for n in nodes if n.get("delay") and n.get("alive") ) / max(1, alive)) if alive else -1
    html = []
    html.append("<!doctype html><html lang='zh'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>")
    html.append("<title>订阅中心</title><style>body{font-family:Arial,Helvetica,sans-serif;background:#f7f9fb;color:#222;padding:18px} .card{background:#fff;padding:12px;border-radius:8px;margin-bottom:12px;box-shadow:0 2px 6px rgba(0,0,0,0.06)} .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px} .node{border:1px solid #eee;padding:8px;border-radius:6px;background:#fff;text-align:center} .node img{max-width:160px} .stat{display:inline-block;padding:6px 10px;background:#eef6ff;color:#0366d6;border-radius:12px;margin-right:8px}</style></head><body>")
    html.append(f"<div class='card'><h2>订阅中心</h2><p>Base64订阅：<a href='{MAIN_SUB_URL}' target='_blank'>{MAIN_SUB_URL}</a></p><p>Clash YAML：<a href='{MAIN_PROXY_YAML}' target='_blank'>{MAIN_PROXY_YAML}</a></p><div><img src='qrcode.png' style='width:220px'></div><p class='stat'>总数: {total}</p><p class='stat'>可用: {alive}</p><p class='stat'>平均延迟(ms): {avg_delay if avg_delay>=0 else 'N/A'}</p><p style='color:#666'>最后更新: {now}</p></div>")
    # controls
    html.append("<div class='card'><div style='margin-bottom:8px'><input id='q' placeholder='搜索 IP/协议' oninput='filter()' style='padding:6px;width:60%'><select id='proto' onchange='filter()' style='padding:6px'><option value='all'>全部协议</option><option value='ss'>SS</option><option value='vmess'>VMess</option><option value='trojan'>Trojan</option><option value='socks5'>Socks5</option><option value='socks4'>Socks4</option></select></div><div id='list' class='grid'>")
    # node cards
    for n in nodes:
        name = n.get("name") or f"{n.get('proto','')}_{n.get('server')}_{n.get('port')}"
        server = n.get("server","")
        port = n.get("port","")
        proto = n.get("proto","")
        alive_flag = n.get("alive", False)
        delay = n.get("delay") if n.get("delay") is not None else "N/A"
        qr = n.get("qr","")
        sub_link = n.get("sub_link","")
        html.append(f"<div class='node' data-proto='{proto}' data-text='{server} {proto}'>")
        html.append(f"<strong>{name}</strong><br>")
        if qr:
            html.append(f"<img src='{qr}' alt='qr'><br>")
        html.append(f"<div style='font-size:13px;color:#666'>地址: {server}:{port}<br>延迟: {delay} ms<br>状态: {'在线' if alive_flag else '离线'}</div>")
        if sub_link:
            html.append(f"<div style='margin-top:6px'><button onclick=\"navigator.clipboard.writeText('{sub_link}')\">复制</button> <a href='{qr}' download>下载二维码</a></div>")
        html.append("</div>")
    html.append("</div></div>")
    # js filter
    html.append("""<script>
function filter(){
  var q=document.getElementById('q').value.toLowerCase();
  var proto=document.getElementById('proto').value;
  document.querySelectorAll('#list .node').forEach(function(el){
    var text=el.getAttribute('data-text').toLowerCase();
    var p=el.getAttribute('data-proto');
    var show=true;
    if(q && text.indexOf(q)===-1) show=false;
    if(proto!=='all' && p!==proto) show=false;
    el.style.display= show ? 'block' : 'none';
  });
}
</script>""")
    html.append("</body></html>")
    with open(out_dir / "index.html", "w", encoding="utf-8") as f:
        f.write("\n".join(html))

# ----------------- 主流程 -----------------
async def main():
    print("Start fetch sources:", datetime.utcnow().isoformat())
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_text(session, url) for url in SOURCES]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    # 收集原始 lines
    raw_lines = []
    for i, text in enumerate(responses):
        if not text:
            continue
        # If content contains protocol links, extract them
        proto_links = extract_protocol_links(text)
        raw_lines.extend(proto_links)
        # Extract ip:port occurrences from text (HTML or plain)
        ipports = extract_ip_port_from_text(text)
        raw_lines.extend(ipports)
        # If the file looks like base64 blob (subscription), try decode into lines
        if is_probable_base64(text):
            try:
                decoded = safe_b64decode(text).decode(errors="ignore")
                # decoded may contain links
                raw_lines.extend(extract_protocol_links(decoded))
                raw_lines.extend(extract_ip_port_from_text(decoded))
                # also split by lines
                raw_lines.extend([l.strip() for l in decoded.splitlines() if l.strip()])
            except Exception:
                pass
        # also split original text lines and include those that look like protocol or ipport
        for line in text.splitlines():
            line = line.strip()
            if not line: continue
            if line.startswith(("ss://","vmess://","trojan://")) or re.match(r"^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$", line):
                raw_lines.append(line)

    print(f"Collected raw entries: {len(raw_lines)} (may contain duplicates)")

    # parse to nodes (dedupe)
    parsed_nodes = parse_raw_lines_to_nodes(raw_lines)

    # If proto_link items included, parse them to structured nodes where possible
    # parse_raw_lines_to_nodes will put 'proto_link' for links; we will keep them as-is and decode in test step
    print(f"Parsed initial nodes (rough): {len(parsed_nodes)}")

    # run concurrent TCP tests (this also decodes proto_link into server/port where possible)
    tested = await test_nodes_concurrent(parsed_nodes, max_workers=min(MAX_CONCURRENCY, max(10, len(parsed_nodes)//2)))
    print("Testing finished. total tested:", len(tested))

    # filter: keep alive ones (or keep all but mark)
    if KEEP_ONLY_ALIVE:
        kept = [n for n in tested if n.get("alive")]
    else:
        kept = tested

    print(f"Kept nodes after filter: {len(kept)} (alive only={KEEP_ONLY_ALIVE})")

    # sort by alive then delay
    kept.sort(key=lambda x: (0 if x.get("alive") else 1, x.get("delay") if x.get("delay") is not None else 99999))

    # generate outputs
    generate_clash_yaml(kept, OUT_DIR / "proxy.yaml")
    generate_sub_files(kept, OUT_DIR)
    generate_qr_images(kept, OUT_DIR)
    generate_index_html(kept, OUT_DIR)

    print("All done. Outputs in docs/: proxy.yaml, sub, ss.txt, vmess.txt, trojan.txt, qrcode.png, qrs/*.png, index.html")
    print(f"Stats: total parsed {len(parsed_nodes)}, tested {len(tested)}, kept {len(kept)}")

if __name__ == "__main__":
    asyncio.run(main())
