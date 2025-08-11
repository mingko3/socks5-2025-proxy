#!/usr/bin/env python3
# generate.py
# Multi-source multi-protocol fetch + TCP test + China-access verification (5s) + grouped subscriptions + QR + index.html
# 注意：
#  - 对于 socks/http 我们使用 requests+PySocks 做真实 HTTP 请求到 https://www.baidu.com 来验证大陆可用性。
#  - 对于 ss/vmess/trojan/vless 等协议，完整的 HTTP 透传验证需要协议客户端（v2ray/trojan-core/ss-local），本脚本只做 TCP 连接检测。
#    因此当 STRICT_CHINA_ONLY=True 时，这些协议会被排除（无法确认大陆 HTTP 可用性）。
#  - 若希望包含这些协议，请把 STRICT_CHINA_ONLY=False（但结果不一定是“大陆可用”）。

import os
import re
import json
import time
import base64
import yaml
import qrcode
import socket
import asyncio
import aiohttp
import requests
import concurrent.futures
from datetime import datetime
from urllib.parse import quote, unquote

# ----------------------- 配置 -----------------------
OUTPUT_DIR = "docs"
QR_DIR = os.path.join(OUTPUT_DIR, "qrs")
os.makedirs(QR_DIR, exist_ok=True)

# GitHub Pages base (请替换为你的 pages 地址，如果不同)
GITHUB_PAGES_BASE = "https://mingko3.github.io/socks5-2025-proxy"

# 抓源列表（可以自由扩展）
SOURCES = [
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt",

    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/Shadowsocks.txt",
    "https://raw.githubusercontent.com/freefq/free/master/shadowsocks",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/shadowsocks",

    "https://raw.githubusercontent.com/freefq/free/master/clash.yaml",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/clash/clash.yml",

    # 你可以继续添加其它稳定的公开源
]

# 超时与并发
FETCH_TIMEOUT = 15                 # 抓源超时
TCP_TIMEOUT = 2.0                  # TCP 连接测试超时 (秒)
CHINA_CHECK_TIMEOUT = 5.0          # 中国可用性检测（访问百度）超时 (秒)
MAX_TCP_CONCURRENCY = 200          # 并发 TCP 测试数
HTTP_VERIFY_WORKERS = 40           # requests 线程池大小 用于代理 http 验证

# 过滤策略
STRICT_CHINA_ONLY = True           # 如果 True：只保留被证实可以在中国大陆访问百度的节点（只适用于 socks/http）
MAX_TCP_DELAY_MS = 2000           # TCP 延迟阈值(ms)（过大可认为不可靠）

# 目标验证网址（中国大陆可访问）
CHINA_TEST_URL = "https://www.baidu.com/"

# ----------------------- 工具函数 -----------------------
def safe_b64decode(s: str) -> bytes:
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

def extract_ipports(text: str):
    return [f"{m.group(1)}:{m.group(2)}" for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})", text)]

def extract_proto_links(text: str):
    links = []
    for proto in ("vmess://","vless://","ss://","trojan://"):
        for m in re.finditer(rf"{proto}[A-Za-z0-9+/=\:\@\.\%\-\_\#\?\,\(\)]+", text):
            links.append(m.group(0).strip())
    return links

# ----------------------- 解析节点 -----------------------
def parse_ss(link: str):
    try:
        core = link.split("#",1)[0][5:]
        # some ss links are plain method:pass@host:port (not base64)
        try:
            decoded = safe_b64decode(core).decode()
        except Exception:
            decoded = core
        if "@" in decoded and ":" in decoded.split("@")[-1]:
            method_pass, hostport = decoded.rsplit("@",1)
            method, password = method_pass.split(":",1)
            host, port = hostport.split(":",1)
            return {"proto":"ss","server":host,"port":int(port),"cipher":method,"password":password,"raw":link}
    except Exception:
        pass
    return {"proto_link": link}

def parse_vmess(link: str):
    try:
        b64 = link[8:]
        conf_bytes = safe_b64decode(b64)
        conf = json.loads(conf_bytes.decode(errors="ignore"))
        server = conf.get("add") or conf.get("server") or conf.get("host")
        port = int(conf.get("port") or 0)
        return {"proto":"vmess","server":server,"port":port,"raw_conf":conf,"raw":link}
    except Exception:
        return {"proto_link": link}

def parse_vless(link: str):
    try:
        s = link[7:]
        # vless://uuid@host:port?...
        if "@" in s:
            userpart, rest = s.split("@",1)
            hostport = rest.split("/",1)[0].split("#",1)[0]
            host, port = hostport.split(":",1)
            return {"proto":"vless","server":host,"port":int(port),"uuid":userpart,"raw":link}
    except Exception:
        pass
    return {"proto_link": link}

def parse_trojan(link: str):
    try:
        s = link[9:]
        pwd, rest = s.split("@",1)
        hostport = rest.split("#",1)[0]
        host, port = hostport.split(":",1)
        return {"proto":"trojan","server":host,"port":int(port),"password":pwd,"raw":link}
    except Exception:
        return {"proto_link": link}

# 解析 socks/http like "socks5://1.2.3.4:1080" 或 "http://host:port"
def parse_simple_proxy(line: str):
    try:
        proto = None
        if line.startswith("socks5://") or line.startswith("socks4://") or line.startswith("http://") or line.startswith("https://"):
            if line.startswith("socks5://"):
                proto = "socks5"
                core = line[len("socks5://"):]
            elif line.startswith("socks4://"):
                proto = "socks4"
                core = line[len("socks4://"):]
            elif line.startswith("http://"):
                proto = "http"
                core = line[len("http://"):]
            elif line.startswith("https://"):
                proto = "http"
                core = line[len("https://"):]
            # remove optional auth and fragment
            if "@" in core:
                core = core.split("@",1)[1]
            if "/" in core:
                core = core.split("/",1)[0]
            # core like host:port
            if ":" in core:
                host, port = core.split(":",1)
                return {"proto": proto, "server": host, "port": int(port), "raw": line}
    except Exception:
        pass
    return None

# 统一把各种行解析成节点 dict (可能是 proto_link)
def parse_line_to_node(line: str):
    line = line.strip()
    if not line:
        return None
    if line.startswith("ss://"):
        return parse_ss(line)
    if line.startswith("vmess://"):
        return parse_vmess(line)
    if line.startswith("vless://"):
        return parse_vless(line)
    if line.startswith("trojan://"):
        return parse_trojan(line)
    if line.startswith(("socks5://","socks4://","http://","https://")):
        return parse_simple_proxy(line)
    # ip:port plain
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$", line)
    if m:
        return {"proto":"socks5","server":m.group(1),"port":int(m.group(2)),"raw":line}
    # maybe base64 blob (vmess only)
    if is_probable_base64(line) and len(line) > 80:
        # treat as vmess b64 blob
        return {"proto_link": "vmess://"+line}
    return None

# ----------------------- 抓源 -----------------------
async def fetch_text(session: aiohttp.ClientSession, url: str):
    try:
        async with session.get(url, timeout=FETCH_TIMEOUT) as resp:
            txt = await resp.text()
            return txt
    except Exception:
        return ""

async def fetch_all_sources(sources):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_text(session, u) for u in sources]
        return await asyncio.gather(*tasks, return_exceptions=True)

# ----------------------- 并发 TCP 测试 -----------------------
async def tcp_connect_latency(host: str, port: int, timeout: float = TCP_TIMEOUT):
    try:
        start = time.time()
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return int((time.time() - start) * 1000)
    except Exception:
        return None

async def test_nodes_tcp(nodes, max_workers=100):
    sem = asyncio.Semaphore(max_workers)
    results = []

    async def _test(n):
        async with sem:
            # if has proto_link, decode first
            if "proto_link" in n:
                # attempt to decode
                pl = n["proto_link"]
                decoded = parse_line_to_node(pl)  # will return dict or None
                if decoded:
                    n.update(decoded)
            srv = n.get("server")
            port = n.get("port")
            if not srv or not port:
                n["alive"] = False
                n["delay"] = None
            else:
                delay = await tcp_connect_latency(srv, int(port))
                n["alive"] = bool(delay is not None)
                n["delay"] = delay
            results.append(n)
    tasks = [asyncio.create_task(_test(n)) for n in nodes]
    for t in asyncio.as_completed(tasks):
        await t
    return results

# ----------------------- HTTP 验证（通过代理访问百度） -----------------------
def verify_proxy_http(node, test_url=CHINA_TEST_URL, timeout=CHINA_CHECK_TIMEOUT):
    """
    node: dict with proto (socks5/socks4/http), server, port
    returns True/False
    """
    proto = node.get("proto")
    server = node.get("server")
    port = node.get("port")
    if not proto or not server or not port:
        return False
    proxies = {}
    if proto == "socks5":
        proxies = {"http": f"socks5h://{server}:{port}", "https": f"socks5h://{server}:{port}"}
    elif proto == "socks4":
        proxies = {"http": f"socks4://{server}:{port}", "https": f"socks4://{server}:{port}"}
    elif proto == "http":
        proxies = {"http": f"http://{server}:{port}", "https": f"http://{server}:{port}"}
    else:
        return False
    try:
        r = requests.get(test_url, proxies=proxies, timeout=timeout, allow_redirects=True)
        if r.status_code >= 200 and r.status_code < 400:
            return True
    except Exception:
        return False
    return False

def batch_verify_http(nodes, workers=HTTP_VERIFY_WORKERS):
    verified = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(verify_proxy_http, n): n for n in nodes}
        for fut in concurrent.futures.as_completed(futs):
            n = futs[fut]
            try:
                ok = fut.result()
            except Exception:
                ok = False
            n["china_ok"] = bool(ok)
            verified.append(n)
    return verified

# ----------------------- 输出生成 -----------------------
def write_clash_yaml(nodes, out_path):
    proxies = []
    for n in nodes:
        proto = n.get("proto")
        name = n.get("name") or f"{proto}_{n.get('server')}_{n.get('port')}"
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
            conf = n.get("raw_conf", {})
            proxies.append({
                "name": name,
                "type": "vmess",
                "server": n.get("server"),
                "port": int(n.get("port") or 0),
                "uuid": n.get("raw_conf", {}).get("id", n.get("uuid","")),
                "alterId": int(conf.get("aid", 0) if isinstance(conf.get("aid",0), int) else 0),
                "cipher": "auto",
                "tls": bool(conf.get("tls", False))
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
        elif proto == "vless":
            proxies.append({
                "name": name,
                "type": "vless",
                "server": n.get("server"),
                "port": int(n.get("port")),
                "uuid": n.get("uuid",""),
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
    cfg = {
        "mixed-port": 0,
        "allow-lan": False,
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name":"AUTO","type":"url-test","url":"http://www.gstatic.com/generate_204","interval":300,"proxies":[p["name"] for p in proxies] + ["DIRECT"]}
        ],
        "rules":["MATCH,AUTO"]
    }
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, allow_unicode=True, default_flow_style=False)

def write_sub_files(nodes, out_dir=OUTPUT_DIR):
    # split by proto
    groups = {}
    for n in nodes:
        proto = n.get("proto", "other")
        groups.setdefault(proto, []).append(n)
    # write per-proto sub (raw lines where possible)
    for proto, lst in groups.items():
        lines = []
        for n in lst:
            if "raw" in n:
                lines.append(n["raw"])
            elif "proto_link" in n:
                lines.append(n["proto_link"])
            else:
                # fallback
                lines.append(f"{n.get('proto')}://{n.get('server')}:{n.get('port')}")
        p = os.path.join(out_dir, f"sub_{proto}")
        with open(p, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        # also create base64-encoded version
        try:
            b64 = base64.b64encode("\n".join(lines).encode()).decode()
            with open(os.path.join(out_dir, f"sub_{proto}_b64"), "w", encoding="utf-8") as bf:
                bf.write(b64)
        except Exception:
            pass
    # merged base64 sub (all)
    merged_lines = []
    for proto in groups:
        p = os.path.join(out_dir, f"sub_{proto}")
        if os.path.exists(p):
            merged_lines.extend([l for l in open(p, encoding="utf-8").read().splitlines() if l.strip()])
    with open(os.path.join(out_dir, "sub"), "w", encoding="utf-8") as f:
        f.write("\n".join(merged_lines))

def generate_qr_images(nodes, out_dir=OUTPUT_DIR):
    # main subscription QR
    main_url = f"{GITHUB_PAGES_BASE}/sub"
    try:
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=8, border=4)
        qr.add_data(main_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(os.path.join(out_dir, "qrcode_sub.png"))
    except Exception:
        pass
    # per-proto QR for sub files
    protos = set([n.get("proto","other") for n in nodes])
    for proto in protos:
        url = f"{GITHUB_PAGES_BASE}/sub_{proto}"
        path = os.path.join(out_dir, "qrs", f"qrcode_{proto}.png")
        try:
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=6, border=4)
            qr.add_data(url)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(path)
        except Exception:
            pass

def generate_index_html(nodes, out_dir=OUTPUT_DIR):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    total = len(nodes)
    alive = sum(1 for n in nodes if n.get("alive"))
    delays = [n.get("delay") for n in nodes if n.get("delay") is not None]
    avg_delay = int(sum(delays)/len(delays)) if delays else -1

    # group counts
    groups = {}
    for n in nodes:
        proto = n.get("proto","other")
        groups.setdefault(proto, []).append(n)

    html = []
    html.append("<!doctype html><html lang='zh'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>")
    html.append("<title>订阅中心</title>")
    html.append("<style>body{font-family:Arial,Helvetica,sans-serif;background:#f7f9fb;padding:18px} .card{background:#fff;padding:12px;border-radius:8px;margin-bottom:12px;box-shadow:0 2px 6px rgba(0,0,0,0.06)} .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px} .node{border:1px solid #eee;padding:8px;border-radius:6px;background:#fff;text-align:center} .node img{max-width:160px} .stat{display:inline-block;padding:6px 10px;background:#eef6ff;color:#0366d6;border-radius:12px;margin-right:8px}</style>")
    html.append("</head><body>")
    html.append(f"<div class='card'><h2>订阅中心</h2><p class='stat'>总节点: {total}</p><p class='stat'>可用: {alive}</p><p class='stat'>平均延迟(ms): {avg_delay if avg_delay>=0 else 'N/A'}</p><p>更新时间: {now}</p></div>")

    # main sub and proxy
    html.append("<div class='card'><h3>主要订阅</h3>")
    html.append(f"<p>合并订阅(base64): <a href='sub'>{GITHUB_PAGES_BASE}/sub</a></p>")
    html.append(f"<p>Clash YAML: <a href='proxy.yaml'>{GITHUB_PAGES_BASE}/proxy.yaml</a></p>")
    html.append(f"<p><img src='qrcode_sub.png' width='200'></p>")
    html.append("</div>")

    # per-proto cards
    html.append("<div class='card'><h3>按协议分组订阅</h3><div class='grid'>")
    for proto, lst in groups.items():
        pfile = f"sub_{proto}"
        qrpath = f"qrs/qrcode_{proto}.png"
        html.append("<div class='node'>")
        html.append(f"<h4>{proto.upper()}</h4>")
        html.append(f"<p>数量: {len(lst)}</p>")
        html.append(f"<p><a href='{pfile}'>{GITHUB_PAGES_BASE}/{pfile}</a></p>")
        html.append(f"<img src='{qrpath}' width='160'/>")
        html.append("</div>")
    html.append("</div></div>")

    # short list of top nodes
    html.append("<div class='card'><h3>节点（延迟排序，前200）</h3><div class='grid'>")
    shown = 0
    for n in sorted(nodes, key=lambda x: (0 if x.get("alive") else 1, x.get("delay") if x.get("delay") else 99999))[:200]:
        name = n.get("name") or f"{n.get('proto')}_{n.get('server')}_{n.get('port')}"
        proto = n.get("proto")
        srv = n.get("server")
        port = n.get("port")
        alive_flag = n.get("alive", False)
        delay = n.get("delay") if n.get("delay") is not None else "N/A"
        china_ok = n.get("china_ok", False)
        qr = n.get("qr","")
        html.append("<div class='node'>")
        html.append(f"<strong>{name}</strong><br><small>{proto}</small><br>")
        if qr:
            html.append(f"<img src='{qr}' style='width:140px'><br>")
        html.append(f"<div style='font-size:13px;color:#666'>地址: {srv}:{port}<br>延迟: {delay} ms<br>在线: {'是' if alive_flag else '否'}<br>中国可用: {'是' if china_ok else '否'}</div>")
        html.append("</div>")
    html.append("</div></div>")

    html.append("</body></html>")
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write("\n".join(html))

# ----------------------- 主流程 -----------------------
async def main():
    print("开始抓取源 ...")
    texts = await fetch_all_sources(SOURCES)
    raw_entries = []
    for t in texts:
        if not t:
            continue
        # extract protocol links and ipports
        raw_entries.extend(extract_proto_links(t))
        raw_entries.extend(extract_ipports(t))
        # if file looks like base64 blob, decode and extract
        if is_probable_base64(t):
            try:
                dec = safe_b64decode(t).decode(errors="ignore")
                raw_entries.extend(extract_proto_links(dec))
                raw_entries.extend(extract_ipports(dec))
                raw_entries.extend([l for l in dec.splitlines() if l.strip()])
            except Exception:
                pass
        # also include obvious lines
        for line in t.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith(("ss://","vmess://","vless://","trojan://","socks5://","socks4://","http://","https://")) or re.match(r"^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$", line):
                raw_entries.append(line)

    print(f"原始条目数量 (可能含重复): {len(raw_entries)}")
    # parse to nodes
    nodes = []
    seen = set()
    for line in raw_entries:
        n = parse_line_to_node(line)
        if not n:
            continue
        # normalize raw string for dedupe
        raw = n.get("raw") or n.get("proto_link") or f"{n.get('proto')}://{n.get('server')}:{n.get('port')}"
        if raw in seen:
            continue
        seen.add(raw)
        n["raw"] = raw
        # set proto if decoded returned proto field
        if "proto" not in n:
            # try to infer from proto_link
            if "proto_link" in n:
                if n["proto_link"].startswith("vmess://"):
                    n["proto"] = "vmess"
                elif n["proto_link"].startswith("ss://"):
                    n["proto"] = "ss"
                elif n["proto_link"].startswith("trojan://"):
                    n["proto"] = "trojan"
                elif n["proto_link"].startswith("vless://"):
                    n["proto"] = "vless"
                else:
                    n["proto"] = "other"
        nodes.append(n)

    print(f"解析到节点 (去重后): {len(nodes)}")

    # TCP 测试
    print("开始 TCP 并发测试 ...")
    tested = await test_nodes_tcp(nodes, max_workers=min(MAX_TCP_CONCURRENCY, max(10, len(nodes)//2)))
    print(f"TCP 测试完成，总条目: {len(tested)}")

    # HTTP 验证 for socks/http
    socks_http_nodes = [n for n in tested if n.get("proto") in ("socks5","socks4","http")]
    print(f"需要 HTTP(百度)验证的 socks/http 节点: {len(socks_http_nodes)}")
    verified = []
    if socks_http_nodes:
        verified = batch_verify_http(socks_http_nodes, workers=HTTP_VERIFY_WORKERS)
    # attach china_ok flags to tested list
    for n in tested:
        if n.get("proto") in ("socks5","socks4","http"):
            # find by server+port
            match = next((v for v in verified if v.get("server")==n.get("server") and v.get("port")==n.get("port")), None)
            n["china_ok"] = bool(match and match.get("china_ok"))
        else:
            # cannot verify protocol without client; mark False (unless STRICT_CHINA_ONLY==False)
            n["china_ok"] = False

    # decide final kept nodes
    if STRICT_CHINA_ONLY:
        final_nodes = [n for n in tested if n.get("china_ok") is True and n.get("alive")]
    else:
        # keep those alive and within delay threshold
        final_nodes = [n for n in tested if n.get("alive") and (n.get("delay") is None or n.get("delay") <= MAX_TCP_DELAY_MS)]

    print(f"最终保留节点: {len(final_nodes)} (STRICT_CHINA_ONLY={STRICT_CHINA_ONLY})")

    # prepare sub links if missing
    for n in final_nodes:
        if "sub_link" in n:
            continue
        if n.get("proto") in ("socks5","socks4","http"):
            n["sub_link"] = f"{n['proto']}://{n['server']}:{n['port']}#{quote(n.get('server',''))}"
        elif n.get("proto") in ("ss","vmess","trojan","vless") and n.get("raw"):
            n["sub_link"] = n["raw"]
        else:
            if "proto_link" in n:
                n["sub_link"] = n["proto_link"]
            else:
                n["sub_link"] = f"{n.get('proto')}://{n.get('server')}:{n.get('port')}"

    # generate output files
    print("生成订阅文件与二维码 ...")
    # main clash yaml
    write_clash_yaml(final_nodes, os.path.join(OUTPUT_DIR, "proxy.yaml"))
    # sub files per proto + merged
    write_sub_files(final_nodes, out_dir=OUTPUT_DIR)
    # generate per-node QR images
    for n in final_nodes:
        try:
            s = n.get("sub_link")
            if not s:
                continue
            fname = f"{n.get('proto')}_{n.get('server','unknown').replace('.','_')}_{n.get('port')}.png"
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=6, border=4)
            qr.add_data(s)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(os.path.join(QR_DIR, fname))
            n["qr"] = f"qrs/{fname}"
        except Exception:
            n["qr"] = ""
    # generate group qrs and main sub qr
    generate_qr_images(final_nodes, out_dir=OUTPUT_DIR)
    # generate index.html
    generate_index_html(final_nodes, out_dir=OUTPUT_DIR)

    print("全部完成，输出在 docs/ 目录。")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print("运行异常：", e)
