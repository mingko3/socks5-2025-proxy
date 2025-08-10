#!/usr/bin/env python3
# generate.py
# 功能：
#  - 抓取多个源（raw/text/html/base64）
#  - 解析 ss/vmess/trojan/vless/socks4/socks5/http/ip:port
#  - 并发 TCP 测试 (asyncio) -> 过滤掉无法连通的端口
#  - 对 HTTP/SOCKS4/SOCKS5 做真实 HTTP 请求代理验证 (线程池同步 requests + socks support)
#  - 按协议分组生成单独订阅文件和二维码 + 合并订阅 + Clash YAML + 网页
#
# 注意：
#  - 对于 SS/VMess/Trojan/VLESS 等需要专用握手/加密协议的节点，本脚本仅做 TCP 连接检查（不能做完整协议验证）。
#  - 若要对 VMess/Trojan/VLESS 做完整可用性检测，请使用 v2ray/trojan-core 等工具进行真实代理测试（可扩展）。

import os
import re
import json
import time
import base64
import socket
import yaml
import qrcode
import asyncio
import concurrent.futures
from pathlib import Path
from datetime import datetime
from urllib.parse import quote
import aiohttp
import requests

# -------------------- CONFIG --------------------
OUT = Path("docs")
QRS = OUT / "qrs"
OUT.mkdir(parents=True, exist_ok=True)
QRS.mkdir(parents=True, exist_ok=True)

# GitHub Pages base (请改成你的真实 Pages 地址)
GITHUB_PAGES_BASE = "https://mingko3.github.io/socks5-2025-proxy"
MAIN_SUB = f"{GITHUB_PAGES_BASE}/sub"
MAIN_PROXY_YAML = f"{GITHUB_PAGES_BASE}/proxy.yaml"

# 抓源列表（保持你之前的源并可继续添加）
SOURCES = [
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/Shadowsocks.txt",
    "https://raw.githubusercontent.com/freefq/free/master/shadowsocks",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/shadowsocks",
    "https://raw.githubusercontent.com/freefq/free/master/clash.yaml",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/clash/clash.yml",
    "https://openproxylist.com/proxy/",
    "https://openproxylist.com/v2ray/",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=5000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=5000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
]

# 并发与超时设置（可按需调）
FETCH_TIMEOUT = 15      # fetch 源超时
TCP_TIMEOUT = 3.0       # TCP 连接超时
MAX_TCP_CONCURRENCY = 200
HTTP_VERIFY_WORKERS = 60  # 用来做 requests 验证的线程池大小
HTTP_VERIFY_TIMEOUT = 6   # 验证请求超时(s)
VERIFY_TEST_URL = "http://www.gstatic.com/generate_204"  # 用于通过代理访问检测

# 是否只保留通过最终验证的节点 (对 socks/http 会做真实代理测试；对 ss/vmess/trojan/vless 仅使用 TCP test)
KEEP_ONLY_VERIFIED = True

# 可接受延迟阈值(ms)（可调整，过高的延迟会降低实际可用性）
MAX_ACCEPTABLE_DELAY_MS = 2000

# -------------------- utils --------------------
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

def extract_protocol_links(text: str):
    links = []
    for proto in ("vmess://","vless://","ss://","trojan://"):
        for m in re.finditer(rf"{proto}[A-Za-z0-9+/=\:\@\.\%\-\_\#\?]+", text):
            links.append(m.group(0).strip())
    return links

# -------------------- fetch sources --------------------
async def fetch(session: aiohttp.ClientSession, url: str):
    try:
        async with session.get(url, timeout=FETCH_TIMEOUT) as r:
            return await r.text()
    except Exception as e:
        # print("fetch err", url, e)
        return ""

async def fetch_all_sources(sources):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, s) for s in sources]
        return await asyncio.gather(*tasks, return_exceptions=True)

# -------------------- parsing --------------------
def parse_raw_lines_to_nodes(lines):
    nodes = []
    seen = set()
    for line in lines:
        if not line or not isinstance(line, str):
            continue
        line = line.strip()
        if not line:
            continue
        # protocol link
        if line.startswith(("ss://","vmess://","vless://","trojan://")):
            # keep as proto_link and decode later
            if line in seen: 
                continue
            seen.add(line)
            nodes.append({"proto_link": line})
            continue
        # ip:port exact
        m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$", line)
        if m:
            ip, port = m.group(1), int(m.group(2))
            key = f"socks5|{ip}|{port}"
            if key in seen: continue
            seen.add(key)
            nodes.append({"proto":"socks5","server":ip,"port":port,"raw":f"{ip}:{port}"})
            continue
        # generic extract ip:port fragments
        for ipport in extract_ipports(line):
            ip, port = ipport.split(":")
            key = f"socks5|{ip}|{port}"
            if key in seen: continue
            seen.add(key)
            nodes.append({"proto":"socks5","server":ip,"port":int(port),"raw":ipport})
    return nodes

def decode_proto_link_basic(link):
    # Return dict like proto, server, port, raw, name, etc. If cannot, return {"proto_link":link}
    try:
        if link.startswith("ss://"):
            core = link.split("#",1)[0][5:]
            try:
                dec = safe_b64decode(core).decode(errors="ignore")
            except Exception:
                dec = core
            if "@" in dec and ":" in dec.split("@")[-1]:
                method_pass, hostport = dec.rsplit("@",1)
                method, password = method_pass.split(":",1)
                host, port = hostport.split(":",1)
                return {"proto":"ss","server":host,"port":int(port),"cipher":method,"password":password,"raw":link}
            # fallback
            return {"proto_link":link}
        if link.startswith("vmess://"):
            b64 = link[8:]
            try:
                conf = json.loads(safe_b64decode(b64).decode(errors="ignore"))
                server = conf.get("add") or conf.get("server") or conf.get("host")
                port = int(conf.get("port") or 0)
                return {"proto":"vmess","server":server,"port":port,"uuid":conf.get("id"),"raw_conf":conf,"raw":link}
            except Exception:
                return {"proto_link":link}
        if link.startswith("vless://"):
            # vless://uuid@host:port?...
            s = link[7:]
            try:
                userpart, rest = s.split("@",1)
                hostport = rest.split("/",1)[0].split("#",1)[0]
                host, port = hostport.split(":",1)
                return {"proto":"vless","server":host,"port":int(port),"uuid":userpart,"raw":link}
            except Exception:
                return {"proto_link":link}
        if link.startswith("trojan://"):
            s = link[9:]
            try:
                pwd, rest = s.split("@",1)
                hostport = rest.split("#",1)[0]
                host, port = hostport.split(":",1)
                return {"proto":"trojan","server":host,"port":int(port),"password":pwd,"raw":link}
            except Exception:
                return {"proto_link":link}
    except Exception:
        return {"proto_link":link}

# -------------------- TCP test (async) --------------------
async def tcp_connect_latency(host, port, timeout=TCP_TIMEOUT):
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

async def test_tcp_all(nodes, max_workers=MAX_TCP_CONCURRENCY):
    sem = asyncio.Semaphore(max_workers)
    results = []
    async def worker(n):
        async with sem:
            # if proto_link exists, try decode to get server/port
            if "proto_link" in n:
                parsed = decode_proto_link_basic(n["proto_link"])
                n.update(parsed)
            srv = n.get("server")
            port = n.get("port")
            if not srv or not port:
                n["alive"] = False
                n["delay"] = None
            else:
                delay = await tcp_connect_latency(srv, int(port))
                n["alive"] = True if delay is not None else False
                n["delay"] = delay
            return n
    tasks = [asyncio.create_task(worker(n)) for n in nodes]
    for t in asyncio.as_completed(tasks):
        res = await t
        results.append(res)
    return results

# -------------------- HTTP/SOCKS proxy verification (real HTTP request) ----
# This part uses requests + socks support (pysocks). It runs in a ThreadPoolExecutor.
def verify_proxy_http(node, test_url=VERIFY_TEST_URL, timeout=HTTP_VERIFY_TIMEOUT):
    """
    For proto in socks5/socks4/http/https:
      attempt a real HTTP GET through the proxy to test_url
    Returns True if HTTP status 204/200 returned within timeout, False otherwise
    """
    proto = node.get("proto")
    server = node.get("server")
    port = node.get("port")
    if not server or not port:
        return False
    proxies = {}
    scheme = "http"
    if proto == "socks5":
        proxy_url = f"socks5h://{server}:{port}"
        proxies = {"http": proxy_url, "https": proxy_url}
    elif proto == "socks4":
        proxy_url = f"socks4://{server}:{port}"
        proxies = {"http": proxy_url, "https": proxy_url}
    elif proto in ("http","https"):
        proxy_url = f"http://{server}:{port}"
        proxies = {"http": proxy_url, "https": proxy_url}
    else:
        return False
    try:
        r = requests.get(test_url, proxies=proxies, timeout=timeout, allow_redirects=False)
        if r.status_code in (200, 204):
            return True
        # some proxies respond 302 -> treat 200-ish
        if 200 <= r.status_code < 400:
            return True
    except Exception:
        return False
    return False

def batch_verify_http_nodes(nodes, workers=HTTP_VERIFY_WORKERS):
    verified = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(verify_proxy_http, n): n for n in nodes}
        for fut in concurrent.futures.as_completed(futures):
            n = futures[fut]
            try:
                ok = fut.result()
            except Exception:
                ok = False
            n["http_verified"] = bool(ok)
            verified.append(n)
    return verified

# -------------------- outputs --------------------
def write_group_files(nodes, out_dir=OUT):
    groups = {
        "socks5": [],
        "socks4": [],
        "http": [],
        "ss": [],
        "vmess": [],
        "trojan": [],
        "vless": [],
        "other": []
    }
    for n in nodes:
        proto = n.get("proto") or "other"
        if proto in groups:
            groups[proto].append(n)
        else:
            groups["other"].append(n)

    # write per-group subscription files (raw link where possible, else protocol URI)
    for g, lst in groups.items():
        path = out_dir / f"sub_{g}"
        lines = []
        for n in lst:
            if "sub_link" in n:
                lines.append(n["sub_link"])
            elif n.get("proto") in ("socks5","socks4","http","https"):
                lines.append(f"{n['proto']}://{n['server']}:{n['port']}")
            elif n.get("proto") == "ss" and "raw" in n:
                lines.append(n["raw"])
            elif n.get("proto") == "vmess" and "raw" in n:
                lines.append(n["raw"])
            elif "proto_link" in n:
                lines.append(n["proto_link"])
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        # also write base64-encoded version for ease of client import (like earlier sub)
        with open(path, "rb") as f:
            content = f.read()
        try:
            b64 = base64.b64encode(content).decode()
            with open(out_dir / f"{path.name}_b64", "w", encoding="utf-8") as bf:
                bf.write(b64)
        except Exception:
            pass

    # also write merged sub (all)
    merged_lines = []
    for g in groups:
        p = out_dir / f"sub_{g}"
        if p.exists():
            merged_lines.extend([l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()])
    with open(out_dir / "sub", "w", encoding="utf-8") as f:
        f.write("\n".join(merged_lines))

    # write per-protocol human files like ss.txt vmess.txt trojan.txt
    with open(out_dir / "ss.txt", "w", encoding="utf-8") as f:
        f.write("\n".join([l for l in merged_lines if l.startswith("ss://")]))
    with open(out_dir / "vmess.txt", "w", encoding="utf-8") as f:
        f.write("\n".join([l for l in merged_lines if l.startswith("vmess://")]))
    with open(out_dir / "trojan.txt", "w", encoding="utf-8") as f:
        f.write("\n".join([l for l in merged_lines if l.startswith("trojan://")]))

def generate_clash_yaml(nodes, out_path=OUT / "proxy.yaml"):
    proxies = []
    for n in nodes:
        proto = n.get("proto")
        name = n.get("name") or f"{proto}_{n.get('server')}_{n.get('port')}"
        if proto == "ss":
            proxies.append({"name":name,"type":"ss","server":n.get("server"),"port":int(n.get("port")),"cipher":n.get("cipher",""),"password":n.get("password",""),"udp":True})
        elif proto == "vmess":
            proxies.append({"name":name,"type":"vmess","server":n.get("server"),"port":int(n.get("port")),"uuid":n.get("uuid",""),"alterId":0,"cipher":"auto","tls":bool(n.get("raw_conf",{}).get("tls",False))})
        elif proto == "trojan":
            proxies.append({"name":name,"type":"trojan","server":n.get("server"),"port":int(n.get("port")),"password":n.get("password",""),"udp":True})
        elif proto in ("socks5","socks4","http"):
            proxies.append({"name":name,"type":proto,"server":n.get("server"),"port":int(n.get("port")),"udp":False})
    cfg = {
        "mixed-port": 0,
        "allow-lan": False,
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups":[{"name":"AUTO","type":"url-test","url":"http://www.gstatic.com/generate_204","interval":300,"proxies":[p["name"] for p in proxies] + ["DIRECT"]}],
        "rules":["MATCH,AUTO"]
    }
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, allow_unicode=True, default_flow_style=False)

def generate_qr_for_group(group_name):
    url = f"{GITHUB_PAGES_BASE}/sub_{group_name}"
    path = OUT / f"qrcode_{group_name}.png"
    try:
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=8, border=4)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(path)
    except Exception as e:
        print("QR gen error for", group_name, e)

def generate_index_html(nodes):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    total = len(nodes)
    alive = sum(1 for n in nodes if n.get("alive"))
    verified_http = sum(1 for n in nodes if n.get("http_verified"))
    avg_delay = int(sum(n.get("delay") for n in nodes if n.get("delay") and n.get("alive")) / max(1, alive)) if alive else -1

    html = []
    html.append("<!doctype html><html lang='zh'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>")
    html.append("<title>订阅中心</title><style>body{font-family:Arial,Helvetica,sans-serif;padding:16px;background:#f7f9fb} .card{background:#fff;padding:12px;border-radius:8px;margin-bottom:12px;box-shadow:0 2px 6px rgba(0,0,0,0.06)} .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px} .node{border:1px solid #eee;padding:8px;border-radius:6px;background:#fff;text-align:center} .tag{display:inline-block;padding:6px 8px;background:#eef6ff;color:#0366d6;border-radius:10px;margin-right:6px}</style></head><body>")
    html.append(f"<div class='card'><h2>订阅中心</h2><p>总节点: <span class='tag'>{total}</span> 可连通: <span class='tag'>{alive}</span> HTTP 验证通过 (socks/http): <span class='tag'>{verified_http}</span> 平均延迟(ms): <span class='tag'>{avg_delay if avg_delay>=0 else 'N/A'}</span></p>")
    html.append(f"<p>主合并订阅: <a href='{GITHUB_PAGES_BASE}/sub' target='_blank'>{GITHUB_PAGES_BASE}/sub</a></p>")
    html.append("<div style='display:flex;gap:12px;flex-wrap:wrap'>")
    # group QR cards
    for g in ("socks5","socks4","http","ss","vmess","trojan","vless"):
        qrpath = f"qrcode_{g}.png"
        html.append(f"<div style='width:200px;text-align:center'><h4>{g}</h4><a href='{GITHUB_PAGES_BASE}/sub_{g}' target='_blank'>{GITHUB_PAGES_BASE}/sub_{g}</a><br><img src='{qrpath}' style='width:160px;margin-top:6px'></div>")
    html.append("</div></div>")

    # node list (top N)
    html.append("<div class='card'><h3>节点一览（按延迟排序，前100）</h3><div class='grid'>")
    shown = 0
    for n in sorted(nodes, key=lambda x: (0 if x.get("alive") else 1, x.get("delay") if x.get("delay") else 99999))[:200]:
        name = n.get("name") or f"{n.get('proto')}_{n.get('server')}_{n.get('port')}"
        server = n.get("server","")
        port = n.get("port","")
        proto = n.get("proto","")
        alive_flag = n.get("alive", False)
        delay = n.get("delay") if n.get("delay") is not None else "N/A"
        httpv = n.get("http_verified", False)
        qr = n.get("qr","")
        sub_link = n.get("sub_link","")
        html.append("<div class='node'>")
        html.append(f"<strong>{name}</strong><br><small>{proto}</small><br>")
        if qr:
            html.append(f"<img src='{qr}' style='width:140px'><br>")
        html.append(f"<div style='font-size:13px;color:#666'>地址: {server}:{port}<br>延迟: {delay} ms<br>alive: {'是' if alive_flag else '否'}<br>http验证: {'✓' if httpv else '—'}</div>")
        if sub_link:
            html.append(f"<p><button onclick=\"navigator.clipboard.writeText('{sub_link}')\">复制节点链接</button></p>")
        html.append("</div>")
        shown += 1
    html.append("</div></div>")
    html.append(f"<footer style='color:#999'>最后更新: {now}</footer></body></html>")

    with open(OUT / "index.html", "w", encoding="utf-8") as f:
        f.write("\n".join(html))

# -------------------- main --------------------
async def main():
    start = time.time()
    print("Start fetching sources...")
    responses = await fetch_all_sources(SOURCES)
    raw_lines = []
    for r in responses:
        if not r: continue
        # extract protocol links & ip:port
        raw_lines.extend(extract_protocol_links(r))
        raw_lines.extend(extract_ipports(r))
        # if looks like base64 blob, try decode to find embedded links
        if is_probable_base64(r):
            try:
                dec = safe_b64decode(r).decode(errors="ignore")
                raw_lines.extend(extract_protocol_links(dec))
                raw_lines.extend(extract_ipports(dec))
                for line in dec.splitlines():
                    if line.strip():
                        raw_lines.append(line.strip())
            except Exception:
                pass
        # finally also add lines that are explicit
        for line in r.splitlines():
            line = line.strip()
            if not line: continue
            if line.startswith(("ss://","vmess://","vless://","trojan://")) or re.match(r"^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$", line):
                raw_lines.append(line)
    print(f"Collected raw entries: {len(raw_lines)}")

    # parse to nodes
    nodes = parse_raw_lines_to_nodes(raw_lines)
    print(f"Parsed nodes: {len(nodes)}")

    # TCP test (async)
    print("Start TCP connectivity test...")
    tested = await test_tcp_all(nodes, max_workers=min(MAX_TCP_CONCURRENCY, max(10, len(nodes)//2)))
    print("TCP test done. Total tested:", len(tested))

    # Post-process: for items lacking proto but with proto_link decoded earlier will have been filled
    # Now prepare lists for HTTP/SOCKS verification
    socks_http_nodes = [n for n in tested if n.get("proto") in ("socks5","socks4","http","https")]
    other_nodes = [n for n in tested if n.get("proto") not in ("socks5","socks4","http","https")]

    # For socks/http do real HTTP verification via requests (threadpool)
    print(f"Starting HTTP/SOCKS verification for {len(socks_http_nodes)} nodes (this will do real proxied HTTP GET to {VERIFY_TEST_URL}) ...")
    verified_list = []
    if socks_http_nodes:
        with concurrent.futures.ThreadPoolExecutor(max_workers=HTTP_VERIFY_WORKERS) as ex:
            futures = {ex.submit(lambda n: (n, __import__('requests').get if False else None), n): n for n in socks_http_nodes}
        # we won't use that trick; call batch_verify_http_nodes
        verified = batch_verify_http_nodes(socks_http_nodes, workers=HTTP_VERIFY_WORKERS)
        # merge results
        for n in tested:
            if n.get("proto") in ("socks5","socks4","http","https"):
                # find matching in verified
                for v in verified:
                    if v.get("server")==n.get("server") and v.get("port")==n.get("port"):
                        n["http_verified"] = v.get("http_verified", False)
                        break
                else:
                    n["http_verified"] = False

    # For other protos (ss/vmess/trojan/vless) we only have TCP result; mark http_verified False (can't test here)
    for n in tested:
        if "http_verified" not in n:
            n["http_verified"] = False

    # decide final kept nodes
    if KEEP_ONLY_VERIFIED:
        # KEEP only:
        final_nodes = []
        # include all nodes that either:
        #  - are socks/http and http_verified==True
        #  - or are other protos and alive==True and delay <= MAX_ACCEPTABLE_DELAY_MS
        for n in tested:
            proto = n.get("proto")
            if proto in ("socks5","socks4","http","https"):
                if n.get("http_verified"):
                    final_nodes.append(n)
            else:
                if n.get("alive") and (n.get("delay") is not None and n.get("delay") <= MAX_ACCEPTABLE_DELAY_MS):
                    final_nodes.append(n)
    else:
        final_nodes = tested

    print(f"Kept final nodes: {len(final_nodes)} (keep_only_verified={KEEP_ONLY_VERIFIED})")

    # prepare sub_link for nodes where missing (use raw/proto_link/or default)
    for n in final_nodes:
        if "sub_link" in n:
            continue
        if n.get("proto") in ("socks5","socks4","http","https"):
            n["sub_link"] = f"{n['proto']}://{n['server']}:{n['port']}#{quote(n.get('server',''))}"
        elif n.get("proto") == "ss" and "raw" in n:
            n["sub_link"] = n["raw"]
        elif n.get("proto") == "vmess" and "raw" in n:
            n["sub_link"] = n["raw"]
        elif "proto_link" in n:
            n["sub_link"] = n["proto_link"]
        else:
            n["sub_link"] = f"{n.get('proto','unknown')}://{n.get('server')}:{n.get('port')}"

    # sort final_nodes by alive & delay
    final_nodes.sort(key=lambda x: (0 if x.get("alive") else 1, x.get("delay") if x.get("delay") else 99999))

    # generate outputs
    print("Generating output files...")
    generate_clash_yaml(final_nodes, out_path=OUT / "proxy.yaml")
    write_group_files(final_nodes, out_dir=OUT)
    # generate per-node QR images and group QR
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
            img.save(QRS / fname)
            n["qr"] = f"qrs/{fname}"
        except Exception:
            n["qr"] = ""

    # generate group QR codes
    for g in ("socks5","socks4","http","ss","vmess","trojan","vless"):
        try:
            generate_qr_for_group(g)
        except Exception:
            pass

    generate_index_html(final_nodes)

    end = time.time()
    print(f"Done. Time elapsed: {int(end-start)}s. Final nodes: {len(final_nodes)}")
    # summary printing (short)
    total_parsed = len(nodes)
    alive_count = sum(1 for n in final_nodes if n.get("alive"))
    http_ok = sum(1 for n in final_nodes if n.get("http_verified"))
    print(f"Summary: parsed={total_parsed}, final={len(final_nodes)}, alive={alive_count}, http_ok={http_ok}")

if __name__ == "__main__":
    asyncio.run(main())
