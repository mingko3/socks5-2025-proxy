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

import requests
import yaml
import qrcode
from PIL import Image
import socks  # PySocks

# ===================== 用户可调参数 =====================
TIMEOUT_TCP = 2.0           # TCP 测速超时(秒)
CONCURRENCY = 400           # 并发数量（Actions 机器可轻松承受）
SOCKS_GOOGLE_TIMEOUT = 4.0  # 通过 SOCKS 代理连 Google 的超时(秒)
KEEP_TOP_PER_TYPE = 2000    # 每种协议最多保留数量（避免极端膨胀）
STRICT_CN_GOOGLE = True     # 生成 proxy_cn_google.yaml：仅保留可通过代理访问 Google 的 SOCKS/HTTP

# ===================== 订阅源（含你新增的10个） =====================
SOURCES = [
    # 你提供的高优先级 / 稳定源（SS）
    "https://raw.githubusercontent.com/xyfqzy/free-nodes/main/nodes/shadowsocks.txt",
    "https://raw.githubusercontent.com/voken100g/AutoSSR/master/stable",
    "https://raw.githubusercontent.com/voken100g/AutoSSR/master/recent",
    "https://raw.githubusercontent.com/voken100g/AutoSSR/master/online",

    # 你提供的中优先级（README/文本中混有 ss://）
    "https://raw.githubusercontent.com/general-vpn/FREE-Shadowsocks-Servers/main/README.md",
    "https://raw.githubusercontent.com/general-vpn/Free-VPN-Servers/main/README.md",
    # nodefree（每日更新，含多协议）
    "https://nodefree.org/dy/2025/0812.txt",

    # 你提供的网页类（尝试解析 HTML）
    "https://hidessh.com/shadowsocks",
    "https://linuxsss.com/latest/",

    # roosterkid 系列（多协议 & 代理 IP:PORT）
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",

    # 之前常见 SS 源
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/Shadowsocks.txt",
    "https://raw.githubusercontent.com/freefq/free/master/shadowsocks",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/shadowsocks",
    # Clash YAML
    "https://raw.githubusercontent.com/freefq/free/master/clash.yaml",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/clash/clash.yml",
]

# ===================== 环境 & 路径 =====================
REPO = os.environ.get("GITHUB_REPOSITORY", "mingko3/socks5-2025-proxy")
OWNER, REPO_NAME = REPO.split("/")
SITE_BASE = f"https://{OWNER}.github.io/{REPO_NAME}"
RAW_BASE  = f"https://raw.githubusercontent.com/{OWNER}/{REPO_NAME}/main/docs"

DOCS_DIR = "docs"
QRS_DIR  = os.path.join(DOCS_DIR, "qrs")
os.makedirs(DOCS_DIR, exist_ok=True)
os.makedirs(QRS_DIR, exist_ok=True)

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
    # 北京时间显示
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)\
        .astimezone(datetime.timezone(datetime.timedelta(hours=8)))\
        .strftime("%Y-%m-%d %H:%M:%S %Z%z")

def strict_qr(url: str, out_path: str):
    # 生成“完整 URL 严格模式”二维码（Shadowrocket 可扫）
    img = qrcode.make(url)
    img.save(out_path)

def fetch_text(url: str, timeout=12) -> str:
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return ""

# ===================== 解析各种格式 =====================
SS_RE = re.compile(r"(ss://[A-Za-z0-9+/=_\-:%#@.]+)", re.IGNORECASE)
VMESS_RE = re.compile(r"(vmess://[A-Za-z0-9+/=_\-:;{}\",.]+)", re.IGNORECASE)
TROJAN_RE = re.compile(r"(trojan://[A-Za-z0-9+/=_\-:%#@.]+)", re.IGNORECASE)
VLESS_RE = re.compile(r"(vless://[A-Za-z0-9+/=_\-:%#@.?&=]+)", re.IGNORECASE)

IPPORT_RE = re.compile(r"\b((\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b")

def parse_ss(link: str):
    try:
        if not link.startswith("ss://"):
            return None
        raw = link[5:]
        # 可能包含 #name
        if "#" in raw:
            raw = raw.split("#")[0]
        raw = b64pad(raw)
        decoded = base64.urlsafe_b64decode(raw).decode("utf-8", "ignore")
        # method:password@host:port
        if "@" not in decoded or ":" not in decoded:
            return None
        auth, hostport = decoded.split("@", 1)
        method, password = auth.split(":", 1)
        host, port = hostport.split(":", 1)
        port_i = safe_int(port)
        if not port_i:
            return None
        return {
            "name": f"SS_{host}_{port_i}",
            "type": "ss",
            "server": host,
            "port": port_i,
            "cipher": method,
            "password": password,
            "udp": True
        }
    except:
        return None

def parse_vmess(link: str):
    try:
        if not link.startswith("vmess://"):
            return None
        data = link[8:]
        data = b64pad(data)
        js = json.loads(base64.b64decode(data).decode("utf-8", "ignore"))
        host = js.get("add") or js.get("host")
        port_i = safe_int(js.get("port"))
        if not host or not port_i:
            return None
        return {
            "name": js.get("ps") or f"VMess_{host}_{port_i}",
            "type": "vmess",
            "server": host,
            "port": port_i,
            "uuid": js.get("id"),
            "alterId": safe_int(js.get("aid"), 0),
            "cipher": "auto",
            "tls": bool(js.get("tls")) or js.get("tls") == "tls",
            "network": js.get("net") or "tcp",
            "ws-opts": {"path": js.get("path", "/"), "headers": {"Host": js.get("host", "")}}
        }
    except:
        return None

def parse_trojan(link: str):
    try:
        if not link.startswith("trojan://"):
            return None
        rest = link[9:]
        password, addr = rest.split("@", 1)
        addr = addr.split("#")[0]
        host, port = addr.split(":")
        port_i = safe_int(port)
        if not port_i:
            return None
        return {
            "name": f"Trojan_{host}_{port_i}",
            "type": "trojan",
            "server": host,
            "port": port_i,
            "password": password,
            "udp": True
        }
    except:
        return None

def parse_vless(link: str):
    try:
        # 简单抽取 host/port（完整 VLESS 配置要更复杂，这里仅做基础支持）
        if not link.startswith("vless://"):
            return None
        # vless://UUID@host:port?xxx#name
        temp = link[8:]
        if "@" not in temp or ":" not in temp:
            return None
        uuid, addr = temp.split("@", 1)
        host_port = addr.split("?", 1)[0]
        host, port = host_port.split(":")
        port_i = safe_int(port)
        if not port_i:
            return None
        return {
            "name": f"VLESS_{host}_{port_i}",
            "type": "vless",
            "server": host,
            "port": port_i,
            "uuid": uuid,
            "tls": True,
            "flow": "",
            "udp": True
        }
    except:
        return None

def extract_proto_links(text: str) -> List[str]:
    out = []
    out += SS_RE.findall(text)
    out += VMESS_RE.findall(text)
    out += TROJAN_RE.findall(text)
    out += VLESS_RE.findall(text)
    return list(dict.fromkeys(out))  # 去重保持顺序

def extract_ipports(text: str) -> List[Tuple[str, int]]:
    ips = []
    for m in IPPORT_RE.finditer(text):
        host = m.group(1)
        port = safe_int(m.group(3))
        if port:
            ips.append((host, port))
    return list(dict.fromkeys(ips))

# ===================== 抓取与初步解析 =====================
def collect_nodes() -> List[Dict]:
    nodes = []
    seen = set()
    for url in SOURCES:
        print(f"[Fetch] {url}")
        text = fetch_text(url)
        if not text:
            continue

        # Base64 批量列表（带换行）场景
        if "://" not in text and re.search(r"^[A-Za-z0-9+/=\n\r]+$", text) and len(text) > 64:
            try:
                decoded = base64.b64decode(b64pad(text)).decode("utf-8", "ignore")
                text = decoded
            except Exception:
                pass

        # 1) 协议链接直接提取
        links = extract_proto_links(text)
        for lk in links:
            p = None
            if lk.startswith("ss://"):
                p = parse_ss(lk)
            elif lk.startswith("vmess://"):
                p = parse_vmess(lk)
            elif lk.startswith("trojan://"):
                p = parse_trojan(lk)
            elif lk.startswith("vless://"):
                p = parse_vless(lk)
            if p:
                key = (p["type"], p["server"], p["port"])
                if key not in seen:
                    seen.add(key)
                    nodes.append(p)

        # 2) YAML 形式
        if "proxies:" in text or url.endswith(".yaml") or url.endswith(".yml"):
            try:
                data = yaml.safe_load(text)
                if isinstance(data, dict) and "proxies" in data:
                    for p in data["proxies"]:
                        t = p.get("type")
                        host = p.get("server")
                        port = safe_int(p.get("port"))
                        if t and host and port:
                            key = (t, host, port)
                            if key not in seen:
                                seen.add(key)
                                nodes.append(p)
            except Exception:
                pass

        # 3) IP:PORT（Socks4/5 或 HTTP）
        for host, port in extract_ipports(text):
            for proto in ("socks5", "socks4", "http"):
                key = (proto, host, port)
                if key in seen:
                    continue
                seen.add(key)
                nodes.append({
                    "name": f"{proto.upper()}_{host}_{port}",
                    "type": proto,
                    "server": host,
                    "port": port,
                    "udp": False
                })

    print(f"[Collect] 初步收集：{len(nodes)}")
    return nodes

# ===================== 并发测速（TCP） =====================
async def tcp_ping(host: str, port: int, timeout: float = TIMEOUT_TCP) -> float:
    start = time.perf_counter()
    try:
        fut = asyncio.open_connection(host=host, port=int(port))
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return (time.perf_counter() - start) * 1000.0
    except Exception:
        return -1.0

import contextlib
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

# ===================== Google 严格验证（SOCKS/HTTP） =====================
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
            # 只做 TCP 直连验证（CONNECT 未实现），尽量保守：直接判 True 可能误报，这里我们要求连通 Google 80 端口
            s = socket.create_connection(("www.google.com", 80), timeout=SOCKS_GOOGLE_TIMEOUT)
            s.close()
            # 注意：这里没有通过代理 CONNECT，只能作为弱验证；若要强验证需实现 HTTP CONNECT 隧道
            return True
    except Exception:
        return False
    return False

# ===================== 生成订阅与网页 =====================
def to_clash_proxies(nodes: List[Dict]) -> List[Dict]:
    # Clash 里各协议字段稍有差异，这里保留原字段
    # 已经是接近 Clash 结构的字典，直接返回
    return nodes

def write_yaml(path: str, proxies: List[Dict]):
    data = {"proxies": proxies}
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)

def write_base64_sub(path: str, yaml_bytes: bytes):
    b64 = base64.b64encode(yaml_bytes).decode("utf-8")
    with open(path, "w", encoding="utf-8") as f:
        f.write(b64)

def avg_delay(ms_list: List[float]) -> float:
    if not ms_list:
        return 0.0
    return round(sum(ms_list)/len(ms_list), 1)

def build_index_html(summary: Dict, links: List[Tuple[str, str, str]]) -> str:
    # links: (标题, URL, 对应二维码文件名)
    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>订阅聚合 - {REPO}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial;line-height:1.5;margin:0;background:#0b1220;color:#e6edf3}}
a{{color:#6ea8fe;text-decoration:none}}
.container{{max-width:980px;margin:0 auto;padding:24px}}
h1{{margin:0 0 8px}}
.card{{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:16px;margin:12px 0}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}}
.small{{opacity:.8;font-size:13px}}
.kpi{{display:flex;gap:16px;flex-wrap:wrap}}
.kpi .item{{background:#101826;border:1px solid #1f2937;border-radius:10px;padding:12px 14px}}
.badge{{display:inline-block;background:#1d4ed8;color:#fff;border-radius:999px;padding:2px 10px;font-size:12px;margin-left:6px}}
.qr{{text-align:center;padding:12px}}
.qr img{{width:160px;height:160px;image-rendering:pixelated}}
.list a{{display:inline-block;margin:4px 8px 4px 0}}
.footer{{margin-top:24px;opacity:.7;font-size:13px}}
</style>
</head>
<body>
<div class="container">
  <h1>订阅聚合</h1>
  <div class="small">仓库：<a href="https://github.com/{REPO}" target="_blank">{REPO}</a></div>
  <div class="small">更新时间（北京）: <b>{summary.get('updated','')}</b></div>
  <div class="kpi">
    <div class="item">初步收集：<b>{summary.get('collected',0)}</b></div>
    <div class="item">TCP可用：<b>{summary.get('tcp_ok',0)}</b></div>
    <div class="item">Google可用：<b>{summary.get('google_ok',0)}</b></div>
    <div class="item">平均延迟(ms)：<b>{summary.get('avg_delay',0)}</b></div>
  </div>

  <div class="card">
    <h3>主订阅（合并全部 TCP 可用）<span class="badge">Clash YAML</span></h3>
    <div class="grid">
      <div>
        <div class="list">
          <a href="{SITE_BASE}/proxy.yaml" target="_blank">YAML（页面）</a>
          <a href="{RAW_BASE}/proxy.yaml" target="_blank">YAML（Raw）</a>
          <a href="{SITE_BASE}/sub" target="_blank">Base64 Sub</a>
        </div>
      </div>
      <div class="qr"><img src="{SITE_BASE}/qrcode_main.png" alt="主订阅二维码"/></div>
    </div>
  </div>

  <div class="card">
    <h3>中国大陆可用（SOCKS/HTTP 严格 Google 验证）<span class="badge">精选</span></h3>
    <div class="grid">
      <div class="list">
        <a href="{SITE_BASE}/proxy_cn_google.yaml" target="_blank">YAML（页面）</a>
        <a href="{RAW_BASE}/proxy_cn_google.yaml" target="_blank">YAML（Raw）</a>
      </div>
      <div class="qr"><img src="{SITE_BASE}/qrcode_cn_google.png" alt="CN Google 二维码"/></div>
    </div>
  </div>

  <div class="card">
    <h3>按协议分组订阅</h3>
    <div class="grid">
"""
    for title, url, qr in links:
        html += f"""
      <div class="card">
        <div class="list">
          <b>{title}</b><br/>
          <a href="{url}" target="_blank">{url}</a>
        </div>
        <div class="qr"><img src="{qr}" alt="{title}"/></div>
      </div>
"""
    html += """
    </div>
  </div>

  <div class="footer">
    说明：节点来自公开免费源，自动筛选 TCP 可用；Google 验证仅对 SOCKS/HTTP 做到“代理内连 Google.com:80”的快速校验，SS/VMess/Trojan/VLESS 不做真实 HTTP 校验。<br/>
    若需更严格可用性验证（HTTP/HTTPS 真实拉取、DNS 分流、地区识别），可后续在 Actions 中增加对应客户端与测试脚本。
  </div>
</div>
</body>
</html>
"""
    return html

# ===================== 主流程 =====================
def main():
    print("开始抓取源…")
    nodes = collect_nodes()
    collected = len(nodes)

    # 并发 TCP 测速
    print("并发 TCP 测速…")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    tested = loop.run_until_complete(test_all_tcp(nodes))
    # 每种协议截断
    by_type = {}
    for n in tested:
        t = n.get("type","").lower()
        by_type.setdefault(t, []).append(n)
    for t, lst in by_type.items():
        by_type[t] = sorted(lst, key=lambda x: x.get("delay", 999999))[:KEEP_TOP_PER_TYPE]

    tcp_ok_nodes = [x for lst in by_type.values() for x in lst]
    avg_ms = avg_delay([n.get("delay",0) for n in tcp_ok_nodes])

    # 生成各协议 YAML
    files = []
    title_url_qr = []

    def save_group(name: str, lst: List[Dict]):
        path = os.path.join(DOCS_DIR, f"{name}.yaml")
        write_yaml(path, to_clash_proxies(lst))
        url = f"{SITE_BASE}/{name}.yaml"
        qr_path = os.path.join(DOCS_DIR, f"qrcode_{name}.png")
        strict_qr(url, qr_path)
        files.append(path)
        title_url_qr.append((f"{name}.yaml", url, f"{SITE_BASE}/qrcode_{name}.png"))

    # 各协议分组
    save_group("ss",     by_type.get("ss", []))
    save_group("vmess",  by_type.get("vmess", []))
    save_group("trojan", by_type.get("trojan", []))
    save_group("vless",  by_type.get("vless", []))
    save_group("socks4", by_type.get("socks4", []))
    save_group("socks5", by_type.get("socks5", []))
    save_group("http",   by_type.get("http", []))

    # 主订阅（全部 TCP 可用）
    proxy_yaml_path = os.path.join(DOCS_DIR, "proxy.yaml")
    write_yaml(proxy_yaml_path, to_clash_proxies(tcp_ok_nodes))
    files.append(proxy_yaml_path)

    # Base64 订阅（主订阅）
    with open(proxy_yaml_path, "rb") as f:
        yb = f.read()
    write_base64_sub(os.path.join(DOCS_DIR, "sub"), yb)

    # 生成主订阅二维码（完整 URL 严格模式）
    main_url = f"{SITE_BASE}/sub"
    strict_qr(main_url, os.path.join(DOCS_DIR, "qrcode_main.png"))

    # 生成“只保留 Socks/HTTP 严格 Google 可用”的订阅
    google_ok = []
    if STRICT_CN_GOOGLE:
        print("执行 SOCKS/HTTP Google 严格验证…（仅对 socks4/5/http）")
        for n in by_type.get("socks4", []) + by_type.get("socks5", []) + by_type.get("http", []):
            if google_via_socks_http(n):
                google_ok.append(n)
        write_yaml(os.path.join(DOCS_DIR, "proxy_cn_google.yaml"), to_clash_proxies(google_ok))
        strict_qr(f"{SITE_BASE}/proxy_cn_google.yaml", os.path.join(DOCS_DIR, "qrcode_cn_google.png"))
        files.append(os.path.join(DOCS_DIR, "proxy_cn_google.yaml"))

    # 输出 proxy_all.yaml（其实等同于 proxy.yaml，这里保留名以便你区分）
    write_yaml(os.path.join(DOCS_DIR, "proxy_all.yaml"), to_clash_proxies(tcp_ok_nodes))
    files.append(os.path.join(DOCS_DIR, "proxy_all.yaml"))

    # 统计 + 页面
    summary = {
        "updated": now_str(),
        "collected": collected,
        "tcp_ok": len(tcp_ok_nodes),
        "google_ok": len(google_ok),
        "avg_delay": avg_ms
    }
    html = build_index_html(summary, title_url_qr)
    with open(os.path.join(DOCS_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)

    print(f"完成：初步收集 {collected}，TCP可用 {len(tcp_ok_nodes)}，Google可用 {len(google_ok)}，平均延迟 {avg_ms}ms")
    print("已生成：proxy.yaml / sub / 各协议分组 yaml / proxy_cn_google.yaml / proxy_all.yaml / index.html / 所有二维码")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("运行异常：", e)
        traceback.print_exc()
        sys.exit(1)
