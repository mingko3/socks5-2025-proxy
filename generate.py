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
import contextlib
from typing import List, Dict, Tuple

import requests
import yaml
import qrcode
from PIL import Image, ImageDraw, ImageFont
import socks  # PySocks

# ===================== 可调参数 =====================
TIMEOUT_TCP = 2.0            # TCP 测速超时(秒)
CONCURRENCY = 400            # 并发数量
SOCKS_GOOGLE_TIMEOUT = 4.0   # SOCKS/HTTP 代理连 Google 超时
KEEP_TOP_PER_TYPE = 2000     # 每协议最多保留
STRICT_CN_GOOGLE = True      # 生成 proxy_cn_google.yaml（仅 SOCKS/HTTP 代理内连通 Google）
BATCH_SIZE = 20              # 每批节点数（二维码分批）
EMBED_MAX_BYTES = 1800       # 内嵌二维码最大 data: 内容字节数（超过则自动降级为 URL 型）
QR_SIZE = 660                # 生成二维码图像像素
QR_BORDER = 24               # 外围彩色圆角边框宽度（像素）

# ===================== 订阅源 =====================
SOURCES = [
    # 高优先级/稳定（SS）
    "https://raw.githubusercontent.com/xyfqzy/free-nodes/main/nodes/shadowsocks.txt",
    "https://raw.githubusercontent.com/voken100g/AutoSSR/master/stable",
    "https://raw.githubusercontent.com/voken100g/AutoSSR/master/recent",
    "https://raw.githubusercontent.com/voken100g/AutoSSR/master/online",

    # README/文本混合 ss://
    "https://raw.githubusercontent.com/general-vpn/FREE-Shadowsocks-Servers/main/README.md",
    "https://raw.githubusercontent.com/general-vpn/Free-VPN-Servers/main/README.md",

    # nodefree（示例日更页）
    "https://nodefree.org/dy/2025/0812.txt",

    # HTML 类
    "https://hidessh.com/shadowsocks",
    "https://linuxsss.com/latest/",

    # roosterkid 系列
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",

    # 其他常见 SS 源 & Clash YAML
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/Shadowsocks.txt",
    "https://raw.githubusercontent.com/freefq/free/master/shadowsocks",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/shadowsocks",
    "https://raw.githubusercontent.com/freefq/free/master/clash.yaml",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/clash/clash.yml",
]

# ===================== 路径 & 站点 =====================
REPO = os.environ.get("GITHUB_REPOSITORY", "mingko3/socks5-2025-proxy")
OWNER, REPO_NAME = REPO.split("/")
SITE_BASE = f"https://{OWNER}.github.io/{REPO_NAME}"
RAW_BASE  = f"https://raw.githubusercontent.com/{OWNER}/{REPO_NAME}/main/docs"

DOCS_DIR  = "docs"
QRS_DIR   = os.path.join(DOCS_DIR, "qrs")
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
    except Exception:
        pass
    return ""

# —— QR：带彩色圆角边框（URL=蓝色、内嵌=绿色） ——
def _rounded_rect(img: Image.Image, radius: int, border_px: int, color: tuple):
    w, h = img.size
    canvas = Image.new("RGBA", (w + border_px*2, h + border_px*2), (0,0,0,0))
    draw = ImageDraw.Draw(canvas)
    outer = [0,0,canvas.width,canvas.height]
    # 画圆角矩形
    draw.rounded_rectangle(outer, radius=radius, fill=(0,0,0,0), outline=color, width=border_px)
    # 把二维码贴到中心
    canvas.paste(img, (border_px, border_px))
    return canvas.convert("RGB")

def make_qr_img(data: str, border_color=(52,104,255)) -> Image.Image:
    qr = qrcode.QRCode(
        version=None, error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=max(2, QR_SIZE // 58), border=2
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    # 调整到目标尺寸
    img = img.resize((QR_SIZE, QR_SIZE), Image.NEAREST)
    # 加彩色圆角边框
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
        if not link.startswith("ss://"):
            return None
        raw = link[5:]
        raw = raw.split("#")[0]
        dec = base64.urlsafe_b64decode(b64pad(raw)).decode("utf-8","ignore")
        if "@" not in dec or ":" not in dec:
            return None
        auth, addr = dec.split("@",1)
        method, password = auth.split(":",1)
        host, port = addr.split(":")
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
        data = base64.b64decode(b64pad(link[8:])).decode("utf-8","ignore")
        js = json.loads(data)
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
        password, addr = rest.split("@",1)
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
        if not link.startswith("vless://"):
            return None
        temp = link[8:]
        if "@" not in temp or ":" not in temp:
            return None
        uuid, addr = temp.split("@",1)
        host_port = addr.split("?",1)[0]
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
    return list(dict.fromkeys(out))

def extract_ipports(text: str) -> List[Tuple[str, int]]:
    ips = []
    for m in IPPORT_RE.finditer(text):
        host = m.group(1); port = safe_int(m.group(3))
        if port:
            ips.append((host, port))
    return list(dict.fromkeys(ips))

# ===================== 抓取与初步解析 =====================
def collect_nodes() -> List[Dict]:
    nodes, seen = [], set()
    for url in SOURCES:
        print(f"[Fetch] {url}")
        text = fetch_text(url)
        if not text: 
            continue

        # Base64 列表
        if "://" not in text and re.search(r"^[A-Za-z0-9+/=\n\r]+$", text) and len(text) > 64:
            try:
                text = base64.b64decode(b64pad(text)).decode("utf-8","ignore")
            except Exception:
                pass

        # 1) 协议链接
        for lk in extract_proto_links(text):
            p = None
            if lk.startswith("ss://"): p = parse_ss(lk)
            elif lk.startswith("vmess://"): p = parse_vmess(lk)
            elif lk.startswith("trojan://"): p = parse_trojan(lk)
            elif lk.startswith("vless://"): p = parse_vless(lk)
            if p:
                key = (p["type"], p["server"], p["port"])
                if key not in seen:
                    seen.add(key); nodes.append(p)

        # 2) YAML
        if "proxies:" in text or url.endswith((".yaml",".yml")):
            try:
                data = yaml.safe_load(text)
                if isinstance(data, dict) and "proxies" in data:
                    for p in data["proxies"]:
                        t = p.get("type"); host = p.get("server"); port = safe_int(p.get("port"))
                        if t and host and port:
                            key = (t, host, port)
                            if key not in seen:
                                seen.add(key); nodes.append(p)
            except Exception:
                pass

        # 3) IP:PORT → socks4/5/http
        for host, port in extract_ipports(text):
            for proto in ("socks5","socks4","http"):
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
    print(f"[Collect] 初步收集: {len(nodes)}")
    return nodes

# ===================== 并发 TCP 测速 =====================
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

async def test_all_tcp(nodes: List[Dict]) -> List[Dict]:
    sem = asyncio.Semaphore(CONCURRENCY); out = []
    async def test_one(n):
        async with sem:
            d = await tcp_ping(n["server"], n["port"])
            if d > 0:
                n["delay"] = round(d, 1); out.append(n)
    await asyncio.gather(*(test_one(n) for n in nodes))
    return out

# ===================== Google 严格验证（仅 socks4/5/http） =====================
def google_via_socks_http(n: Dict) -> bool:
    host, port = n["server"], int(n["port"])
    try:
        if n["type"].lower() in ("socks5","socks4"):
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5 if n["type"]=="socks5" else socks.SOCKS4, host, port)
            s.settimeout(SOCKS_GOOGLE_TIMEOUT)
            s.connect(("www.google.com", 80))
            s.close()
            return True
        elif n["type"].lower() == "http":
            # 这里只做直连 80 端口连通性弱验证；严格 CONNECT 需要实现隧道
            s = socket.create_connection(("www.google.com", 80), timeout=SOCKS_GOOGLE_TIMEOUT)
            s.close()
            return True
    except Exception:
        return False
    return False

# ===================== 导出 & 订阅构建 =====================
def to_clash_proxies(nodes: List[Dict]) -> List[Dict]:
    return nodes

def write_yaml(path: str, proxies: List[Dict]):
    data = {"proxies": proxies}
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)

def write_text(path: str, s: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(s)

def write_base64_sub(path: str, yaml_bytes: bytes):
    b64 = base64.b64encode(yaml_bytes).decode("utf-8")
    with open(path, "w", encoding="utf-8") as f:
        f.write(b64)

def avg_delay(ms_list: List[float]) -> float:
    return round(sum(ms_list)/len(ms_list), 1) if ms_list else 0.0

# 生成批次文件 + 双二维码（URL蓝、内嵌绿），返回批次信息列表
def export_batches(proto: str, nodes: List[Dict]) -> List[Dict]:
    items = []
    if not nodes:
        return items
    subdir = os.path.join(GROUPS_DIR, proto)
    os.makedirs(subdir, exist_ok=True)
    for i in range(0, len(nodes), BATCH_SIZE):
        batch = nodes[i:i+BATCH_SIZE]
        idx = i // BATCH_SIZE + 1
        fn = f"{proto}_batch_{idx}.yaml"
        path = os.path.join(subdir, fn)
        write_yaml(path, to_clash_proxies(batch))
        url_page = f"{SITE_BASE}/groups/{proto}/{fn}"
        url_raw  = f"{RAW_BASE}/groups/{proto}/{fn}"

        # URL 型二维码（蓝）
        qr_url_path = os.path.join(QRS_DIR, f"{proto}_batch_{idx}_url.png")
        save_qr_to(qr_url_path, url_page, color=(66,133,244))  # 蓝

        # 内嵌型二维码（绿）：小容量 data:，超限降级
        with open(path, "rb") as f:
            yb = f.read()
        data_uri = f"data:text/plain;base64,{base64.b64encode(yb).decode('utf-8')}"
        embed_ok = len(data_uri.encode("utf-8")) <= EMBED_MAX_BYTES

        if embed_ok:
            qr_emb_path = os.path.join(QRS_DIR, f"{proto}_batch_{idx}_embed.png")
            save_qr_to(qr_emb_path, data_uri, color=(16,185,129))  # 绿
            embed_img_url = f"{SITE_BASE}/qrs/{proto}_batch_{idx}_embed.png"
        else:
            qr_emb_path = None
            embed_img_url = None

        items.append({
            "index": idx,
            "page_url": url_page,
            "raw_url": url_raw,
            "qr_url_img": f"{SITE_BASE}/qrs/{proto}_batch_{idx}_url.png",
            "qr_embed_img": embed_img_url,
            "embed_fallback": (not embed_ok)
        })
    return items

# 页面
def build_index_html(summary: Dict,
                     per_proto_all: List[Dict],
                     per_proto_batches: Dict[str, List[Dict]]) -> str:
    # per_proto_all: {title,url_page,url_raw,qr_url_img,qr_embed_img,embed_fallback,count}
    # per_proto_batches: proto -> [ {index,page_url,raw_url,qr_url_img,qr_embed_img,embed_fallback} ]

    def chips_kpi():
        return f"""
<div class="kpi">
  <div class="item">初步收集：<b>{summary.get('collected',0)}</b></div>
  <div class="item">TCP可用：<b>{summary.get('tcp_ok',0)}</b></div>
  <div class="item">Google可用：<b>{summary.get('google_ok',0)}</b></div>
  <div class="item">平均延迟(ms)：<b>{summary.get('avg_delay',0)}</b></div>
</div>"""

    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>订阅聚合 - {REPO}</title>
<style>
:root{{--bg:#0b1220;--card:#111827;--line:#1f2937;--txt:#e6edf3;--link:#6ea8fe}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial;line-height:1.55}}
.container{{max-width:1080px;margin:0 auto;padding:18px 16px 40px}}
h1,h2,h3{{margin:8px 0 10px}}
a{{color:var(--link);text-decoration:none}}
.small{{opacity:.8;font-size:13px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;margin:14px 0}}
.kpi{{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0 2px}}
.kpi .item{{background:#101826;border:1px solid var(--line);border-radius:10px;padding:10px 12px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}}
.badge{{display:inline-block;background:#1d4ed8;color:#fff;border-radius:999px;padding:2px 10px;font-size:12px;margin-left:6px}}
.qrbox{{text-align:center}}
.qrbox img{{width:220px;height:220px;image-rendering:pixelated;border-radius:18px}}
.tag{{display:inline-block;padding:2px 8px;border:1px solid var(--line);border-radius:8px;margin-right:6px;font-size:12px;opacity:.85}}
.note{{font-size:12px;opacity:.7}}
.row{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
hr.sep{{border:0;border-top:1px dashed #263043;margin:8px 0}}
</style>
</head>
<body>
<div class="container">
  <h1>订阅聚合</h1>
  <div class="small">仓库：<a href="https://github.com/{REPO}" target="_blank">{REPO}</a></div>
  <div class="small">更新时间（北京）: <b>{summary.get('updated','')}</b></div>
  {chips_kpi()}

  <div class="card">
    <h3>主订阅（合并全部 TCP 可用）<span class="badge">Clash YAML</span></h3>
    <div class="grid">
      <div>
        <div class="row">
          <a class="tag" href="{SITE_BASE}/proxy.yaml" target="_blank">YAML（页面）</a>
          <a class="tag" href="{RAW_BASE}/proxy.yaml" target="_blank">YAML（Raw）</a>
          <a class="tag" href="{SITE_BASE}/sub" target="_blank">Base64 Sub</a>
        </div>
        <div class="note">推荐扫码右侧蓝边二维码；若客户端支持“扫码打开链接”即会导入订阅。</div>
      </div>
      <div class="qrbox"><img src="{SITE_BASE}/qrcode_main.png" alt="主订阅 QR"/></div>
    </div>
  </div>

  <div class="card">
    <h3>中国大陆可用（SOCKS/HTTP 严格 Google 验证）<span class="badge">精选</span></h3>
    <div class="grid">
      <div class="row">
        <a class="tag" href="{SITE_BASE}/proxy_cn_google.yaml" target="_blank">YAML（页面）</a>
        <a class="tag" href="{RAW_BASE}/proxy_cn_google.yaml" target="_blank">YAML（Raw）</a>
      </div>
      <div class="qrbox"><img src="{SITE_BASE}/qrcode_cn_google.png" alt="CN-Google QR"/></div>
    </div>
  </div>

  <div class="card">
    <h3>按协议整包订阅（每类全部，可较大）</h3>
    <div class="grid">
"""
    for item in per_proto_all:
        html += f"""
      <div class="card">
        <div><b>{item['title']}</b> <span class="note">共 {item['count']} 节点</span></div>
        <div class="row">
          <a class="tag" href="{item['url_page']}" target="_blank">YAML（页面）</a>
          <a class="tag" href="{item['url_raw']}" target="_blank">YAML（Raw）</a>
        </div>
        <hr class="sep"/>
        <div class="grid">
          <div class="qrbox"><div class="note">URL 型（蓝边）</div><img src="{item['qr_url_img']}" alt="URL QR"/></div>
          <div class="qrbox">"""
        if item["qr_embed_img"]:
            html += f"""<div class="note">内嵌型（绿边）</div><img src="{item['qr_embed_img']}" alt="Embed QR"/>"""
        else:
            html += f"""<div class="note">内嵌超限 → 使用 URL</div>"""
        html += """</div></div>
      </div>"""

    html += """
    </div>
  </div>

  <div class="card">
    <h3>按协议分批订阅（每批 20 个，推荐）</h3>
"""

    # 批次渲染
    for proto, batches in per_proto_batches.items():
        if not batches:
            continue
        html += f"""<h4 style="margin:8px 0 6px">{proto.upper()}</h4>
        <div class="grid">"""
        for b in batches:
            html += f"""
          <div class="card">
            <div><b>批次 #{b['index']}</b></div>
            <div class="row">
              <a class="tag" href="{b['page_url']}" target="_blank">YAML（页面）</a>
              <a class="tag" href="{b['raw_url']}" target="_blank">YAML（Raw）</a>
            </div>
            <hr class="sep"/>
            <div class="grid">
              <div class="qrbox"><div class="note">URL 型（蓝边）</div><img src="{b['qr_url_img']}" alt="URL QR"/></div>
              <div class="qrbox">"""
            if b["qr_embed_img"]:
                html += f"""<div class="note">内嵌型（绿边）</div><img src="{b['qr_embed_img']}" alt="Embed QR"/>"""
            else:
                html += f"""<div class="note">内嵌超限 → 使用 URL</div>"""
            html += """</div></div>
          </div>"""
        html += "</div>"

    html += f"""
  </div>

  <div class="card">
    <h3>说明</h3>
    <div class="small">
    1) 节点来自公开免费源，先并发 TCP 存活筛选，再按每协议保留前 {KEEP_TOP_PER_TYPE} 个。<br/>
    2) “中国大陆可用”仅对 SOCKS/HTTP 做了 <code>代理内连 Google.com:80</code> 的快速校验，SS/VMess/Trojan/VLESS 未做真实 HTTP 验证。<br/>
    3) 二维码：蓝边=URL 型（最稳），绿边=内嵌型（离线导入，容量有限，超限将自动降级为 URL 型）。<br/>
    4) 若扫码“无效”，请先用系统相机或浏览器扫码“打开链接”再交由客户端导入（部分客户端只识别 URL）。<br/>
    更新时间：{summary.get('updated','')}
    </div>
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

    print("并发 TCP 测速…")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    tested = loop.run_until_complete(test_all_tcp(nodes))

    # 各协议分组 & 截断
    by_type: Dict[str, List[Dict]] = {}
    for n in tested:
        t = (n.get("type") or "").lower()
        by_type.setdefault(t, []).append(n)
    for t, lst in by_type.items():
        by_type[t] = sorted(lst, key=lambda x: x.get("delay", 9e9))[:KEEP_TOP_PER_TYPE]

    tcp_ok_nodes = [x for lst in by_type.values() for x in lst]
    avg_ms = avg_delay([n.get("delay",0) for n in tcp_ok_nodes])

    # —— 主订阅（全部 TCP 可用）
    proxy_yaml_path = os.path.join(DOCS_DIR, "proxy.yaml")
    write_yaml(proxy_yaml_path, to_clash_proxies(tcp_ok_nodes))
    with open(proxy_yaml_path, "rb") as f:
        yb = f.read()
    write_base64_sub(os.path.join(DOCS_DIR, "sub"), yb)
    # 主订阅二维码（URL：指向 sub）
    save_qr_to(os.path.join(DOCS_DIR, "qrcode_main.png"), f"{SITE_BASE}/sub", color=(66,133,244))

    # —— 中国大陆可用（SOCKS/HTTP 严格 Google）
    google_ok = []
    if STRICT_CN_GOOGLE:
        print("执行 SOCKS/HTTP Google 严格验证…")
        for n in by_type.get("socks4", []) + by_type.get("socks5", []) + by_type.get("http", []):
            if google_via_socks_http(n):
                google_ok.append(n)
        path_cn = os.path.join(DOCS_DIR, "proxy_cn_google.yaml")
        write_yaml(path_cn, to_clash_proxies(google_ok))
        save_qr_to(os.path.join(DOCS_DIR, "qrcode_cn_google.png"),
                   f"{SITE_BASE}/proxy_cn_google.yaml", color=(66,133,244))

    # —— 导出各协议“整包” + 双二维码
    per_proto_all_cards = []
    for proto in ("ss","vmess","trojan","vless","socks4","socks5","http"):
        lst = by_type.get(proto, [])
        all_path = os.path.join(DOCS_DIR, f"{proto}.yaml")
        write_yaml(all_path, to_clash_proxies(lst))
        url_page = f"{SITE_BASE}/{proto}.yaml"
        url_raw  = f"{RAW_BASE}/{proto}.yaml"

        # URL 型 QR（蓝）
        url_qr_path = os.path.join(QRS_DIR, f"{proto}_all_url.png")
        save_qr_to(url_qr_path, url_page, color=(66,133,244))

        # 内嵌型 QR（绿），容量判断
        with open(all_path, "rb") as f:
            yb = f.read()
        data_uri = f"data:text/plain;base64,{base64.b64encode(yb).decode('utf-8')}"
        if len(data_uri.encode("utf-8")) <= EMBED_MAX_BYTES:
            embed_qr_path = os.path.join(QRS_DIR, f"{proto}_all_embed.png")
            save_qr_to(embed_qr_path, data_uri, color=(16,185,129))
            embed_img = f"{SITE_BASE}/qrs/{proto}_all_embed.png"
        else:
            embed_img = None

        per_proto_all_cards.append({
            "title": f"{proto}.yaml",
            "count": len(lst),
            "url_page": url_page,
            "url_raw": url_raw,
            "qr_url_img": f"{SITE_BASE}/qrs/{proto}_all_url.png",
            "qr_embed_img": embed_img,
            "embed_fallback": (embed_img is None),
        })

    # —— 按协议分批导出 + 双二维码
    per_proto_batches = {}
    for proto in ("ss","vmess","trojan","vless","socks4","socks5","http"):
        per_proto_batches[proto] = export_batches(proto, by_type.get(proto, []))

    # —— 另存一份 proxy_all.yaml（别名）
    write_yaml(os.path.join(DOCS_DIR, "proxy_all.yaml"), to_clash_proxies(tcp_ok_nodes))

    # —— 页面
    summary = {
        "updated": now_str_beijing(),
        "collected": collected,
        "tcp_ok": len(tcp_ok_nodes),
        "google_ok": len(google_ok),
        "avg_delay": avg_ms
    }
    html = build_index_html(summary, per_proto_all_cards, per_proto_batches)
    write_text(os.path.join(DOCS_DIR, "index.html"), html)

    print(f"完成：初步收集 {collected}，TCP可用 {len(tcp_ok_nodes)}，Google可用 {len(google_ok)}，平均延迟 {avg_ms}ms")
    print("已生成：主订阅/子订阅、各协议整包 + 批次 YAML、双二维码、统计页。")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("运行异常：", e)
        traceback.print_exc()
        sys.exit(1)
