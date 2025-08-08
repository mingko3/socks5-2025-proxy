#!/usr/bin/env python3
# generate.py
# 功能：抓取多个免费订阅源 -> 解析 SS/VMess/Trojan -> 去重/测速/归类 -> 生成 Clash YAML、Base64 合并订阅、单协议文件、二维码、页面

import os
import re
import json
import time
import socket
import base64
import yaml
import requests
import qrcode
from datetime import datetime
from urllib.parse import quote, unquote
from pathlib import Path

# -------------------------
# 配置区（你可以在这里添加/删除源）
# 我加入了你之前提到的常见源与一些社区常见 raw 链接
# 如果你想我再去网上找并验证更多源，请说一声，我会爬取并补充
# -------------------------
SOURCES = [
    # 用户之前提供或常见的订阅源
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/Shadowsocks.txt",
    "https://raw.githubusercontent.com/freefq/free/master/shadowsocks",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/shadowsocks",
    "https://raw.githubusercontent.com/freefq/free/master/clash.yaml",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/clash/clash.yml",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt",
    # 你可以在这里添加更多 raw 链接
]

# 输出目录
OUT = Path("docs")
QRS = OUT / "qrs"
OUT.mkdir(parents=True, exist_ok=True)
QRS.mkdir(parents=True, exist_ok=True)

# 主订阅 URL（供二维码与网页展示用，注意：需要你开启 Pages 并确保路径正确）
GITHUB_PAGES_BASE = "https://mingko3.github.io/socks5-2025-proxy"
MAIN_SUB_URL = f"{GITHUB_PAGES_BASE}/sub"
MAIN_PROXY_YAML_URL = f"{GITHUB_PAGES_BASE}/proxy.yaml"

# 测试连接时的超时（秒）
TCP_TIMEOUT = 1.5

# -------------------------
# 工具函数
# -------------------------
def safe_b64decode(s: str):
    """宽松的 base64 解码（自动补齐 =）"""
    if isinstance(s, str):
        s = s.strip()
        # Replace URL-safe chars
        s = s.replace("-", "+").replace("_", "/")
        padding = (-len(s)) % 4
        if padding:
            s += "=" * padding
        try:
            return base64.b64decode(s)
        except Exception:
            # 最后尝试 urlsafe_b64decode
            try:
                return base64.urlsafe_b64decode(s)
            except Exception:
                raise

def tcp_test(host: str, port: int, timeout=TCP_TIMEOUT):
    """简单 TCP 连接测试，返回延迟 ms 或 None"""
    try:
        start = time.time()
        with socket.create_connection((host, int(port)), timeout=timeout):
            end = time.time()
            return int((end - start) * 1000)
    except Exception:
        return None

def make_strict_qrcode(data: str, filename: str, version=None, box_size=10, border=4):
    """使用严格参数生成二维码，兼容 Shadowrocket"""
    qr = qrcode.QRCode(
        version=version,  # None 或指定整数
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=box_size,
        border=border
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)

def url_is_raw_sub(url: str):
    """判断是不是看起来像 raw 的订阅（不精确）"""
    return any(k in url for k in ["/raw.", "raw.githubusercontent.com", ".txt", ".sub", ".yaml", ".yml"])

# -------------------------
# 解析函数（SS / VMess / Trojan）
# -------------------------
def parse_ss_line(line: str):
    """解析 ss://... 或 ss://base64#name"""
    try:
        # remove fragment
        if "#" in line:
            line = line.split("#", 1)[0]
        if line.startswith("ss://"):
            raw = line[5:]
        else:
            raw = line
        # Some SS use method:password@host:port after base64 decode
        # Try robust decode
        try:
            decoded = safe_b64decode(raw).decode("utf-8")
            # format: method:password@host:port
            if "@" in decoded and ":" in decoded.split("@")[-1]:
                method_password, hostport = decoded.rsplit("@", 1)
                method, password = method_password.split(":", 1)
                host, port = hostport.split(":", 1)
                return {"type":"ss", "server": host, "port": int(port), "cipher": method, "password": password}
            else:
                # Some SS use method:password then base64 for everything else, fallback
                return None
        except Exception:
            # maybe raw is already in form method:pass@host:port (not base64)
            if "@" in raw and ":" in raw.split("@")[-1]:
                method_password, hostport = raw.rsplit("@", 1)
                method, password = method_password.split(":", 1)
                host, port = hostport.split(":", 1)
                return {"type":"ss", "server": host, "port": int(port), "cipher": method, "password": password}
            return None
    except Exception:
        return None

def parse_vmess_line(line: str):
    """解析 vmess://base64"""
    try:
        data = line[len("vmess://"):] if line.startswith("vmess://") else line
        b = safe_b64decode(data)
        conf = json.loads(b.decode(errors="ignore"))
        server = conf.get("add") or conf.get("server") or conf.get("host")
        port = int(conf.get("port", 0))
        return {
            "type":"vmess",
            "server": server,
            "port": port,
            "uuid": conf.get("id") or conf.get("uuid"),
            "ps": conf.get("ps") or conf.get("remark") or "",
            "raw": conf
        }
    except Exception:
        return None

def parse_trojan_line(line: str):
    """解析 trojan://password@host:port#name"""
    try:
        s = line[len("trojan://"):] if line.startswith("trojan://") else line
        password, rest = s.split("@",1)
        hostport = rest.split("#",1)[0]
        host, port = hostport.split(":",1)
        return {"type":"trojan", "server": host, "port": int(port), "password": password}
    except Exception:
        return None

# -------------------------
# 主抓取与解析流程
# -------------------------
raw_nodes = []  # 临时收集原始节点字符串（完整协议链接）
for src in SOURCES:
    try:
        print("Fetching source:", src)
        r = requests.get(src, timeout=15)
        if r.status_code != 200:
            print("  -> HTTP", r.status_code)
            continue
        text = r.text.strip()
        if not text:
            continue

        # If the content seems to be a base64 blob (subscription), try decode into lines
        if ("ss://" not in text and "vmess://" not in text and "trojan://" not in text) and (not url_is_raw_sub(src)):
            # try decode as base64
            try:
                decoded = safe_b64decode(text).decode(errors="ignore")
                lines = [l.strip() for l in decoded.splitlines() if l.strip()]
            except Exception:
                # fallback to split original text
                lines = [l.strip() for l in text.splitlines() if l.strip()]
        else:
            lines = [l.strip() for l in text.splitlines() if l.strip()]

        # collect protocol lines
        for ln in lines:
            if ln.startswith(("ss://","vmess://","trojan://")):
                raw_nodes.append(ln)
            else:
                # some raw lists include "IP:PORT" lines (e.g. roosterkid), try to convert to socks5? we skip raw IP:PORT for now
                # But if it's like 'ip:port' with mention of socks5 or http in same line, we could parse; keep simple for now
                if re.search(r"\d+\.\d+\.\d+\.\d+:\d+", ln):
                    # treat as socks5 text node
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)", ln)
                    if m:
                        ip = m.group(1); port = m.group(2)
                        raw_nodes.append(f"socks5://{ip}:{port}")
    except Exception as e:
        print("  -> source error:", e)

print("Total raw nodes collected:", len(raw_nodes))

# -------------------------
# 解析 raw_nodes -> structured nodes
# -------------------------
nodes = []  # dict items with fields: id, proto, server, port, meta...
seen_keys = set()  # for dedupe: proto+server+port

for raw in raw_nodes:
    n = None
    if raw.startswith("ss://"):
        n = parse_ss_line(raw)
        if n:
            proto = "ss"; server = n["server"]; port = int(n["port"])
            key = f"{proto}|{server}|{port}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            entry = {
                "proto": "ss",
                "server": server,
                "port": port,
                "cipher": n.get("cipher",""),
                "password": n.get("password",""),
                "name": f"SS_{server}_{port}",
            }
            nodes.append(entry)
    elif raw.startswith("vmess://"):
        n = parse_vmess_line(raw)
        if n and n.get("server"):
            proto = "vmess"; server = n["server"]; port = int(n["port"])
            key = f"{proto}|{server}|{port}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            entry = {
                "proto": "vmess",
                "server": server,
                "port": port,
                "uuid": n.get("uuid",""),
                "ps": n.get("ps",""),
                "raw": n.get("raw"),
                "name": n.get("ps") or f"VMESS_{server}_{port}"
            }
            nodes.append(entry)
    elif raw.startswith("trojan://"):
        n = parse_trojan_line(raw)
        if n:
            proto = "trojan"; server = n["server"]; port = int(n["port"])
            key = f"{proto}|{server}|{port}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            entry = {
                "proto": "trojan",
                "server": server,
                "port": port,
                "password": n.get("password",""),
                "name": f"Trojan_{server}_{port}"
            }
            nodes.append(entry)
    elif raw.startswith("socks5://"):
        # treat socks5 as basic type
        try:
            part = raw[len("socks5://"):]
            host, port = part.split(":",1)
            proto="socks5"; key=f"{proto}|{host}|{port}"
            if key in seen_keys: continue
            seen_keys.add(key)
            entry={"proto":"socks5","server":host,"port":int(port),"name":f"SOCKS5_{host}_{port}"}
            nodes.append(entry)
        except: pass
    else:
        # ignore unknown
        pass

print("Total structured nodes (after dedupe):", len(nodes))

# -------------------------
# 节点测试（TCP）与地理位置查询（可选）
# -------------------------
def ip_country_lookup(ip):
    """尝试使用免费 ip geolocation 服务（注意有速率限制），失败则返回 '未知'"""
    try:
        # 使用 ipapi.co 无需 key（有调用限制）
        resp = requests.get(f"https://ipapi.co/{ip}/country_name/", timeout=6)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception:
        pass
    return "未知"

for idx, node in enumerate(nodes):
    server = node.get("server")
    port = node.get("port")
    # 测试延迟
    latency = tcp_test(server, port)
    node["latency_ms"] = latency if latency is not None else -1
    node["ok"] = latency is not None
    # 地区查询（失败时为 "未知"）
    try:
        node["country"] = ip_country_lookup(server)
    except Exception:
        node["country"] = "未知"
    # add index id
    node["id"] = f"{node['proto']}_{idx+1}"

print("Tested nodes sample (first 10):")
for a in nodes[:10]:
    print(a["id"], a["proto"], a["server"], a["port"], "ok" if a["ok"] else "bad", a["latency_ms"], a["country"])

# -------------------------
# 输出：生成 proxy.yaml, sub（base64合并）, 单协议文件, 节点二维码, index.html
# -------------------------
# split lists by proto
ss_list = [n for n in nodes if n["proto"]=="ss"]
vmess_list = [n for n in nodes if n["proto"]=="vmess"]
trojan_list = [n for n in nodes if n["proto"]=="trojan"]
socks5_list = [n for n in nodes if n["proto"]=="socks5"]

# 生成 Clash proxies 格式（简化属性以兼容）
clash_proxies = []
for n in nodes:
    if n["proto"] == "ss":
        clash_proxies.append({
            "name": n["name"],
            "type": "ss",
            "server": n["server"],
            "port": n["port"],
            "cipher": n.get("cipher",""),
            "password": n.get("password",""),
            "udp": True
        })
    elif n["proto"] == "vmess":
        # minimal vmess entry
        clash_proxies.append({
            "name": n.get("name","vmess"),
            "type": "vmess",
            "server": n["server"],
            "port": n["port"],
            "uuid": n.get("uuid",""),
            "alterId": 0,
            "cipher": "auto",
            "tls": True if n.get("raw",{}).get("tls") else False
        })
    elif n["proto"] == "trojan":
        clash_proxies.append({
            "name": n["name"],
            "type": "trojan",
            "server": n["server"],
            "port": n["port"],
            "password": n.get("password",""),
            "udp": True
        })
    elif n["proto"] == "socks5":
        clash_proxies.append({
            "name": n["name"],
            "type": "socks5",
            "server": n["server"],
            "port": n["port"],
            "udp": False
        })

clash_config = {
    "mixed-port": 0,
    "allow-lan": False,
    "log-level": "info",
    "proxies": clash_proxies,
    "proxy-groups": [
        {
            "name":"🚀 节点自动选择",
            "type":"url-test",
            "url":"http://www.gstatic.com/generate_204",
            "interval":300,
            "proxies":[p["name"] for p in clash_proxies] + ["DIRECT"]
        }
    ],
    "rules":["MATCH,🚀 节点自动选择"]
}

with open(OUT / "proxy.yaml","w",encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True, default_flow_style=False)

# 生成 base64 混合订阅（写成 plain 链接，每行一个节点链接；客户端通常接受 base64 blob 或 plain list）
lines = []
for n in ss_list:
    raw = f"{n['cipher']}:{n['password']}@{n['server']}:{n['port']}"
    encoded = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
    lines.append(f"ss://{encoded}#{quote(n['name'])}")
for n in vmess_list:
    conf = {
        "v":"2","ps":n.get("name","vmess"), "add":n["server"], "port":str(n["port"]),
        "id": n.get("uuid",""), "aid": "0", "net": n.get("raw",{}).get("net","tcp"),
        "type":"none", "host": n.get("raw",{}).get("host",""), "path": n.get("raw",{}).get("path","/"), "tls": n.get("raw",{}).get("tls", "")
    }
    b = base64.b64encode(json.dumps(conf, separators=(",",":")).encode()).decode()
    lines.append(f"vmess://{b}")
for n in trojan_list:
    lines.append(f"trojan://{n.get('password','')}@{n['server']}:{n['port']}#{quote(n['name'])}")
for n in socks5_list:
    lines.append(f"socks5://{n['server']}:{n['port']}#{quote(n['name'])}")

# save sub as plain list (not wrapped) and also provide base64-blob version
with open(OUT / "sub", "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

# also write per-protocol files
with open(OUT / "ss.txt","w",encoding="utf-8") as f:
    f.write("\n".join([l for l in lines if l.startswith("ss://")]))
with open(OUT / "vmess.txt","w",encoding="utf-8") as f:
    f.write("\n".join([l for l in lines if l.startswith("vmess://")]))
with open(OUT / "trojan.txt","w",encoding="utf-8") as f:
    f.write("\n".join([l for l in lines if l.startswith("trojan://")]))

# 生成主订阅二维码（使用严格参数）
make_strict_qrcode(MAIN_SUB_URL, str(OUT / "qrcode.png"))

# 为每个节点生成二维码（采用严格参数）
for n in nodes:
    proto = n["proto"]
    if proto == "ss":
        raw = f"{n['cipher']}:{n['password']}@{n['server']}:{n['port']}"
        s = "ss://" + base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=") + "#" + quote(n["name"])
    elif proto == "vmess":
        conf = n.get("raw") or {}
        # ensure minimal conf
        conf2 = {
            "v": "2", "ps": n.get("name","vmess"), "add": n["server"], "port": str(n["port"]),
            "id": n.get("uuid",""), "aid": "0",
            "net": conf.get("net","tcp"), "type": "none", "host": conf.get("host",""), "path": conf.get("path",""), "tls": conf.get("tls","")
        }
        s = "vmess://" + base64.b64encode(json.dumps(conf2, separators=(",",":")).encode()).decode()
    elif proto == "trojan":
        s = f"trojan://{n.get('password','')}@{n['server']}:{n['port']}#{quote(n['name'])}"
    elif proto == "socks5":
        s = f"socks5://{n['server']}:{n['port']}#{quote(n['name'])}"
    else:
        continue

    fname = f"{proto}_{n['server'].replace('.','_')}_{n['port']}.png"
    try:
        make_strict_qrcode(s, str(QRS / fname))
        n["qr"] = f"qrs/{fname}"
    except Exception as e:
        print("QR save failed", e)
        n["qr"] = ""

# -------------------------
# 生成美化 index.html 页面（分类、显示国家、延迟、二维码）
# -------------------------
def human_latency(ms):
    if ms < 0:
        return "不可用"
    return f"{ms} ms"

now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

html = f"""<!doctype html>
<html lang="zh">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>订阅中心 - socks5-2025-proxy</title>
  <style>
    body{{font-family: Arial, Helvetica, sans-serif; background:#f7f9fb; color:#222; padding:20px;}}
    .card{{background:#fff; border-radius:8px; padding:18px; box-shadow:0 2px 8px rgba(0,0,0,0.06); margin-bottom:18px;}}
    .qr-main{{text-align:center;}}
    .grid{{display:grid; grid-template-columns: repeat(auto-fill,minmax(240px,1fr)); gap:12px; margin-top:12px;}}
    .node{{border:1px solid #eee; padding:10px; border-radius:6px; background:#fff; text-align:center;}}
    .node img{{max-width:160px;}}
    .meta{{
      font-size:13px; color:#666; margin-top:6px;
    }}
    .tag{{display:inline-block; padding:3px 8px; background:#f0f4ff; color:#0366d6; border-radius:12px; font-size:12px; margin:2px;}}
    .copy{{cursor:pointer; color:#0366d6; text-decoration:underline;}}
  </style>
</head>
<body>
  <h1>订阅中心</h1>
  <div class="card qr-main">
    <h2>主订阅（合并）</h2>
    <p>Base64 订阅（全部节点）：<a href="{MAIN_SUB_URL}" target="_blank">{MAIN_SUB_URL}</a></p>
    <p>Clash YAML：<a href="{MAIN_PROXY_YAML_URL}" target="_blank">{MAIN_PROXY_YAML_URL}</a></p>
    <div>
      <img src="qrcode.png" alt="订阅二维码" style="width:220px;">
    </div>
    <p class="meta">请使用 Shadowrocket/Clash 等客户端扫码导入（若扫码失败，请复制链接粘贴）</p>
  </div>

  <div class="card">
    <h3>节点统计</h3>
    <div class="tag">全部：{len(nodes)}</div>
    <div class="tag">SS：{len(ss_list)}</div>
    <div class="tag">VMess：{len(vmess_list)}</div>
    <div class="tag">Trojan：{len(trojan_list)}</div>
    <div class="tag">Socks5：{len(socks5_list)}</div>
    <p style="color:#666; margin-top:8px;">最后更新：{now}</p>
  </div>

  <div class="card">
    <h3>节点列表（按协议分组）</h3>
    <h4>SS 节点</h4>
    <div class="grid">
"""
# SS nodes
for n in ss_list:
    html += f"""
    <div class="node">
      <strong>{n['name']}</strong><br>
      <img src="{n.get('qr','')}" alt="qr"><br>
      <div class="meta">地址：{n['server']}:{n['port']}<br>延迟：{human_latency(n['latency_ms'])}<br>国家：{n.get('country','未知')}</div>
    </div>
    """

html += "<h4>VMess 节点</h4><div class='grid'>"
for n in vmess_list:
    html += f"""
    <div class="node">
      <strong>{n.get('name','')}</strong><br>
      <img src="{n.get('qr','')}" alt="qr"><br>
      <div class="meta">地址：{n['server']}:{n['port']}<br>延迟：{human_latency(n['latency_ms'])}<br>国家：{n.get('country','未知')}</div>
    </div>
    """
html += "</div>"

html += "<h4>Trojan 节点</h4><div class='grid'>"
for n in trojan_list:
    html += f"""
    <div class="node">
      <strong>{n.get('name','')}</strong><br>
      <img src="{n.get('qr','')}" alt="qr"><br>
      <div class="meta">地址：{n['server']}:{n['port']}<br>延迟：{human_latency(n['latency_ms'])}<br>国家：{n.get('country','未知')}</div>
    </div>
    """
html += "</div>"

html += "<h4>Socks5 节点</h4><div class='grid'>"
for n in socks5_list:
    html += f"""
    <div class="node">
      <strong>{n.get('name','')}</strong><br>
      <img src="{n.get('qr','')}" alt="qr"><br>
      <div class="meta">地址：{n['server']}:{n['port']}<br>延迟：{human_latency(n['latency_ms'])}<br>国家：{n.get('country','未知')}</div>
    </div>
    """
html += "</div>"

html += """
  </div>
  <footer style="margin-top:18px; color:#999; font-size:13px;">自动生成 &nbsp;|&nbsp; 注意：节点来自公共免费源，可能不稳定或不可用。请勿用于非法用途。</footer>
</body>
</html>
"""

with open(OUT / "index.html","w",encoding="utf-8") as f:
    f.write(html)

print("Generation finished. Files in docs/: proxy.yaml, sub, ss.txt, vmess.txt, trojan.txt, qrcode.png, qrs/*.png, index.html")
