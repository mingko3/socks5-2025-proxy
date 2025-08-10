import requests
import base64
import yaml
import os
import re
import qrcode
import json
import asyncio
import socket
from urllib.parse import unquote
from datetime import datetime

# ==============================
# 配置部分
# ==============================
OUTPUT_DIR = "docs"
QR_DIR = os.path.join(OUTPUT_DIR, "qrs")
os.makedirs(QR_DIR, exist_ok=True)

# 订阅源列表（多协议）
SUB_LINKS = [
    # Shadowsocks Base64 / 文本
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/Shadowsocks.txt",
    "https://raw.githubusercontent.com/freefq/free/master/shadowsocks",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/shadowsocks",

    # Clash YAML
    "https://raw.githubusercontent.com/freefq/free/master/clash.yaml",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/clash/clash.yml",

    # roosterkid 源
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt"
]

TEST_TIMEOUT = 1.5  # 秒
CONCURRENCY = 200   # 并发任务数

# ==============================
# 节点解析函数
# ==============================
def parse_ss(link):
    try:
        if '#' in link:
            link = link.split('#')[0]
        link = link[len('ss://'):]
        missing_padding = len(link) % 4
        if missing_padding:
            link += '=' * (4 - missing_padding)
        decoded = base64.urlsafe_b64decode(link).decode()
        method, rest = decoded.split(':', 1)
        password, server_port = rest.rsplit('@', 1)
        server, port = server_port.split(':')
        return {"name": f"SS_{server}_{port}", "type": "ss", "server": server, "port": int(port), "cipher": method, "password": password, "udp": True}
    except:
        return None

def parse_vmess(link):
    try:
        data = link[len("vmess://"):]
        decoded = base64.b64decode(data + '===').decode()
        conf = json.loads(decoded)
        return {"name": conf.get("ps", "vmess"), "type": "vmess", "server": conf.get("add"), "port": int(conf.get("port")), "uuid": conf.get("id"), "alterId": int(conf.get("aid", 0)), "cipher": "auto", "tls": conf.get("tls", False), "network": conf.get("net"), "ws-opts": {"path": conf.get("path", "/"), "headers": {"Host": conf.get("host", "")}}}
    except:
        return None

def parse_trojan(link):
    try:
        content = link[len("trojan://"):]
        password, rest = content.split("@")
        server_port = rest.split("#")[0]
        server, port = server_port.split(":")
        return {"name": f"Trojan_{server}_{port}", "type": "trojan", "server": server, "port": int(port), "password": password, "udp": True}
    except:
        return None

def parse_socks(link, t="socks5"):
    try:
        link = link.split("#")[0]
        content = link[len(f"{t}://"):]
        if '@' in content:
            auth, server_port = content.split("@")
            user, pwd = auth.split(":")
        else:
            server_port = content
        server, port = server_port.split(":")
        return {"name": f"{t.upper()}_{server}_{port}", "type": t, "server": server, "port": int(port), "udp": True}
    except:
        return None

# ==============================
# 测速函数
# ==============================
async def tcp_ping(host, port):
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=TEST_TIMEOUT)
        writer.close()
        return True
    except:
        return False

async def test_nodes(nodes):
    sem = asyncio.Semaphore(CONCURRENCY)
    results = []

    async def test_one(node):
        async with sem:
            ok = await tcp_ping(node["server"], node["port"])
            if ok:
                results.append(node)

    await asyncio.gather(*(test_one(n) for n in nodes))
    return results

# ==============================
# 主流程
# ==============================
print("开始抓取源...")
all_nodes = []

for url in SUB_LINKS:
    try:
        res = requests.get(url, timeout=10)
        content = res.text.strip()

        if content.startswith("proxies:") or ".yaml" in url or ".yml" in url:
            try:
                data = yaml.safe_load(content)
                for p in data.get("proxies", []):
                    all_nodes.append(p)
            except:
                pass
        else:
            try:
                if "://" not in content:
                    decoded = base64.b64decode(content + "===").decode(errors="ignore")
                    lines = decoded.splitlines()
                else:
                    lines = content.splitlines()
            except:
                lines = content.splitlines()

            for line in lines:
                node = None
                if line.startswith("ss://"):
                    node = parse_ss(line)
                elif line.startswith("vmess://"):
                    node = parse_vmess(line)
                elif line.startswith("trojan://"):
                    node = parse_trojan(line)
                elif line.startswith("socks5://"):
                    node = parse_socks(line, "socks5")
                elif line.startswith("socks4://"):
                    node = parse_socks(line, "socks4")

                if node:
                    all_nodes.append(node)
    except Exception as e:
        print(f"抓取失败 {url}: {e}")

print(f"共解析 {len(all_nodes)} 个节点，开始测速...")
all_nodes = asyncio.run(test_nodes(all_nodes))
print(f"测速完成，可用节点数: {len(all_nodes)}")

# ==============================
# 按协议分组
# ==============================
groups = {}
for n in all_nodes:
    groups.setdefault(n["type"], []).append(n)

# 保存分组订阅和二维码
BASE_URL = "https://mingko3.github.io/socks5-2025-proxy"

for proto, nodes in groups.items():
    clash_data = {"proxies": nodes, "proxy-groups": [], "rules": ["MATCH,DIRECT"]}
    clash_file = os.path.join(OUTPUT_DIR, f"{proto}.yaml")
    with open(clash_file, "w", encoding="utf-8") as f:
        yaml.dump(clash_data, f, allow_unicode=True)
    sub_url = f"{BASE_URL}/{proto}.yaml"
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_Q)
    qr.add_data(sub_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(os.path.join(QR_DIR, f"{proto}.png"))

# 主订阅
main_clash = {"proxies": all_nodes, "proxy-groups": [], "rules": ["MATCH,DIRECT"]}
with open(os.path.join(OUTPUT_DIR, "proxy.yaml"), "w", encoding="utf-8") as f:
    yaml.dump(main_clash, f, allow_unicode=True)
main_url = f"{BASE_URL}/proxy.yaml"
main_qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_Q)
main_qr.add_data(main_url)
main_qr.make(fit=True)
img = main_qr.make_image(fill_color="black", back_color="white")
img.save(os.path.join(OUTPUT_DIR, "sub_qr.png"))

# ==============================
# 生成 index.html
# ==============================
update_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>代理订阅</title>
<style>
body {{ font-family: Arial; background: #f4f4f4; text-align: center; }}
.card {{ background: white; padding: 20px; margin: 20px auto; border-radius: 10px; max-width: 600px; }}
</style>
</head>
<body>
<h1>代理订阅</h1>
<p>最后更新时间：{update_time}</p>
<div class="card">
<h2>主订阅</h2>
<p><a href="{main_url}">{main_url}</a></p>
<img src="sub_qr.png" width="200">
</div>
"""

for proto in groups:
    html += f"""
    <div class="card">
    <h2>{proto.upper()} 节点订阅</h2>
    <p><a href="{BASE_URL}/{proto}.yaml">{BASE_URL}/{proto}.yaml</a></p>
    <img src="qrs/{proto}.png" width="200">
    <p>节点数量: {len(groups[proto])}</p>
    </div>
    """

html += "</body></html>"

with open(os.path.join(OUTPUT_DIR, "index.html"), "w", encoding="utf-8") as f:
    f.write(html)

print("全部完成！")
