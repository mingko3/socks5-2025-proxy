import requests
import base64
import yaml
import os
import re
import qrcode
import json
import socket
from urllib.parse import unquote
from datetime import datetime

# ======== 配置 ========
OUTPUT_DIR = "docs"
QR_DIR = os.path.join(OUTPUT_DIR, "qrs")
os.makedirs(QR_DIR, exist_ok=True)

# 所有订阅源
SUB_LINKS = [
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
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt"
]

# ======== 协议解析 ========
def parse_ss(link):
    try:
        link = link.strip()
        if link.startswith("ss://"):
            link = link[5:]
        if '#' in link:
            link = link.split('#')[0]
        padding = len(link) % 4
        if padding:
            link += "=" * (4 - padding)
        decoded = base64.urlsafe_b64decode(link).decode()
        method, rest = decoded.split(':', 1)
        password, server_port = rest.rsplit('@', 1)
        server, port = server_port.split(':')
        return {"name": f"SS_{server}", "type": "ss", "server": server, "port": int(port), "cipher": method, "password": password}
    except:
        return None

def parse_vmess(link):
    try:
        data = link[len("vmess://"):]
        padding = len(data) % 4
        if padding:
            data += "=" * (4 - padding)
        decoded = base64.b64decode(data).decode()
        conf = json.loads(decoded)
        return {
            "name": conf.get("ps", "vmess"),
            "type": "vmess",
            "server": conf.get("add"),
            "port": int(conf.get("port")),
            "uuid": conf.get("id"),
            "alterId": int(conf.get("aid", 0)),
            "cipher": "auto",
            "tls": conf.get("tls", False)
        }
    except:
        return None

def parse_trojan(link):
    try:
        content = link[len("trojan://"):]
        password, rest = content.split("@")
        server, port = rest.split(":")
        return {"name": f"Trojan_{server}", "type": "trojan", "server": server, "port": int(port), "password": password}
    except:
        return None

# ======== 测速 ========
def test_node(server, port, timeout=1.5):
    try:
        with socket.create_connection((server, int(port)), timeout=timeout):
            return True
    except:
        return False

# ======== 抓取并分类 ========
nodes_by_type = {"ss": [], "vmess": [], "trojan": [], "other": []}

print("开始抓取源...")
for url in SUB_LINKS:
    try:
        res = requests.get(url, timeout=10)
        content = res.text.strip()

        if content.startswith("proxies:") or ".yaml" in url or ".yml" in url:
            try:
                data = yaml.safe_load(content)
                for p in data.get("proxies", []):
                    if p.get("server") and p.get("port"):
                        if test_node(p["server"], p["port"]):
                            nodes_by_type[p.get("type", "other")].append(p)
            except:
                continue
        else:
            if '://' not in content:
                try:
                    content = base64.b64decode(content + '===').decode(errors="ignore")
                except:
                    pass
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                node = None
                if line.startswith("ss://"):
                    node = parse_ss(line)
                    if node and test_node(node['server'], node['port']):
                        nodes_by_type["ss"].append(node)
                elif line.startswith("vmess://"):
                    node = parse_vmess(line)
                    if node and test_node(node['server'], node['port']):
                        nodes_by_type["vmess"].append(node)
                elif line.startswith("trojan://"):
                    node = parse_trojan(line)
                    if node and test_node(node['server'], node['port']):
                        nodes_by_type["trojan"].append(node)
    except Exception as e:
        print(f"Error fetching {url}: {e}")

total_count = sum(len(v) for v in nodes_by_type.values())
print(f"总数: {total_count}")

# ======== 生成订阅文件 ========
MAIN_SUB_URL = "https://mingko3.github.io/socks5-2025-proxy/sub"
main_qr = qrcode.make(MAIN_SUB_URL)
main_qr.save(os.path.join(OUTPUT_DIR, "qrcode.png"))

# 按类型生成单独订阅
for proto, node_list in nodes_by_type.items():
    if not node_list:
        continue
    proto_file = os.path.join(OUTPUT_DIR, f"{proto}.txt")
    with open(proto_file, "w", encoding="utf-8") as f:
        for n in node_list:
            if proto == "ss":
                raw = f"{n['cipher']}:{n['password']}@{n['server']}:{n['port']}"
                f.write("ss://" + base64.b64encode(raw.encode()).decode() + "\n")
            elif proto == "vmess":
                vmess_json = base64.b64encode(json.dumps(n).encode()).decode()
                f.write("vmess://" + vmess_json + "\n")
            elif proto == "trojan":
                f.write(f"trojan://{n['password']}@{n['server']}:{n['port']}\n")
    # 二维码
    qr = qrcode.make(f"{MAIN_SUB_URL}/{proto}.txt")
    qr.save(os.path.join(QR_DIR, f"{proto}.png"))

# ======== 生成网页 ========
update_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
html = f"""
<html>
<head>
    <meta charset="utf-8">
    <title>订阅中心</title>
</head>
<body>
    <h1>订阅中心</h1>
    <p style="color:green;font-weight:bold;">更新时间: {update_time}</p>
    <h2>总订阅</h2>
    <img src="qrcode.png" width="150"><br>
    <a href="{MAIN_SUB_URL}">{MAIN_SUB_URL}</a>
    <h2>分类订阅</h2>
    <ul>
"""
for proto in nodes_by_type.keys():
    file_path = f"{proto}.txt"
    if os.path.exists(os.path.join(OUTPUT_DIR, file_path)):
        html += f"<li>{proto.upper()} <a href='{file_path}'>{file_path}</a> <img src='qrs/{proto}.png' width='120'></li>"
html += """
    </ul>
</body>
</html>
"""

with open(os.path.join(OUTPUT_DIR, "index.html"), "w", encoding="utf-8") as f:
    f.write(html)

print("生成完成 ✅")
