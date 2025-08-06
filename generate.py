import os
import base64
import requests
import yaml
import json
import qrcode
from urllib.parse import quote
from datetime import datetime
from pathlib import Path

# 创建输出目录
Path("docs/qrs").mkdir(parents=True, exist_ok=True)

# 订阅地址
CLASH_URL = "https://mingko3.github.io/socks5-2025-proxy/proxy.yaml"
BASE64_URL = "https://mingko3.github.io/socks5-2025-proxy/sub"

# 创建主二维码（必须完整 URL，确保 Shadowrocket 可识别）
def make_strict_qrcode(data, filename):
    qr = qrcode.QRCode(
        version=5,
        error_correction=qrcode.constants.ERROR_CORRECT_H,  # 使用高纠错等级
        box_size=10,
        border=4  # 添加足够边距，便于识别
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image()
    img.save(filename)

make_strict_qrcode(BASE64_URL, "docs/qrcode.png")

# 节点订阅源（示例）
sources = [
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/freefq/free/master/shadowsocks",
]

# 节点分类存储
ss_nodes, vmess_nodes, trojan_nodes = [], [], []

def parse_ss(ssstr):
    try:
        if not ssstr.startswith("ss://"):
            return None
        if "#" in ssstr:
            ssstr = ssstr.split("#")[0]
        ssstr = ssstr[5:]
        padding = 4 - len(ssstr) % 4
        if padding:
            ssstr += "=" * padding
        decoded = base64.urlsafe_b64decode(ssstr).decode()
        method, rest = decoded.split(":", 1)
        password, server_port = rest.rsplit("@", 1)
        server, port = server_port.split(":")
        return {
            "name": f"ss_{server}_{port}",
            "type": "ss",
            "server": server,
            "port": int(port),
            "cipher": method,
            "password": password,
            "udp": True,
        }
    except:
        return None

def parse_vmess(link):
    try:
        data = link[8:]
        padding = 4 - len(data) % 4
        if padding:
            data += "=" * padding
        js = json.loads(base64.b64decode(data).decode())
        return {
            "name": js.get("ps", "vmess"),
            "type": "vmess",
            "server": js["add"],
            "port": int(js["port"]),
            "uuid": js["id"],
            "alterId": int(js.get("aid", 0)),
            "cipher": "auto",
            "tls": js.get("tls", ""),
            "network": js.get("net", ""),
            "ws-opts": {
                "path": js.get("path", "/"),
                "headers": {"Host": js.get("host", "")},
            },
        }
    except:
        return None

def parse_trojan(link):
    try:
        content = link[len("trojan://"):]
        password, rest = content.split("@")
        server, port = rest.split(":")[0:2]
        return {
            "name": f"trojan_{server}_{port}",
            "type": "trojan",
            "server": server,
            "port": int(port),
            "password": password,
            "udp": True,
        }
    except:
        return None

# 处理订阅
for src in sources:
    try:
        res = requests.get(src, timeout=15)
        content = res.text
        lines = (
            base64.b64decode(content + "===").decode().splitlines()
            if "://" not in content
            else content.strip().splitlines()
        )

        for line in lines:
            if line.startswith("ss://"):
                node = parse_ss(line)
                if node:
                    ss_nodes.append(node)
            elif line.startswith("vmess://"):
                node = parse_vmess(line)
                if node:
                    vmess_nodes.append(node)
            elif line.startswith("trojan://"):
                node = parse_trojan(line)
                if node:
                    trojan_nodes.append(node)
    except Exception as e:
        print(f"源出错：{src} -> {e}")

# 合并 Clash 配置
proxy = ss_nodes + vmess_nodes + trojan_nodes
with open("docs/proxy.yaml", "w", encoding="utf-8") as f:
    yaml.dump({"proxies": proxy}, f, allow_unicode=True)

# 输出 Base64 订阅
ss_links = [
    "ss://" + base64.urlsafe_b64encode(
        f"{n['cipher']}:{n['password']}@{n['server']}:{n['port']}".encode()
    ).decode()
    for n in ss_nodes
]
vmess_links = [
    "vmess://" + base64.b64encode(
        json.dumps({
            "v": "2",
            "ps": n["name"],
            "add": n["server"],
            "port": str(n["port"]),
            "id": n["uuid"],
            "aid": str(n["alterId"]),
            "net": n["network"],
            "type": "none",
            "host": n["ws-opts"]["headers"].get("Host", ""),
            "path": n["ws-opts"].get("path", ""),
            "tls": n["tls"],
        }).encode()
    ).decode()
    for n in vmess_nodes
]
trojan_links = [
    f"trojan://{n['password']}@{n['server']}:{n['port']}#{quote(n['name'])}"
    for n in trojan_nodes
]

with open("docs/sub", "w", encoding="utf-8") as f:
    f.write(base64.b64encode(("\n".join(ss_links + vmess_links + trojan_links)).encode()).decode())

# 生成每个节点二维码
def save_qr(text, name):
    img = qrcode.make(text)
    path = f"docs/qrs/{name}.png"
    img.save(path)

for node in ss_links + vmess_links + trojan_links:
    proto = node.split("://")[0]
    name = node.split("://")[1][:40].replace("/", "_").replace("=", "_")
    save_qr(node, f"{proto}_{name}")

# 更新网页 index.html
with open("docs/index.html", "w", encoding="utf-8") as f:
    f.write(f"""<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>订阅分享</title>
    <style>
        body {{ font-family: sans-serif; background: #f6f6f6; padding: 30px; }}
        h1 {{ text-align: center; }}
        .qr-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 20px; margin-top: 30px; }}
        .item {{ background: white; padding: 10px; border: 1px solid #ccc; text-align: center; }}
        img {{ max-width: 100%; }}
    </style>
</head>
<body>
    <h1>📡 节点订阅分享</h1>
    <p>📄 Clash 配置文件：<br><a href="{CLASH_URL}">{CLASH_URL}</a></p>
    <p>📦 Base64 订阅链接：<br><a href="{BASE64_URL}">{BASE64_URL}</a></p>
    <p>📷 扫码订阅链接</p>
    <img src="qrcode.png" width="200"><br>
    <h2>📍 每个节点二维码</h2>
    <div class="qr-grid">
""")
    for img in os.listdir("docs/qrs"):
        f.write(f'<div class="item"><img src="qrs/{img}"><br>{img}</div>\n')
    f.write(f"""
    </div>
    <p style="text-align:center;margin-top:20px;">最后更新：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}（自动部署）</p>
</body>
</html>
""")
