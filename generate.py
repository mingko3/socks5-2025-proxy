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

SUB_LINKS = [
    # SS Base64 源
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/Shadowsocks.txt",
    "https://raw.githubusercontent.com/freefq/free/master/shadowsocks",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/shadowsocks",
    # Clash YAML 源
    "https://raw.githubusercontent.com/freefq/free/master/clash.yaml",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/clash/clash.yml",
    # Roosterkid 源
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt"
]

def test_node(server, port):
    try:
        with socket.create_connection((server, int(port)), timeout=1.5):
            return True
    except:
        return False

def parse_ss(link):
    try:
        if '#' in link:
            link = link.split('#')[0]
        link = link[len('ss://'):] if link.startswith('ss://') else link
        padding = len(link) % 4
        if padding: link += '=' * (4 - padding)
        decoded = base64.urlsafe_b64decode(link).decode()
        method, rest = decoded.split(':', 1)
        password, server_port = rest.rsplit('@', 1)
        server, port = server_port.split(':')
        return {
            "name": f"SS_{server}_{port}",
            "type": "ss",
            "server": server,
            "port": int(port),
            "cipher": method,
            "password": password,
            "udp": True
        }
    except:
        return None

def parse_vmess(link):
    try:
        data = link[len("vmess://"):]
        decoded = base64.b64decode(data + '===').decode()
        conf = json.loads(decoded)
        return {
            "name": conf.get("ps", "vmess"),
            "type": "vmess",
            "server": conf.get("add"),
            "port": int(conf.get("port")),
            "uuid": conf.get("id"),
            "alterId": int(conf.get("aid", 0)),
            "cipher": "auto",
            "tls": conf.get("tls", False),
            "network": conf.get("net"),
            "ws-opts": {
                "path": conf.get("path", "/"),
                "headers": {"Host": conf.get("host", "")}
            }
        }
    except:
        return None

def parse_trojan(link):
    try:
        content = link[len("trojan://"):]
        password, rest = content.split("@")
        server, port = rest.split(":")
        port = port.split("#")[0]
        return {
            "name": f"Trojan_{server}_{port}",
            "type": "trojan",
            "server": server,
            "port": int(port),
            "password": password,
            "udp": True
        }
    except:
        return None

ss_nodes, vmess_nodes, trojan_nodes = [], [], []

for url in SUB_LINKS:
    try:
        print(f"Fetching: {url}")
        res = requests.get(url, timeout=10)
        content = res.text.strip()

        if content.startswith("proxies:") or ".yaml" in url or ".yml" in url:
            try:
                data = yaml.safe_load(content)
                for p in data.get("proxies", []):
                    if p.get("type") == "ss" and test_node(p['server'], p['port']):
                        ss_nodes.append(p)
                    elif p.get("type") == "vmess" and test_node(p['server'], p['port']):
                        vmess_nodes.append(p)
                    elif p.get("type") == "trojan" and test_node(p['server'], p['port']):
                        trojan_nodes.append(p)
            except:
                continue
        else:
            lines = base64.b64decode(content + '===').decode(errors="ignore").splitlines() if '://' not in content else content.splitlines()
            for line in lines:
                line = line.strip()
                if line.startswith("ss://"):
                    n = parse_ss(line)
                    if n and test_node(n['server'], n['port']):
                        ss_nodes.append(n)
                elif line.startswith("vmess://"):
                    n = parse_vmess(line)
                    if n and test_node(n['server'], n['port']):
                        vmess_nodes.append(n)
                elif line.startswith("trojan://"):
                    n = parse_trojan(line)
                    if n and test_node(n['server'], n['port']):
                        trojan_nodes.append(n)
    except Exception as e:
        print(f"Error: {e}")

# 构建 clash.yaml
all_nodes = ss_nodes + vmess_nodes + trojan_nodes
config = {
    "proxies": all_nodes,
    "proxy-groups": [{
        "name": "🚀 自动选择",
        "type": "url-test",
        "url": "http://www.gstatic.com/generate_204",
        "interval": 300,
        "tolerance": 50,
        "proxies": [n["name"] for n in all_nodes]
    }]
}

# 输出目录
os.makedirs("docs/qrs", exist_ok=True)

# 生成 proxy.yaml
with open("docs/proxy.yaml", "w", encoding="utf-8") as f:
    yaml.dump(config, f, allow_unicode=True)

# 生成 base64 sub
with open("docs/proxy.yaml", "rb") as f:
    b64 = base64.b64encode(f.read()).decode()
    with open("docs/sub", "w", encoding="utf-8") as o:
        o.write(b64)

# 主订阅二维码
img = qrcode.make("https://mingko3.github.io/socks5-2025-proxy/sub")
img.save("docs/sub_qr.png")

# 单个节点二维码 + 收集 info
card_html = ""
for n in all_nodes:
    info = f"{n['type']}://{n['server']}:{n['port']}"
    qr_img = qrcode.make(info)
    name = n['name'].replace(":", "_").replace("/", "_")
    qr_path = f"docs/qrs/{name}.png"
    qr_img.save(qr_path)
    card_html += f'''
    <div class="card">
        <h4>{n["name"]}</h4>
        <p>协议: {n["type"]}</p>
        <img src="qrs/{name}.png" width="130"/><br/>
        <code>{n["server"]}:{n["port"]}</code>
    </div>
    '''

# 生成 index.html
html = f'''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>订阅信息</title>
    <style>
        body {{ font-family: Arial; background: #f4f4f4; color: #333; }}
        h2 {{ color: #0066cc; }}
        .card {{ display:inline-block; width:200px; padding:10px; margin:10px; background:#fff; border-radius:8px; box-shadow:0 2px 5px rgba(0,0,0,0.1); text-align:center; }}
    </style>
</head>
<body>
    <h2>Clash 订阅链接</h2>
    <p><a href="https://mingko3.github.io/socks5-2025-proxy/proxy.yaml">Clash 配置</a></p>
    <p><a href="https://mingko3.github.io/socks5-2025-proxy/sub">Base64 Sub</a></p>
    <p><img src="sub_qr.png" width="150"/></p>
    <h3>全部节点二维码</h3>
    {card_html}
</body>
</html>
'''

with open("docs/index.html", "w", encoding="utf-8") as f:
    f.write(html)

print("✅ 所有订阅内容与二维码生成完毕！")
