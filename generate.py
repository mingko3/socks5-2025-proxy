import os
import base64
import json
import yaml
import qrcode
import requests
import socket
from urllib.parse import urlparse
from datetime import datetime

# ================== 配置区域 ==================
OUT_DIR = "docs"
QR_DIR = os.path.join(OUT_DIR, "qrs")
os.makedirs(QR_DIR, exist_ok=True)

# 可用节点超时时间（秒）
TIMEOUT = 1.5

# 订阅输出路径
OUTPUTS = {
    "clash": os.path.join(OUT_DIR, "proxy.yaml"),
    "base64": os.path.join(OUT_DIR, "sub"),
    "ss": os.path.join(OUT_DIR, "ss.txt"),
    "vmess": os.path.join(OUT_DIR, "vmess.txt"),
    "trojan": os.path.join(OUT_DIR, "trojan.txt"),
    "html": os.path.join(OUT_DIR, "index.html")
}

# 订阅源（已测试可用）
SUBS = [
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/Shadowsocks.txt",
    "https://raw.githubusercontent.com/freefq/free/master/shadowsocks",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/shadowsocks",
    "https://raw.githubusercontent.com/freefq/free/master/clash.yaml",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/clash/clash.yml"
]
# ================== 工具函数 ==================

def test_tcp(server, port):
    try:
        socket.create_connection((server, int(port)), timeout=TIMEOUT)
        return True
    except:
        return False

def parse_ss(link):
    try:
        if '#' in link:
            link = link.split('#')[0]
        link = link[len('ss://'):] if link.startswith('ss://') else link
        missing_padding = len(link) % 4
        if missing_padding:
            link += '=' * (4 - missing_padding)
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
            "name": conf.get("ps", "VMESS"),
            "type": "vmess",
            "server": conf.get("add"),
            "port": int(conf.get("port")),
            "uuid": conf.get("id"),
            "alterId": int(conf.get("aid", 0)),
            "cipher": "auto",
            "tls": conf.get("tls", False),
            "network": conf.get("net"),
            "ws-opts": {"path": conf.get("path", "/"), "headers": {"Host": conf.get("host", "")}}
        }
    except:
        return None

def parse_trojan(link):
    try:
        content = link[len("trojan://"):]
        password, rest = content.split("@")
        server_port = rest.split("#")[0]
        server, port = server_port.split(":")
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

# ========== 主流程 ==========

ss_nodes, vmess_nodes, trojan_nodes = [], [], []

for url in SUBS:
    try:
        print(f"获取：{url}")
        r = requests.get(url, timeout=10)
        content = r.text.strip()

        # YAML 格式
        if "proxies:" in content or url.endswith((".yml", ".yaml")):
            try:
                data = yaml.safe_load(content)
                for p in data.get("proxies", []):
                    if test_tcp(p["server"], p["port"]):
                        if p["type"] == "ss":
                            ss_nodes.append(p)
                        elif p["type"] == "vmess":
                            vmess_nodes.append(p)
                        elif p["type"] == "trojan":
                            trojan_nodes.append(p)
            except:
                continue
        else:
            links = base64.b64decode(content + '===').decode(errors="ignore").splitlines() if '://' not in content else content.splitlines()
            for link in links:
                node = None
                if link.startswith("ss://"):
                    node = parse_ss(link)
                    if node and test_tcp(node["server"], node["port"]):
                        ss_nodes.append(node)
                elif link.startswith("vmess://"):
                    node = parse_vmess(link)
                    if node and test_tcp(node["server"], node["port"]):
                        vmess_nodes.append(node)
                elif link.startswith("trojan://"):
                    node = parse_trojan(link)
                    if node and test_tcp(node["server"], node["port"]):
                        trojan_nodes.append(node)
    except Exception as e:
        print(f"抓取失败：{url}，原因：{e}")

# ========== 输出 Clash 配置 ==========
config = {
    "proxies": ss_nodes + vmess_nodes + trojan_nodes,
    "proxy-groups": [
        {
            "name": "🚀 节点选择",
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "proxies": [p["name"] for p in ss_nodes + vmess_nodes + trojan_nodes]
        }
    ]
}

with open(OUTPUTS["clash"], "w", encoding="utf-8") as f:
    yaml.dump(config, f, allow_unicode=True)

# ========== 输出 Base64 订阅 ==========
base64_text = ""
for n in ss_nodes:
    base64_text += f"ss://{base64.b64encode(f'{n['cipher']}:{n['password']}@{n['server']}:{n['port']}'.encode()).decode()}\n"
for n in vmess_nodes:
    vmess_json = base64.b64encode(json.dumps({
        "v": "2", "ps": n["name"], "add": n["server"], "port": str(n["port"]),
        "id": n["uuid"], "aid": str(n.get("alterId", 0)), "net": n["network"],
        "type": "none", "host": n.get("ws-opts", {}).get("headers", {}).get("Host", ""),
        "path": n.get("ws-opts", {}).get("path", "/"), "tls": n.get("tls", False)
    }).encode()).decode()
    base64_text += f"vmess://{vmess_json}\n"
for n in trojan_nodes:
    base64_text += f"trojan://{n['password']}@{n['server']}:{n['port']}\n"

with open(OUTPUTS["base64"], "w", encoding="utf-8") as f:
    f.write(base64_text)

with open(OUTPUTS["ss"], "w", encoding="utf-8") as f:
    f.writelines([line for line in base64_text.splitlines() if line.startswith("ss://")])

with open(OUTPUTS["vmess"], "w", encoding="utf-8") as f:
    f.writelines([line for line in base64_text.splitlines() if line.startswith("vmess://")])

with open(OUTPUTS["trojan"], "w", encoding="utf-8") as f:
    f.writelines([line for line in base64_text.splitlines() if line.startswith("trojan://")])

# ========== 生成二维码 ==========
def save_qr(content, filename):
    img = qrcode.make(content)
    img.save(filename)

save_qr("https://mingko3.github.io/socks5-2025-proxy/sub", os.path.join(OUT_DIR, "sub_qr.png"))

for i, node in enumerate(ss_nodes + vmess_nodes + trojan_nodes):
    name = node["name"].replace(" ", "_").replace("/", "_")
    qr_path = os.path.join(QR_DIR, f"{name}.png")
    if node["type"] == "ss":
        uri = f"ss://{base64.b64encode(f'{node['cipher']}:{node['password']}@{node['server']}:{node['port']}'.encode()).decode()}"
    elif node["type"] == "vmess":
        uri = f"vmess://{base64.b64encode(json.dumps({...}).encode()).decode()}"
    elif node["type"] == "trojan":
        uri = f"trojan://{node['password']}@{node['server']}:{node['port']}"
    save_qr(uri, qr_path)

# ========== 生成网页 ==========
html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>多协议订阅中心</title>
    <style>
        body {{ font-family: Arial; padding: 20px; background: #f8f8f8; }}
        h1 {{ color: #333; }}
        a {{ display:block; margin: 10px 0; color: blue; }}
        img {{ height: 150px; }}
        .qrcode {{ margin: 10px 0; }}
    </style>
</head>
<body>
    <h1>代理订阅 · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h1>
    <a href="proxy.yaml" download>📥 下载 Clash 配置</a>
    <a href="sub" download>📥 Base64 订阅</a>
    <a href="ss.txt" download>📥 SS 节点</a>
    <a href="vmess.txt" download>📥 VMess 节点</a>
    <a href="trojan.txt" download>📥 Trojan 节点</a>
    <div class="qrcode">
        <h3>扫码订阅：</h3>
        <img src="sub_qr.png" alt="订阅二维码">
    </div>
    <h3>节点二维码：</h3>
    <ul>
"""
for f in os.listdir(QR_DIR):
    html += f'<li>{f}<br><img src="qrs/{f}"></li>'

html += """
    </ul>
</body>
</html>
"""

with open(OUTPUTS["html"], "w", encoding="utf-8") as f:
    f.write(html)

print("✅ 所有订阅已生成完毕。")
