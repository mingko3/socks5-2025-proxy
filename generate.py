import requests
import base64
import yaml
import os
import re
import qrcode
import json
from urllib.parse import unquote

# 所有订阅源列表（支持 SS/VMess/Trojan/VLESS + YAML）
SUB_LINKS = [
    # SS Base64
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

# 解析 ss 链接
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

# 解析 vmess 链接
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
            "ws-opts": {"path": conf.get("path", "/"), "headers": {"Host": conf.get("host", "")}}
        }
    except:
        return None

# 解析 trojan 链接
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

# 统一收集所有节点
ss_nodes = []
vmess_nodes = []
trojan_nodes = []

for url in SUB_LINKS:
    try:
        print(f"Fetching: {url}")
        res = requests.get(url, timeout=10)
        content = res.text.strip()

        if content.startswith("proxies:") or ".yaml" in url or ".yml" in url:
            try:
                data = yaml.safe_load(content)
                for p in data.get("proxies", []):
                    if p.get("type") == "ss":
                        ss_nodes.append(p)
                    elif p.get("type") == "vmess":
                        vmess_nodes.append(p)
                    elif p.get("type") == "trojan":
                        trojan_nodes.append(p)
            except:
                continue

        else:
            lines = base64.b64decode(content + '===').decode(errors="ignore").splitlines() if '://' not in content else content.splitlines()
            for line in lines:
                line = line.strip()
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
        print(f"Error fetching {url}: {e}")

# 写入 Clash 配置
def save_yaml():
    all_nodes = ss_nodes + vmess_nodes + trojan_nodes
    proxies = [n for n in all_nodes if n]
    proxy_names = [p["name"] for p in proxies]

    clash = {
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": proxy_names
            }
        ]
    }
    os.makedirs("docs", exist_ok=True)
    with open("docs/proxy.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash, f, allow_unicode=True)

    return proxies

# 写入 base64 订阅
def save_base64(filename, nodes):
    if not nodes:
        return
    lines = []
    for node in nodes:
        if node["type"] == "ss":
            raw = f"{node['cipher']}:{node['password']}@{node['server']}:{node['port']}"
            encoded = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
            lines.append(f"ss://{encoded}#{node['name']}")
        elif node["type"] == "trojan":
            lines.append(f"trojan://{node['password']}@{node['server']}:{node['port']}#{node['name']}")
        elif node["type"] == "vmess":
            conf = {
                "v": "2",
                "ps": node["name"],
                "add": node["server"],
                "port": str(node["port"]),
                "id": node["uuid"],
                "aid": str(node.get("alterId", 0)),
                "net": node.get("network", "tcp"),
                "type": "none",
                "host": node.get("ws-opts", {}).get("headers", {}).get("Host", ""),
                "path": node.get("ws-opts", {}).get("path", "/"),
                "tls": node.get("tls", False)
            }
            encoded = base64.b64encode(json.dumps(conf).encode()).decode()
            lines.append(f"vmess://{encoded}")

    with open(f"docs/{filename}", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    if filename == "sub":
        with open(f"docs/{filename}", "rb") as f:
            encoded = base64.b64encode(f.read()).decode()
        with open("docs/sub", "w") as sf:
            sf.write(encoded)

# 写入二维码 HTML + 图片
def generate_html():
    os.makedirs("docs", exist_ok=True)
    links = [
        ("Clash 配置 (proxy.yaml)", "proxy.yaml"),
        ("混合 Base64 订阅 (sub)", "sub"),
        ("SS 节点 (ss.txt)", "ss.txt"),
        ("VMess 节点 (vmess.txt)", "vmess.txt"),
        ("Trojan 节点 (trojan.txt)", "trojan.txt")
    ]

    html = """<html><head><meta charset='utf-8'><title>订阅中心</title></head><body><h2>多格式代理订阅</h2>"""
    for title, path in links:
        url = f"https://mingko3.github.io/socks5-2025-proxy/{path}"
        qr_img = qrcode.make(url)
        qr_path = f"docs/{path}.png"
        qr_img.save(qr_path)
        html += f"<h3>{title}</h3><p><a href='{url}'>{url}</a><br><img src='{path}.png' width='200'/></p>"
    html += "</body></html>"
    with open("docs/index.html", "w", encoding="utf-8") as f:
        f.write(html)

# 主执行
all_nodes = save_yaml()
save_base64("ss.txt", ss_nodes)
save_base64("trojan.txt", trojan_nodes)
save_base64("vmess.txt", vmess_nodes)
save_base64("sub", ss_nodes + trojan_nodes + vmess_nodes)
generate_html()
print("✅ 所有订阅与二维码网页已生成完毕")
