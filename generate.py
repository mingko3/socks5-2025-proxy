import requests, base64, yaml, os, re, qrcode, json, socket
from urllib.parse import unquote
from datetime import datetime

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

def test_node(server, port):
    try:
        socket.create_connection((server, int(port)), timeout=1.5)
        return True
    except:
        return False

def parse_ss(link):
    try:
        if '#' in link: link = link.split('#')[0]
        link = link[len('ss://'):] if link.startswith('ss://') else link
        link += '=' * (4 - len(link) % 4)
        decoded = base64.urlsafe_b64decode(link).decode()
        method, rest = decoded.split(':', 1)
        password, server_port = rest.rsplit('@', 1)
        server, port = server_port.split(':')
        return {"name": f"SS_{server}_{port}", "type": "ss", "server": server, "port": int(port), "cipher": method, "password": password, "udp": True}
    except:
        return None

def parse_vmess(link):
    try:
        decoded = base64.b64decode(link[len("vmess://"):] + '===').decode()
        conf = json.loads(decoded)
        return {"name": conf.get("ps", "vmess"), "type": "vmess", "server": conf.get("add"),
                "port": int(conf.get("port")), "uuid": conf.get("id"), "alterId": int(conf.get("aid", 0)),
                "cipher": "auto", "tls": conf.get("tls", False), "network": conf.get("net"),
                "ws-opts": {"path": conf.get("path", "/"), "headers": {"Host": conf.get("host", "")}}}
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

ss_nodes, vmess_nodes, trojan_nodes = [], [], []

for url in SUB_LINKS:
    try:
        print(f"[+] Fetching: {url}")
        res = requests.get(url, timeout=10)
        content = res.text.strip()
        if content.startswith("proxies:") or ".yaml" in url or ".yml" in url:
            try:
                data = yaml.safe_load(content)
                for p in data.get("proxies", []):
                    if p.get("type") == "ss" and test_node(p['server'], p['port']): ss_nodes.append(p)
                    elif p.get("type") == "vmess" and test_node(p['server'], p['port']): vmess_nodes.append(p)
                    elif p.get("type") == "trojan" and test_node(p['server'], p['port']): trojan_nodes.append(p)
            except: continue
        else:
            lines = base64.b64decode(content + '===').decode(errors="ignore").splitlines() if '://' not in content else content.splitlines()
            for line in lines:
                line = line.strip()
                node = None
                if line.startswith("ss://"):
                    node = parse_ss(line)
                    if node and test_node(node['server'], node['port']):
                        ss_nodes.append(node)
                elif line.startswith("vmess://"):
                    node = parse_vmess(line)
                    if node and test_node(node['server'], node['port']):
                        vmess_nodes.append(node)
                elif line.startswith("trojan://"):
                    node = parse_trojan(line)
                    if node and test_node(node['server'], node['port']):
                        trojan_nodes.append(node)
    except Exception as e:
        print(f"[-] Error fetching {url}: {e}")

print(f"[+] 总计节点：SS({len(ss_nodes)}), VMess({len(vmess_nodes)}), Trojan({len(trojan_nodes)})")

# 写入文件
os.makedirs("docs", exist_ok=True)

with open("docs/proxy.yaml", "w", encoding="utf-8") as f:
    yaml.dump({"proxies": ss_nodes + vmess_nodes + trojan_nodes}, f, allow_unicode=True)

def encode_nodes(nodes, kind):
    lines = []
    for n in nodes:
        if kind == "ss":
            info = f"{n['cipher']}:{n['password']}@{n['server']}:{n['port']}"
            encoded = base64.urlsafe_b64encode(info.encode()).decode().rstrip("=")
            lines.append("ss://" + encoded)
        elif kind == "trojan":
            lines.append(f"trojan://{n['password']}@{n['server']}:{n['port']}")
        elif kind == "vmess":
            vmess_conf = {
                "v": "2", "ps": n["name"], "add": n["server"], "port": str(n["port"]), "id": n["uuid"],
                "aid": str(n.get("alterId", 0)), "net": n.get("network", "tcp"), "type": "none",
                "host": n.get("ws-opts", {}).get("headers", {}).get("Host", ""),
                "path": n.get("ws-opts", {}).get("path", "/"),
                "tls": "tls" if n.get("tls") else ""
            }
            encoded = base64.b64encode(json.dumps(vmess_conf).encode()).decode()
            lines.append("vmess://" + encoded)
    return lines

with open("docs/ss.txt", "w") as f: f.write("\n".join(encode_nodes(ss_nodes, "ss")))
with open("docs/vmess.txt", "w") as f: f.write("\n".join(encode_nodes(vmess_nodes, "vmess")))
with open("docs/trojan.txt", "w") as f: f.write("\n".join(encode_nodes(trojan_nodes, "trojan")))

# Base64 综合订阅
sub_content = encode_nodes(ss_nodes, "ss") + encode_nodes(vmess_nodes, "vmess") + encode_nodes(trojan_nodes, "trojan")
with open("docs/sub", "w") as f: f.write(base64.b64encode("\n".join(sub_content).encode()).decode())

# ✅ 修复后的二维码生成
def make_qr(url, output):
    qr = qrcode.QRCode(box_size=10, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image()
    img.save(output)

make_qr("https://mingko3.github.io/socks5-2025-proxy/sub", "docs/sub_qr.png")
make_qr("https://mingko3.github.io/socks5-2025-proxy/proxy.yaml", "docs/proxy_qr.png")
make_qr("https://mingko3.github.io/socks5-2025-proxy/ss.txt", "docs/ss_qr.png")
make_qr("https://mingko3.github.io/socks5-2025-proxy/vmess.txt", "docs/vmess_qr.png")
make_qr("https://mingko3.github.io/socks5-2025-proxy/trojan.txt", "docs/trojan_qr.png")

with open("docs/index.html", "w", encoding="utf-8") as f:
    f.write(f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>多格式订阅</title></head>
<body>
<h2>多格式代理订阅</h2>
<p>更新时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<ul>
<li>Clash 配置 (<a href='proxy.yaml'>proxy.yaml</a>)<br><img src='proxy_qr.png' width='150'></li>
<li>混合 Base64 订阅 (<a href='sub'>sub</a>)<br><img src='sub_qr.png' width='150'></li>
<li>SS 订阅 (<a href='ss.txt'>ss.txt</a>)<br><img src='ss_qr.png' width='150'></li>
<li>VMess 订阅 (<a href='vmess.txt'>vmess.txt</a>)<br><img src='vmess_qr.png' width='150'></li>
<li>Trojan 订阅 (<a href='trojan.txt'>trojan.txt</a>)<br><img src='trojan_qr.png' width='150'></li>
</ul>
</body>
</html>
""")
