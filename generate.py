import requests
import base64
import yaml
import os
import re
import qrcode

# 源地址（你可以改为任意包含节点的订阅地址）
URL = "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"

# 目标输出路径
DOCS_DIR = "docs"
YAML_PATH = os.path.join(DOCS_DIR, "proxy.yaml")
SUB_PATH = os.path.join(DOCS_DIR, "sub")
HTML_PATH = os.path.join(DOCS_DIR, "index.html")
QRCODE_PATH = os.path.join(DOCS_DIR, "sub_qr.png")

os.makedirs(DOCS_DIR, exist_ok=True)

def parse_ss(link):
    try:
        data = link[5:]
        if "#" in data:
            data = data.split("#")[0]
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        decoded = base64.urlsafe_b64decode(data).decode('utf-8')
        method_password, server_port = decoded.split('@')
        method, password = method_password.split(':', 1)
        server, port = server_port.split(':')
        return {
            'name': f"SS_{server}_{port}",
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': method,
            'password': password,
            'udp': True
        }
    except Exception:
        return None

def parse_vmess(link):
    try:
        b64 = link[8:]
        padded = b64 + '=' * (-len(b64) % 4)
        decoded = base64.b64decode(padded).decode('utf-8')
        data = eval(decoded.replace("null", "None"))
        return {
            'name': data.get('ps', f"VMess_{data['add']}_{data['port']}"),
            'type': 'vmess',
            'server': data['add'],
            'port': int(data['port']),
            'uuid': data['id'],
            'alterId': int(data.get('aid', 0)),
            'cipher': data.get('scy', 'auto'),
            'tls': data.get('tls', ''),
            'network': data.get('net', ''),
            'ws-opts': {
                'path': data.get('path', ''),
                'headers': {'Host': data.get('host', '')}
            } if data.get('net') == 'ws' else None
        }
    except Exception:
        return None

def parse_trojan(link):
    try:
        match = re.match(r"trojan://(.*?)@(.*?):(\d+)", link)
        if not match:
            return None
        password, server, port = match.groups()
        return {
            'name': f"Trojan_{server}_{port}",
            'type': 'trojan',
            'server': server,
            'port': int(port),
            'password': password,
            'udp': True
        }
    except Exception:
        return None

# 下载订阅数据
try:
    r = requests.get(URL)
    r.raise_for_status()
    raw = base64.b64decode(r.text).decode("utf-8")
except Exception as e:
    print(f"获取订阅失败：{e}")
    raw = ""

# 解析节点
proxies = []
for line in raw.strip().splitlines():
    if line.startswith("ss://"):
        p = parse_ss(line)
    elif line.startswith("vmess://"):
        p = parse_vmess(line)
    elif line.startswith("trojan://"):
        p = parse_trojan(line)
    else:
        p = None
    if p:
        proxies.append(p)

# 写入 proxy.yaml
clash_config = {
    "proxies": proxies,
    "proxy-groups": [{
        "name": "🚀 节点选择",
        "type": "url-test",
        "url": "http://www.gstatic.com/generate_204",
        "interval": 300,
        "proxies": [p["name"] for p in proxies]
    }]
}
with open(YAML_PATH, "w", encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True)

# 写入 base64 订阅 sub
with open(YAML_PATH, "rb") as f:
    encoded = base64.b64encode(f.read()).decode("utf-8")
with open(SUB_PATH, "w", encoding="utf-8") as f:
    f.write(encoded)

# 生成二维码
qr = qrcode.make(f"https://mingko3.github.io/socks5-2025-proxy/sub")
qr.save(QRCODE_PATH)

# 写入 index.html
with open(HTML_PATH, "w", encoding="utf-8") as f:
    f.write(f"""<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>订阅链接</title>
    <style>
        body {{ font-family: sans-serif; text-align: center; padding: 2em; }}
        input {{ width: 90%; padding: 10px; font-size: 1em; }}
        img {{ margin-top: 20px; width: 200px; }}
    </style>
</head>
<body>
    <h1>Clash 订阅</h1>
    <p>复制以下链接导入 Clash：</p>
    <input type="text" readonly value="https://mingko3.github.io/socks5-2025-proxy/sub" onclick="this.select()">
    <p>扫码订阅：</p>
    <img src="sub_qr.png" alt="订阅二维码">
</body>
</html>
""")

print(f"生成完成，共 {len(proxies)} 个节点")
