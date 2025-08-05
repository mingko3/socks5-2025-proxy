import requests
import base64
import yaml
import os
import re

# 创建 docs 文件夹
os.makedirs("docs", exist_ok=True)

# === 1. 处理 SS 链接 ===
def parse_ss_link(link):
    if not link.startswith("ss://"):
        return None
    encoded = link[len("ss://"):].split("#")[0]
    try:
        decoded = base64.b64decode(encoded + '=' * (-len(encoded) % 4)).decode('utf-8')
    except:
        return None
    parts = decoded.split("@")
    if len(parts) != 2:
        return None
    method_password, server_port = parts
    method, password = method_password.split(":", 1)
    server, port = server_port.split(":", 1)
    return {
        "name": f"SS_{server.replace('.', '-')}_{port}",
        "type": "ss",
        "server": server,
        "port": int(port),
        "cipher": method,
        "password": password,
        "udp": True
    }

# === 2. 处理 SOCKS5 链接 ===
def parse_socks5_line(line):
    match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
    if not match:
        return None
    ip, port = match.groups()
    return {
        "name": f"SOCKS5_{ip.replace('.', '-')}_{port}",
        "type": "socks5",
        "server": ip,
        "port": int(port),
        "udp": True
    }

# === 3. 获取 SS 链接列表 ===
ss_url = "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"
try:
    ss_res = requests.get(ss_url)
    ss_res.raise_for_status()
    ss_links = ss_res.text.strip().splitlines()
except:
    ss_links = []

# === 4. 获取 SOCKS5 列表 ===
socks_url = "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt"
try:
    socks_res = requests.get(socks_url)
    socks_res.raise_for_status()
    socks_lines = socks_res.text.strip().splitlines()
except:
    socks_lines = []

# === 5. 统一解析代理 ===
proxies = []

for link in ss_links:
    proxy = parse_ss_link(link)
    if proxy:
        proxies.append(proxy)

for line in socks_lines:
    proxy = parse_socks5_line(line)
    if proxy:
        proxies.append(proxy)

# === 6. 生成 Clash 配置 ===
config = {
    "proxies": proxies,
    "proxy-groups": [
        {
            "name": "🚀 自动选择",
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "proxies": [p["name"] for p in proxies]
        }
    ]
}

# === 7. 保存 YAML 文件 ===
with open("docs/proxy.yaml", "w", encoding="utf-8") as f:
    yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

# === 8. 生成 base64 编码 sub 文件 ===
with open("docs/proxy.yaml", "rb") as f:
    content = f.read()
    b64 = base64.b64encode(content).decode("utf-8")

with open("docs/sub", "w", encoding="utf-8") as f:
    f.write(b64)

# === 9. 创建 index.html 页面 ===
with open("docs/index.html", "w", encoding="utf-8") as f:
    f.write(f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Clash 订阅链接</title>
</head>
<body>
  <h2>Clash 订阅（纯文本）</h2>
  <p><a href="https://mingko3.github.io/socks5-2025-proxy/proxy.yaml" target="_blank">proxy.yaml</a></p>
  <h2>Clash 订阅（Base64）</h2>
  <p><a href="https://mingko3.github.io/socks5-2025-proxy/sub" target="_blank">sub</a></p>
</body>
</html>
""")

print(f"✅ 已生成：{len(proxies)} 个节点。")
