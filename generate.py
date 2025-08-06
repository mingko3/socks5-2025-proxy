import requests, base64, yaml, os, json, qrcode
from datetime import datetime
from urllib.parse import quote
from PIL import Image

# 创建目录
os.makedirs("docs/qrs", exist_ok=True)

# 订阅源列表（仅含 Shadowsocks Base64）
sub_sources = [
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/Shadowsocks.txt",
    "https://raw.githubusercontent.com/freefq/free/master/shadowsocks",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/shadowsocks"
]

ss_nodes = []

def parse_ss(link):
    try:
        if '#' in link:
            link = link.split('#')[0]
        if link.startswith('ss://'):
            link = link[5:]

        padding = len(link) % 4
        if padding:
            link += '=' * (4 - padding)

        decoded = base64.urlsafe_b64decode(link).decode(errors="ignore")
        method, rest = decoded.split(":", 1)
        password, server_port = rest.rsplit("@", 1)
        server, port = server_port.split(":")
        return {
            "name": f"SS_{server}_{port}",
            "type": "ss",
            "server": server,
            "port": int(port),
            "cipher": method,
            "password": password,
            "udp": True
        }
    except Exception as e:
        print("解析错误:", e)
        return None

# 抓取并解析所有源
for url in sub_sources:
    try:
        print("正在抓取:", url)
        res = requests.get(url, timeout=10)
        raw = res.text.strip()

        if "://" not in raw:
            decoded = base64.b64decode(raw + '===').decode(errors="ignore")
            lines = decoded.splitlines()
        else:
            lines = raw.splitlines()

        for line in lines:
            line = line.strip()
            if line.startswith("ss://"):
                node = parse_ss(line)
                if node:
                    ss_nodes.append(node)
    except Exception as e:
        print("抓取失败:", e)

print(f"总共解析出 {len(ss_nodes)} 个 SS 节点")

# YAML 配置
clash_config = {
    "proxies": ss_nodes,
    "proxy-groups": [
        {
            "name": "🚀 自动选择",
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "proxies": [n["name"] for n in ss_nodes]
        }
    ],
    "rules": ["MATCH,🚀 自动选择"]
}

with open("docs/proxy.yaml", "w", encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True)

# Base64 订阅格式（用逗号拼接）
ss_links = []
for n in ss_nodes:
    part = f'{n["cipher"]}:{n["password"]}@{n["server"]}:{n["port"]}'
    encoded = base64.urlsafe_b64encode(part.encode()).decode().rstrip("=")
    ss_links.append(f"ss://{encoded}#{quote(n['name'])}")

sub_content = "\n".join(ss_links)
with open("docs/sub", "w", encoding="utf-8") as f:
    f.write(sub_content)

# 📌 首页二维码
qr = qrcode.make("https://mingko3.github.io/socks5-2025-proxy/sub")
qr.save("docs/sub_qr.png")

# 📌 每个节点二维码
for i, link in enumerate(ss_links):
    qr_img = qrcode.make(link)
    qr_img.save(f"docs/qrs/{i+1}.png")

# 📌 生成网页首页
html = f"""
<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8">
  <title>订阅分享</title>
  <style>
    body {{ font-family: sans-serif; background: #f0f0f0; text-align: center; padding: 2em; }}
    h1 {{ color: #333; }}
    .link {{ margin: 1em 0; font-size: 18px; word-break: break-all; }}
    .qr {{ margin: 2em 0; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; }}
  </style>
</head>
<body>
  <h1>🛰️ 节点订阅分享</h1>
  <div class="link">
    📄 Clash 配置文件：<br>
    <a href="proxy.yaml" target="_blank">https://mingko3.github.io/socks5-2025-proxy/proxy.yaml</a>
  </div>
  <div class="link">
    📦 Base64 订阅链接：<br>
    <a href="sub" target="_blank">https://mingko3.github.io/socks5-2025-proxy/sub</a>
  </div>
  <div class="qr">
    <p>📷 扫码订阅链接</p>
    <img src="sub_qr.png" width="180">
  </div>
  <h2>📍 每个节点二维码</h2>
  <div class="grid">
"""

for i in range(len(ss_links)):
    html += f'<img src="qrs/{i+1}.png" width="120">\n'

html += """
  </div>
  <footer style="margin-top:2em; font-size:14px; color:#888;">
    最后更新：""" + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """（自动部署）
  </footer>
</body>
</html>
"""

with open("docs/index.html", "w", encoding="utf-8") as f:
    f.write(html)

print("✅ 所有文件已生成完毕！")
