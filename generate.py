import requests
import base64
import yaml
import os
import qrcode
from datetime import datetime

# 输出目录
output_dir = "docs"
os.makedirs(output_dir, exist_ok=True)

# 订阅源（仅 SS 格式为例，可扩展）
urls = [
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/Shadowsocks.txt",
    "https://raw.githubusercontent.com/freefq/free/master/shadowsocks",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/shadowsocks",
]

def parse_ss_link(link):
    if not link.startswith("ss://"):
        return None
    encoded = link[5:].split("#")[0]
    try:
        missing_padding = len(encoded) % 4
        if missing_padding:
            encoded += "=" * (4 - missing_padding)
        decoded = base64.urlsafe_b64decode(encoded).decode("utf-8")
        method_password, server_port = decoded.rsplit("@", 1)
        method, password = method_password.split(":", 1)
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
        print(f"解析错误: {e}")
        return None

# 收集节点
proxies = []

for url in urls:
    try:
        res = requests.get(url, timeout=10)
        content = res.text.strip()
        lines = base64.b64decode(content + '===').decode(errors="ignore").splitlines() \
            if "ss://" not in content and not content.startswith("ss://") else content.splitlines()

        for line in lines:
            line = line.strip()
            if line.startswith("ss://"):
                node = parse_ss_link(line)
                if node:
                    proxies.append(node)

    except Exception as e:
        print(f"获取失败: {url}\n{e}")

print(f"总共解析出 {len(proxies)} 个 SS 节点")

# 生成 Clash 配置
clash_config = {
    "proxies": proxies,
    "proxy-groups": [
        {
            "name": "🌀 自动选择",
            "type": "url-test",
            "proxies": [p["name"] for p in proxies],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300
        }
    ],
    "rules": ["MATCH,🌀 自动选择"]
}

# 写入 proxy.yaml
proxy_path = os.path.join(output_dir, "proxy.yaml")
with open(proxy_path, "w", encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True)

# 生成 base64 sub
with open(proxy_path, "rb") as f:
    b64 = base64.b64encode(f.read()).decode("utf-8")

sub_path = os.path.join(output_dir, "sub")
with open(sub_path, "w", encoding="utf-8") as f:
    f.write(b64)

# ✅ 修复二维码无效问题：使用完整订阅链接生成二维码
qr_img = qrcode.make("https://mingko3.github.io/socks5-2025-proxy/sub")
qr_path = os.path.join(output_dir, "sub_qr.png")
qr_img.save(qr_path)

# 生成 index.html 网页
html_path = os.path.join(output_dir, "index.html")
with open(html_path, "w", encoding="utf-8") as f:
    f.write(f"""<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>订阅分享 - socks5-2025-proxy</title>
    <style>
        body {{
            font-family: Arial;
            background-color: #f7f7f7;
            text-align: center;
            padding: 40px;
        }}
        .card {{
            background-color: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            display: inline-block;
        }}
        a {{
            color: #007bff;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h2>🌐 Clash 订阅地址</h2>
        <p><a href="https://mingko3.github.io/socks5-2025-proxy/proxy.yaml" target="_blank">proxy.yaml</a></p>
        <h2>📦 Base64 订阅</h2>
        <p><a href="https://mingko3.github.io/socks5-2025-proxy/sub" target="_blank">sub</a></p>
        <h2>📱 扫码导入（推荐 Shadowrocket）</h2>
        <img src="sub_qr.png" alt="订阅二维码" width="200">
        <p style="margin-top:10px;">扫码或长按识别订阅</p>
        <p>更新时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
</body>
</html>""")

print("✅ 全部生成完成")
