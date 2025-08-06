import os
import base64
import qrcode
from pathlib import Path
from datetime import datetime

# 主订阅链接
BASE64_URL = "https://mingko3.github.io/socks5-2025-proxy/sub"
CLASH_YAML_URL = "https://mingko3.github.io/socks5-2025-proxy/proxy.yaml"

# 创建目录
os.makedirs("docs/qrs", exist_ok=True)

# 使用严格模式生成二维码，解决 Shadowrocket 无效问题
def make_strict_qrcode(data, filename):
    qr = qrcode.QRCode(
        version=5,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image()
    img.save(filename)

# 生成主二维码（订阅链接）
make_strict_qrcode(BASE64_URL, "docs/qrcode.png")

# 示例节点（你应在后续替换为真实抓取结果）
nodes = [
    {"name": "vmess 节点 🇺🇸", "link": "vmess://eyJhZGQiOiJ1c2EuZXhhbXBsZS5jb20iLCAicG9ydCI6IjQ0MyIsICJwcyI6IlVTIE5vZGUifQ=="},
    {"name": "ss 节点 🇩🇪", "link": "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpjYXJkc2hhcmF4QGRlLmV4YW1wbGUuY29tOjQ0Mw=="},
]

# 每个节点生成二维码
for node in nodes:
    safe_name = node["name"].replace(" ", "_").replace("/", "_")
    img_path = f"docs/qrs/{safe_name}.png"
    make_strict_qrcode(node["link"], img_path)

# 生成 index.html 页面
html = f"""<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>节点订阅分享</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f9f9f9; color: #333; padding: 20px;">
    <h1>📡 节点订阅分享</h1>

    <p>📄 Clash 配置文件：<br>
    <a href="{CLASH_YAML_URL}">{CLASH_YAML_URL}</a></p>

    <p>📦 Base64 订阅链接：<br>
    <a href="{BASE64_URL}">{BASE64_URL}</a></p>

    <p>📷 扫码订阅链接：</p>
    <img src="qrcode.png" width="200" alt="订阅二维码"><br><br>

    <h2>📍 每个节点二维码</h2>
"""

for node in nodes:
    safe_name = node["name"].replace(" ", "_").replace("/", "_")
    html += f"""
    <div style="display:inline-block; text-align:center; margin:15px;">
        <img src="qrs/{safe_name}.png" width="150"><br>
        <span>{node["name"]}</span>
    </div>
    """

html += f"""
    <p style="font-size: 12px; color: #777;">最后更新：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}（自动部署）</p>
</body>
</html>
"""

# 写入 HTML 文件
with open("docs/index.html", "w", encoding="utf-8") as f:
    f.write(html)
