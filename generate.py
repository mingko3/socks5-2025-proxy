import requests
import yaml
import base64
import os
from datetime import datetime

# 下载 SOCKS5 列表
url = "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt"
response = requests.get(url)
lines = response.text.strip().splitlines()

# 提取 IP:PORT
proxies = []
for line in lines:
    if line.strip() == "" or line.startswith("SOCKS5 Proxy list updated"):
        continue
    try:
        # 分割格式：🇫🇷 37.44.238.2:63617 281ms FR [ISP]
        parts = line.split()
        if len(parts) < 2:
            continue
        ip_port = parts[1]
        ip, port = ip_port.split(":")
        proxy = {
            "name": ip.replace(".", "-") + "_" + port,
            "type": "socks5",
            "server": ip,
            "port": int(port)
        }
        proxies.append(proxy)
    except Exception as e:
        print("跳过无效行：", line)
        continue

# 构建 Clash YAML 配置
clash_config = {
    "port": 7890,
    "socks-port": 7891,
    "allow-lan": True,
    "mode": "Rule",
    "log-level": "info",
    "proxies": proxies,
    "proxy-groups": [
        {
            "name": "自动选择",
            "type": "url-test",
            "proxies": [proxy["name"] for proxy in proxies],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300
        },
        {
            "name": "手动选择",
            "type": "select",
            "proxies": ["自动选择"] + [proxy["name"] for proxy in proxies]
        }
    ],
    "rules": [
        "MATCH,手动选择"
    ]
}

# 创建 docs 目录（如不存在）
os.makedirs("docs", exist_ok=True)

# 写入 YAML 文件
with open("docs/proxy.yaml", "w", encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True)

# 转为 Base64 并写入 sub 文件
with open("docs/proxy.yaml", "rb") as f:
    b64 = base64.b64encode(f.read()).decode("utf-8")

with open("docs/sub", "w", encoding="utf-8") as f:
    f.write(b64)

print("✅ 生成完成：proxy.yaml 与 sub")
