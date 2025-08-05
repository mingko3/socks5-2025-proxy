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
    if line.strip() == "" or line.startswith("SOCKS5 Proxy list updated") or "://" in line:
        continue
    try:
        parts = line.split()
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
        print(f"跳过无效行：{line}")
        continue

# 构建 Clash 配置
config = {
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
            "proxies": [p["name"] for p in proxies],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300
        },
        {
            "name": "手动选择",
            "type": "select",
            "proxies": ["自动选择"] + [p["name"] for p in proxies]
        }
    ],
    "rules": [
        "MATCH,手动选择"
    ]
}

# 确保 docs 目录存在
os.makedirs("docs", exist_ok=True)

# 写入 proxy.yaml
yaml_path = os.path.join("docs", "proxy.yaml")
with open(yaml_path, "w", encoding="utf-8") as f:
    yaml.dump(config, f, allow_unicode=True)

# 写入 base64 格式的 sub 文件
sub_path = os.path.join("docs", "sub")
with open(yaml_path, "rb") as f:
    encoded = base64.b64encode(f.read()).decode("utf-8")
    with open(sub_path, "w", encoding="utf-8") as su_
