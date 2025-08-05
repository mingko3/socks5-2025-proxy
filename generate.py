import requests
import yaml
import os
from datetime import datetime

# 获取 SOCKS5 列表
url = "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt"
response = requests.get(url)
raw_proxies = response.text.strip().splitlines()

proxies = []

for line in raw_proxies:
    if ':' not in line:
        continue  # 忽略非代理行
    try:
        parts = line.split()
        ip_port = parts[1]  # 第 2 项是 IP:PORT
        ip, port = ip_port.split(":")
        country = parts[3] if len(parts) > 3 else "UN"  # 国家代码
        name = f"{country}-{ip}"

        proxy = {
            "name": name,
            "type": "socks5",
            "server": ip,
            "port": int(port),
            "socks5": True
        }
        proxies.append(proxy)
    except Exception as e:
        print(f"跳过错误行：{line}，原因：{e}")

# Clash 配置结构
clash_config = {
    "port": 7890,
    "socks-port": 7891,
    "allow-lan": True,
    "mode": "Rule",
    "log-level": "info",
    "proxies": proxies,
    "proxy-groups": [
        {
            "name": "auto",
            "type": "url-test",
            "proxies": [p["name"] for p in proxies],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300
        },
        {
            "name": "select",
            "type": "select",
            "proxies": ["auto"] + [p["name"] for p in proxies]
        }
    ],
    "rules": [
        "MATCH,select"
    ]
}

# 创建 docs 文件夹并保存 YAML
os.makedirs("docs", exist_ok=True)
with open("docs/proxy.yaml", "w", encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True)

# 记录时间（可选）
print(f"已生成 {len(proxies)} 个节点")
print(f"更新时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
