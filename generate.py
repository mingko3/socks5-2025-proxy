import requests
import yaml
import base64
import os
from datetime import datetime

url = "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt"
response = requests.get(url)
lines = response.text.strip().split("\n")

proxies = []
for line in lines:
    # 跳过无效行（如说明文字）
    if not line or line.startswith("SOCKS5") or "://" in line or "Proxy list" in line or "Support us" in line or "Fromat" in line:
        continue

    try:
        parts = line.split()
        ip_port = parts[1]  # 取第2部分是 IP:PORT
        ip, port = ip_port.split(":")
        country_flag = parts[0]
        country = parts[2] if len(parts) > 2 else "??"

        name = f"{country_flag}_{ip.replace('.', '-')}_{port}"
        proxies.append({
            "name": name,
            "type": "socks5",
            "server": ip,
            "port": int(port)
        })
    except Exception as e:
        continue

clash_config = {
    "proxies": proxies,
    "proxy-groups": [
        {
            "name": "🚀 节点选择",
            "type": "select",
            "proxies": [proxy["name"] for proxy in proxies]
        }
    ]
}

# 确保 docs 目录存在
os.makedirs("docs", exist_ok=True)

# 写入 proxy.yaml
with open("docs/proxy.yaml", "w", encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True)

# 写入 proxy.yaml.sub（base64）
with open("docs/proxy.yaml", "rb") as f:
    content = f.read()
    b64 = base64.b64encode(content).decode("utf-8")

with open("docs/proxy.yaml.sub", "w", encoding="utf-8") as f:
    f.write(b64)

print(f"生成完成，共 {len(proxies)} 个节点")
