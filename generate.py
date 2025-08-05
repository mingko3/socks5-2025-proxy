import requests
import yaml
import os
import base64
from datetime import datetime

url = "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt"
resp = requests.get(url)
lines = resp.text.splitlines()

proxies = []

for line in lines:
    if line.startswith("#") or "://" in line or line.strip() == "":
        continue

    parts = line.strip().split()
    if len(parts) < 2:
        continue

    ip_port = parts[1]
    try:
        ip, port = ip_port.split(":")
        proxies.append({
            "name": ip.replace(".", "-") + "_" + port,
            "type": "socks5",
            "server": ip,
            "port": int(port)
        })
    except:
        continue

clash_config = {
    "port": 7890,
    "socks-port": 7891,
    "redir-port": 7892,
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

# 确保 docs 目录存在
os.makedirs("docs", exist_ok=True)

# 写入 YAML 文件
yaml_path = os.path.join("docs", "proxy.yaml")
with open(yaml_path, "w", encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True)

# 写入 base64 编码的 sub 文件
sub_path = os.path.join("docs", "sub")
with open(yaml_path, "rb") as f:
    encoded = base64.b64encode(f.read()).decode("utf-8")

with open(sub_path, "w", encoding="utf-8") as subfile:
    subfile.write(encoded)

print("✅ YAML and sub files generated successfully at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
