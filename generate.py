import requests
import yaml
import os
from datetime import datetime

# 目标 URL
url = "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt"

# 发送请求并获取文本内容
res = requests.get(url)
lines = res.text.strip().split("\n")

# 创建 Clash 配置的基本结构
clash_config = {
    "proxies": [],
    "proxy-groups": [
        {
            "name": "auto",
            "type": "url-test",
            "proxies": [],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300
        }
    ]
}

# 逐行处理每个代理节点
for line in lines:
    # 只处理包含 IP:PORT 的行
    if ":" not in line or "[" not in line:
        continue

    try:
        parts = line.split()
        ip_port = parts[1]  # IP:PORT 是第 2 个元素
        ip, port = ip_port.split(":")
        country = parts[3]  # 国家代码

        name = f"{country}_{ip.replace('.', '-')}_{port}"

        clash_config["proxies"].append({
            "name": name,
            "type": "socks5",
            "server": ip,
            "port": int(port),
            "udp": True
        })

        clash_config["proxy-groups"][0]["proxies"].append(name)

    except Exception as e:
        print(f"跳过行: {line}, 错误: {e}")
        continue

# 确保 docs 目录存在
os.makedirs("docs", exist_ok=True)

# 输出到 docs/proxy.yaml 文件中
with open("docs/proxy.yaml", "w", encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True)

# 打印更新时间
print("SOCKS5 Proxy list 已生成于", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
