import requests
import yaml
import os

url = "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt"
output_dir = "docs"
output_file = os.path.join(output_dir, "proxy.yaml")

# 创建输出目录
os.makedirs(output_dir, exist_ok=True)

# 请求 SOCKS5 列表
response = requests.get(url)
proxies = response.text.strip().split("\n")

# 构建 Clash 配置
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

# 添加每个代理
for i, proxy in enumerate(proxies):
    if not proxy or ":" not in proxy:
        continue
    host, port = proxy.strip().split(":")
    name = f"socks5-{i}"
    clash_proxy = {
        "name": name,
        "type": "socks5",
        "server": host,
        "port": int(port),
        "udp": True
    }
    clash_config["proxies"].append(clash_proxy)
    clash_config["proxy-groups"][0]["proxies"].append(name)

# 保存到 YAML 文件
with open(output_file, "w", encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True)

print(f"已保存到 {output_file}")
