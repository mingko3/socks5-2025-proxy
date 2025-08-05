import requests
import yaml
import os

# 目标文件夹（必须是 docs 才能被 GitHub Pages 识别）
output_dir = "docs"
os.makedirs(output_dir, exist_ok=True)

# 获取 SOCKS5 列表
url = "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt"
response = requests.get(url)
proxy_list = response.text.strip().splitlines()

# 构建 Clash 节点格式
proxies = []
for i, line in enumerate(proxy_list):
    if line.count(":") == 1:
        host, port = line.strip().split(":")
        proxy = {
            "name": f"socks5-{i+1}",
            "type": "socks5",
            "server": host,
            "port": int(port)
        }
        proxies.append(proxy)

# 生成 Clash YAML 配置
clash_config = {
    "proxies": proxies,
    "proxy-groups": [
        {
            "name": "auto",
            "type": "url-test",
            "proxies": [p["name"] for p in proxies],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300
        }
    ]
}

# 保存为 docs/proxy.yaml
with open(os.path.join(output_dir, "proxy.yaml"), "w", encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True)

print(f"✅ 已成功生成 {len(proxies)} 个节点，输出文件为 docs/proxy.yaml")
