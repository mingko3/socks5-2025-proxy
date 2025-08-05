import base64
import yaml
import os

def parse_ss_link(link):
    if not link.startswith("ss://"):
        return None
    # 移除 "ss://"
    encoded = link[len("ss://"):]
    # 处理可能包含 # 的部分
    if "#" in encoded:
        encoded = encoded.split("#")[0]
    try:
        decoded = base64.b64decode(encoded).decode('utf-8')
    except:
        return None
    # 分割为认证部分和主机端口部分
    parts = decoded.split("@")
    if len(parts) != 2:
        return None
    auth, hostport = parts
    # 分割主机和端口
    hp = hostport.split(":")
    if len(hp) != 2:
        return None
    server, port = hp
    try:
        port = int(port)
    except ValueError:
        return None
    # 分割认证部分
    a = auth.split(":")
    if len(a) < 2:
        return None
    method = a[0]
    password = ":".join(a[1:])
    return {
        "name": f"SS_{server}_{port}",
        "type": "ss",
        "server": server,
        "port": port,
        "cipher": method,
        "password": password,
        "udp": True
    }

# 假设附件内容已保存为 links.txt
with open("links.txt", "r", encoding="utf-8") as f:
    links = f.read().splitlines()

proxies = []
for link in links:
    if link.startswith("ss://"):
        proxy = parse_ss_link(link)
        if proxy:
            proxies.append(proxy)
    # TODO: 添加 vmess:// 和 trojan:// 的解析逻辑

# 生成 Clash 配置
config = {
    "proxies": proxies,
    "proxy-groups": [
        {
            "name": "Auto",
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "proxies": [p["name"] for p in proxies]
        }
    ]
}

# 确保 docs 目录存在
os.makedirs("docs", exist_ok=True)

# 保存为 YAML 文件
with open("docs/proxy.yaml", "w", encoding="utf-8") as f:
    yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

# 生成 base64 编码的 .sub 文件
with open("docs/proxy.yaml", "rb") as f:
    content = f.read()
    b64 = base64.b64encode(content).decode("utf-8")

with open("docs/sub", "w", encoding="utf-8") as f:
    f.write(b64)

print(f"生成完成，共 {len(proxies)} 个节点")
