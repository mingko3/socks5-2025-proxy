import requests
import yaml
import base64

# 节点来源地址
url = "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt"
response = requests.get(url)
lines = response.text.strip().split('\n')

# Clash 格式配置列表
clash_proxies = []

# 最多取前 20 条（你可改为 50 或更多）
for index, line in enumerate(lines[:20]):
    parts = line.strip().split(':')
    if len(parts) != 2:
        continue
    ip, port = parts
    proxy = {
        'name': f"S5_{index + 1}",
        'type': 'socks5',
        'server': ip,
        'port': int(port),
        'udp': False
    }
    clash_proxies.append(proxy)

# 保存为 proxy.yaml 文件
clash_config = {
    'proxies': clash_proxies
}
with open("proxy.yaml", "w", encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True)

# 生成 base64 格式的订阅内容（普通节点列表）
plain_text = '\n'.join([f'socks5://{p["server"]}:{p["port"]}' for p in clash_proxies])
sub_encoded = base64.b64encode(plain_text.encode()).decode()

# 写入 sub 文件
with open("sub", "w", encoding="utf-8") as f:
    f.write(sub_encoded)

print("✅ proxy.yaml 和 sub 文件已生成！")
