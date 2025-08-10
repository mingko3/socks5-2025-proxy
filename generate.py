import os
import re
import base64
import requests
import yaml
import qrcode
import asyncio
import aiohttp
from datetime import datetime

OUTPUT_DIR = "docs"
QR_DIR = os.path.join(OUTPUT_DIR, "qrs")
os.makedirs(QR_DIR, exist_ok=True)

NODE_SOURCES = [
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Proxy.yml",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
]

# 异步 TCP 测速
async def tcp_ping(host, port, timeout=2):
    try:
        start = datetime.now()
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        end = datetime.now()
        writer.close()
        await writer.wait_closed()
        return (end - start).microseconds // 1000
    except:
        return None

# 解析节点
def parse_nodes(raw_text):
    nodes = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith(("ss://", "vmess://", "vless://", "trojan://")) or line.lower().startswith("socks"):
            nodes.append(line)
    return nodes

# 抓取所有源
def fetch_all_sources():
    all_nodes = []
    for url in NODE_SOURCES:
        try:
            print(f"抓取源: {url}")
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                all_nodes.extend(parse_nodes(r.text))
        except Exception as e:
            print(f"源 {url} 抓取失败: {e}")
    return list(set(all_nodes))

# 并发测速 & 可用性过滤
async def filter_nodes(nodes):
    usable_nodes = []

    async def test_node(node):
        host_port = None
        if node.startswith(("vmess://", "vless://", "trojan://")):
            try:
                decoded = base64.b64decode(node.split("://")[1] + "==").decode(errors="ignore")
                server_match = re.search(r'"add"\s*:\s*"([^"]+)"', decoded)
                port_match = re.search(r'"port"\s*:\s*(\d+)', decoded)
                if server_match and port_match:
                    host_port = (server_match.group(1), int(port_match.group(1)))
            except:
                return
        elif node.startswith("ss://"):
            try:
                hp = node.split("@")[-1]
                host_port = (hp.split(":")[0], int(hp.split(":")[1]))
            except:
                return
        elif node.lower().startswith("socks"):
            hp = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', node)
            if hp:
                host_port = (hp.group(1), int(hp.group(2)))

        if host_port:
            delay = await tcp_ping(*host_port)
            if delay and delay <= 1000:
                usable_nodes.append((node, delay))

    await asyncio.gather(*(test_node(n) for n in nodes))
    return usable_nodes

# 写 Clash YAML
def write_clash_yaml(nodes, file_path):
    proxies = []
    for i, (node, delay) in enumerate(nodes):
        if node.startswith("ss://"):
            proxies.append({"name": f"SS_{i}_{delay}ms", "type": "ss", "server": "example.com", "port": 443, "cipher": "aes-256-gcm", "password": "password"})
        elif node.startswith("vmess://"):
            proxies.append({"name": f"VMess_{i}_{delay}ms", "type": "vmess", "server": "example.com", "port": 443, "uuid": "uuid", "alterId": 0, "cipher": "auto"})
        elif node.startswith("vless://"):
            proxies.append({"name": f"VLESS_{i}_{delay}ms", "type": "vless", "server": "example.com", "port": 443, "uuid": "uuid", "cipher": "auto"})
        elif node.startswith("trojan://"):
            proxies.append({"name": f"Trojan_{i}_{delay}ms", "type": "trojan", "server": "example.com", "port": 443, "password": "password"})
        elif node.lower().startswith("socks4"):
            proxies.append({"name": f"SOCKS4_{i}_{delay}ms", "type": "socks5", "server": "example.com", "port": 1080})
        elif node.lower().startswith("socks5"):
            proxies.append({"name": f"SOCKS5_{i}_{delay}ms", "type": "socks5", "server": "example.com", "port": 1080})

    config = {
        "proxies": proxies,
        "proxy-groups": [{
            "name": "Auto",
            "type": "url-test",
            "proxies": [p["name"] for p in proxies],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300
        }],
        "rules": ["MATCH,Auto"]
    }
    with open(file_path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True)

# 生成二维码
def make_qr(data, path):
    img = qrcode.make(data)
    img.save(path)

# 主流程
async def main():
    raw_nodes = fetch_all_sources()
    print(f"总抓取节点: {len(raw_nodes)}")

    usable_nodes = await filter_nodes(raw_nodes)
    print(f"可用节点: {len(usable_nodes)}")

    # 主订阅
    main_yaml = os.path.join(OUTPUT_DIR, "proxy.yaml")
    write_clash_yaml(usable_nodes, main_yaml)
    make_qr("https://mingko3.github.io/socks5-2025-proxy/proxy.yaml", os.path.join(QR_DIR, "main.png"))

    # Base64 订阅
    sub_data = "\n".join([n for n, _ in usable_nodes])
    sub_file = os.path.join(OUTPUT_DIR, "sub")
    with open(sub_file, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(sub_data.encode()).decode())
    make_qr("https://mingko3.github.io/socks5-2025-proxy/sub", os.path.join(QR_DIR, "sub.png"))

    # 协议分组
    protocols = ["ss://", "vmess://", "vless://", "trojan://", "socks4", "socks5"]
    for proto in protocols:
        proto_nodes = [(n, d) for n, d in usable_nodes if n.lower().startswith(proto)]
        if proto_nodes:
            file_name = proto.replace("://", "").upper() + ".yaml"
            file_path = os.path.join(OUTPUT_DIR, file_name)
            write_clash_yaml(proto_nodes, file_path)
            make_qr(f"https://mingko3.github.io/socks5-2025-proxy/{file_name}", os.path.join(QR_DIR, f"{proto.replace('://', '')}.png"))

    # 更新时间
    with open(os.path.join(OUTPUT_DIR, "update_time.txt"), "w", encoding="utf-8") as f:
        f.write(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))

if __name__ == "__main__":
    asyncio.run(main())
