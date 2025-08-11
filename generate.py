import os
import re
import base64
import yaml
import qrcode
from datetime import datetime
import aiohttp
import asyncio

# 配置
OUTPUT_DIR = "docs"
BASE_URL = "https://mingko3.github.io/socks5-2025-proxy"
TIMEOUT = 5  # 节点测速超时时间

# 严格二维码生成
def make_strict_qrcode(url, path):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=8,
        border=4
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(path)

# 异步抓取文本
async def fetch_text(session, url):
    try:
        async with session.get(url, timeout=TIMEOUT) as resp:
            return await resp.text()
    except:
        return ""

# 节点测速（TCP Ping）
async def tcp_ping(host, port):
    try:
        start = asyncio.get_event_loop().time()
        reader, writer = await asyncio.open_connection(host, port)
        writer.close()
        await writer.wait_closed()
        end = asyncio.get_event_loop().time()
        return round((end - start) * 1000)
    except:
        return None

# 解析节点（支持多协议）
def parse_nodes(raw):
    nodes = []
    lines = raw.strip().splitlines()
    for line in lines:
        if line.startswith("ss://"):
            nodes.append({"type": "ss", "raw": line})
        elif line.startswith("vmess://"):
            nodes.append({"type": "vmess", "raw": line})
        elif line.startswith("trojan://"):
            nodes.append({"type": "trojan", "raw": line})
        elif line.startswith("vless://"):
            nodes.append({"type": "vless", "raw": line})
        elif re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", line):  # IP:Port
            ip, port = line.split(":")
            nodes.append({"type": "socks5", "server": ip, "port": int(port)})
    return nodes

# 异步测速过滤
async def filter_nodes(nodes):
    results = []
    sem = asyncio.Semaphore(50)

    async def test_node(node):
        async with sem:
            if "server" in node:  # SOCKS5
                delay = await tcp_ping(node["server"], node["port"])
                if delay and delay <= 2000:
                    node["delay"] = delay
                    results.append(node)
            else:  # 其他协议先直接保留（后期可加解析+测速）
                results.append(node)

    await asyncio.gather(*(test_node(n) for n in nodes))
    return results

# 保存 Clash YAML
def save_clash_yaml(nodes, path):
    proxies = []
    for n in nodes:
        if n["type"] == "socks5":
            proxies.append({
                "name": f"{n['type'].upper()}_{n['server']}_{n['port']}",
                "type": "socks5",
                "server": n["server"],
                "port": n["port"]
            })
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump({"proxies": proxies}, f, allow_unicode=True)

# 保存 Base64
def save_base64(nodes, path):
    urls = [n["raw"] for n in nodes if "raw" in n]
    with open(path, "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(urls).encode()).decode())

# 生成网页
def generate_html(groups, total, available, avg_delay):
    html_path = os.path.join(OUTPUT_DIR, "index.html")
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(f"<h2>订阅中心</h2>")
        f.write(f"<p>总节点: {total} | 可用: {available} | 平均延迟(ms): {avg_delay}</p>")
        f.write(f"<p>更新时间: {now}</p>")
        for name, info in groups.items():
            f.write("<div style='margin:20px;padding:10px;border:1px solid #ccc'>")
            f.write(f"<h3>{name} ({info['count']})</h3>")
            f.write(f"<a href='{info['url']}'>{info['url']}</a><br>")
            f.write(f"<img src='{info['qr']}'><br>")
            f.write("</div>")

# 主运行
async def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    sources = [
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt"
    ]

    async with aiohttp.ClientSession() as session:
        texts = await asyncio.gather(*(fetch_text(session, url) for url in sources))

    all_nodes = []
    for t in texts:
        all_nodes.extend(parse_nodes(t))

    print(f"抓取节点: {len(all_nodes)}")
    filtered = await filter_nodes(all_nodes)
    print(f"可用节点: {len(filtered)}")

    avg_delay = round(sum(n.get("delay", 0) for n in filtered if "delay" in n) / max(1, len([n for n in filtered if "delay" in n])), 2)

    groups = {}

    # 主订阅 YAML
    main_yaml = os.path.join(OUTPUT_DIR, "proxy.yaml")
    save_clash_yaml(filtered, main_yaml)
    main_url = f"{BASE_URL}/proxy.yaml"
    make_strict_qrcode(main_url, os.path.join(OUTPUT_DIR, "proxy.png"))
    groups["主订阅"] = {"url": main_url, "qr": "proxy.png", "count": len(filtered)}

    # Base64
    sub_path = os.path.join(OUTPUT_DIR, "sub")
    save_base64(filtered, sub_path)
    sub_url = f"{BASE_URL}/sub"
    make_strict_qrcode(sub_url, os.path.join(OUTPUT_DIR, "sub.png"))
    groups["Base64 订阅"] = {"url": sub_url, "qr": "sub.png", "count": len(filtered)}

    # 协议分组
    protocols = {}
    for n in filtered:
        protocols.setdefault(n["type"], []).append(n)

    for proto, nodes in protocols.items():
        yaml_path = os.path.join(OUTPUT_DIR, f"{proto}.yaml")
        save_clash_yaml(nodes, yaml_path)
        url = f"{BASE_URL}/{proto}.yaml"
        qr_path = os.path.join(OUTPUT_DIR, f"{proto}.png")
        make_strict_qrcode(url, qr_path)
        groups[f"{proto.upper()} 节点订阅"] = {"url": url, "qr": f"{proto}.png", "count": len(nodes)}

    generate_html(groups, len(all_nodes), len(filtered), avg_delay)

if __name__ == "__main__":
    asyncio.run(main())
