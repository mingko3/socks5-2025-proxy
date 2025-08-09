import os
import base64
import yaml
import aiohttp
import asyncio
import time
import qrcode
from urllib.parse import quote
from datetime import datetime

# 你的源列表（保留原有全部）
SOURCES = [
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    # 其他 YAML / Base64 源可继续添加
]

BASE64_URL = "https://mingko3.github.io/socks5-2025-proxy/sub"
CLASH_URL = "https://mingko3.github.io/socks5-2025-proxy/proxy.yaml"

# 测速配置
TEST_TIMEOUT = 3
MAX_CONCURRENCY = 100

# 存储
os.makedirs("docs", exist_ok=True)

async def fetch(session, url):
    try:
        async with session.get(url, timeout=10) as resp:
            return await resp.text()
    except:
        return ""

async def tcp_ping(host, port):
    start = time.time()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TEST_TIMEOUT)
        writer.close()
        await writer.wait_closed()
        return int((time.time() - start) * 1000)  # 毫秒
    except:
        return None

async def test_nodes(nodes):
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    results = []

    async def test_one(node):
        async with sem:
            delay = await tcp_ping(node["server"], int(node["port"]))
            if delay is not None:
                node["alive"] = True
                node["delay"] = delay
            else:
                node["alive"] = False
                node["delay"] = None
            results.append(node)

    await asyncio.gather(*(test_one(n) for n in nodes))
    return results

def parse_sources(raw_texts):
    nodes = []
    for txt in raw_texts:
        for line in txt.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("vmess://") or line.startswith("ss://") or line.startswith("trojan://"):
                # 这里只做简单收集，解析可以扩展
                proto = line.split("://")[0]
                nodes.append({
                    "name": f"{proto.upper()}节点",
                    "server": "example.com",  # TODO: 从解码中解析
                    "port": 443,
                    "proto": proto,
                    "raw": line
                })
            elif ":" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    nodes.append({
                        "name": f"SOCKS节点",
                        "server": parts[0],
                        "port": parts[1],
                        "proto": "socks5",
                        "raw": line
                    })
    return nodes

async def main():
    print("开始抓取源...")
    async with aiohttp.ClientSession() as session:
        raw_texts = await asyncio.gather(*(fetch(session, url) for url in SOURCES))

    print("解析节点...")
    nodes = parse_sources(raw_texts)
    total_nodes = len(nodes)
    print(f"共解析 {total_nodes} 个节点")

    print("开始测速...")
    tested_nodes = await test_nodes(nodes)
    alive_nodes = [n for n in tested_nodes if n["alive"]]
    dead_nodes = [n for n in tested_nodes if not n["alive"]]
    print(f"可用节点: {len(alive_nodes)}, 不可用: {len(dead_nodes)}")

    print("生成订阅...")
    alive_nodes.sort(key=lambda x: x["delay"] if x["delay"] else 9999)
    sub_content = "\n".join(n["raw"] for n in alive_nodes)
    with open("docs/sub", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(sub_content.encode()).decode())

    print("生成 Clash YAML...")
    clash_config = {
        "proxies": [],
        "proxy-groups": []
    }
    for n in alive_nodes:
        clash_config["proxies"].append({
            "name": n["name"],
            "type": n["proto"] if n["proto"] != "ss" else "ss",
            "server": n["server"],
            "port": int(n["port"])
        })
    with open("docs/proxy.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True)

    print("生成二维码...")
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_Q)
    qr.add_data(BASE64_URL)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save("docs/qrcode.png")

    print("生成网页...")
    html = f"""
    <html>
    <head><meta charset="utf-8"><title>订阅中心</title></head>
    <body>
    <h2>订阅中心</h2>
    <p>Base64 订阅：<a href="{BASE64_URL}">{BASE64_URL}</a></p>
    <p>Clash YAML：<a href="{CLASH_URL}">{CLASH_URL}</a></p>
    <img src="qrcode.png" width="200"><br>
    节点总数: {total_nodes} | 可用: {len(alive_nodes)} | 不可用: {len(dead_nodes)}<br>
    最后更新: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}
    </body>
    </html>
    """
    with open("docs/index.html", "w", encoding="utf-8") as f:
        f.write(html)

if __name__ == "__main__":
    asyncio.run(main())
