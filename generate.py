<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>多格式代理订阅</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f8f9fa;
            color: #212529;
            padding: 20px;
            margin: 0;
        }
        h1, h2 {
            text-align: center;
            color: #343a40;
        }
        .section {
            margin: 40px auto;
            padding: 20px;
            max-width: 700px;
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.1);
        }
        .qr-block {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-top: 10px;
        }
        .qr-block img {
            width: 120px;
            height: 120px;
            border: 1px solid #dee2e6;
        }
        .link {
            flex: 1;
            margin-left: 20px;
            word-break: break-all;
        }
        .footer {
            text-align: center;
            color: #6c757d;
            font-size: 14px;
            margin-top: 40px;
        }
        @media screen and (max-width: 600px) {
            .qr-block {
                flex-direction: column;
                align-items: center;
            }
            .link {
                margin-left: 0;
                margin-top: 10px;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <h1>多格式代理订阅</h1>

    <div class="section">
        <h2>Clash 配置 (proxy.yaml)</h2>
        <div class="qr-block">
            <img src="sub_qr.png" alt="Clash QR">
            <div class="link">
                <a href="https://mingko3.github.io/socks5-2025-proxy/proxy.yaml" target="_blank">
                    https://mingko3.github.io/socks5-2025-proxy/proxy.yaml
                </a>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>基础 Base64 订阅 (sub)</h2>
        <div class="qr-block">
            <img src="sub_qr.png" alt="Base64 QR">
            <div class="link">
                <a href="https://mingko3.github.io/socks5-2025-proxy/sub" target="_blank">
                    https://mingko3.github.io/socks5-2025-proxy/sub
                </a>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>SS 格式 (ss.txt)</h2>
        <div class="qr-block">
            <img src="ss_qr.png" alt="SS QR">
            <div class="link">
                <a href="https://mingko3.github.io/socks5-2025-proxy/ss.txt" target="_blank">
                    https://mingko3.github.io/socks5-2025-proxy/ss.txt
                </a>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>VMess 格式 (vmess.txt)</h2>
        <div class="qr-block">
            <img src="vmess_qr.png" alt="VMess QR">
            <div class="link">
                <a href="https://mingko3.github.io/socks5-2025-proxy/vmess.txt" target="_blank">
                    https://mingko3.github.io/socks5-2025-proxy/vmess.txt
                </a>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Trojan 格式 (trojan.txt)</h2>
        <div class="qr-block">
            <img src="trojan_qr.png" alt="Trojan QR">
            <div class="link">
                <a href="https://mingko3.github.io/socks5-2025-proxy/trojan.txt" target="_blank">
                    https://mingko3.github.io/socks5-2025-proxy/trojan.txt
                </a>
            </div>
        </div>
    </div>

    <div class="footer">更新时间：2025-08-06 05:48:25</div>
</body>
</html>
def parse_ss(link):
    try:
        if '#' in link:
            link = link.split('#')[0]
        link = link[len('ss://'):] if link.startswith('ss://') else link
        missing_padding = len(link) % 4
        if missing_padding:
            link += '=' * (4 - missing_padding)
        decoded = base64.urlsafe_b64decode(link).decode()
        method, rest = decoded.split(':', 1)
        password, server_port = rest.rsplit('@', 1)
        server, port = server_port.split(':')
        return {
            "name": f"SS_{server}_{port}",
            "type": "ss",
            "server": server,
            "port": int(port),
            "cipher": method,
            "password": password,
            "udp": True
        }
    except:
        return None

def parse_vmess(link):
    try:
        data = link[len("vmess://"):]
        decoded = base64.b64decode(data + '===').decode()
        conf = json.loads(decoded)
        return {
            "name": conf.get("ps", f"vmess_{conf.get('add')}"),
            "type": "vmess",
            "server": conf.get("add"),
            "port": int(conf.get("port")),
            "uuid": conf.get("id"),
            "alterId": int(conf.get("aid", 0)),
            "cipher": "auto",
            "tls": conf.get("tls", False),
            "network": conf.get("net"),
            "ws-opts": {"path": conf.get("path", "/"), "headers": {"Host": conf.get("host", "")}}
        }
    except:
        return None

def parse_trojan(link):
    try:
        content = link[len("trojan://"):]
        password, rest = content.split("@")
        server_port = rest.split("#")[0]
        server, port = server_port.split(":")
        return {
            "name": f"Trojan_{server}_{port}",
            "type": "trojan",
            "server": server,
            "port": int(port),
            "password": password,
            "udp": True
        }
    except:
        return None

# 简单 TCP 测速函数
def test_node(server, port):
    try:
        with socket.create_connection((server, int(port)), timeout=1.5):
            return True
    except:
        return False
ss_nodes = []
vmess_nodes = []
trojan_nodes = []

for url in SUB_LINKS:
    try:
        print(f"Fetching: {url}")
        res = requests.get(url, timeout=10)
        content = res.text.strip()

        # 处理 Clash YAML 类型订阅
        if content.startswith("proxies:") or ".yaml" in url or ".yml" in url:
            try:
                data = yaml.safe_load(content)
                for p in data.get("proxies", []):
                    if p.get("type") == "ss" and test_node(p['server'], p['port']):
                        ss_nodes.append(p)
                    elif p.get("type") == "vmess" and test_node(p['server'], p['port']):
                        vmess_nodes.append(p)
                    elif p.get("type") == "trojan" and test_node(p['server'], p['port']):
                        trojan_nodes.append(p)
            except:
                continue
        else:
            # 普通 base64 或纯文本格式
            lines = base64.b64decode(content + '===').decode(errors="ignore").splitlines() if '://' not in content else content.splitlines()
            for line in lines:
                line = line.strip()
                node = None
                if line.startswith("ss://"):
                    node = parse_ss(line)
                    if node and test_node(node['server'], node['port']):
                        ss_nodes.append(node)
                elif line.startswith("vmess://"):
                    node = parse_vmess(line)
                    if node and test_node(node['server'], node['port']):
                        vmess_nodes.append(node)
                elif line.startswith("trojan://"):
                    node = parse_trojan(line)
                    if node and test_node(node['server'], node['port']):
                        trojan_nodes.append(node)
    except Exception as e:
        print(f"Error fetching {url}: {e}")

print(f"✅ 有效节点数：SS({len(ss_nodes)}), VMess({len(vmess_nodes)}), Trojan({len(trojan_nodes)})")
# 创建 docs 和 docs/qrs 目录
os.makedirs("docs/qrs", exist_ok=True)

# 保存完整 Clash 配置
clash_config = {
    "proxies": ss_nodes + vmess_nodes + trojan_nodes,
    "proxy-groups": [
        {
            "name": "🚀 节点选择",
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "proxies": [p["name"] for p in ss_nodes + vmess_nodes + trojan_nodes]
        }
    ]
}
with open("docs/proxy.yaml", "w", encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True)

# 生成 base64 订阅
with open("docs/proxy.yaml", "rb") as f:
    content = f.read()
    b64 = base64.b64encode(content).decode("utf-8")
with open("docs/sub", "w", encoding="utf-8") as f:
    f.write(b64)

# 生成主订阅二维码
img = qrcode.make("https://mingko3.github.io/socks5-2025-proxy/sub")
img.save("docs/sub_qr.png")

# 单独导出每个节点的二维码图片
def save_qr(node, index):
    if node["type"] == "ss":
        uri = f"{node['cipher']}:{node['password']}@{node['server']}:{node['port']}"
        b64_uri = base64.b64encode(uri.encode()).decode()
        full = f"ss://{b64_uri}"
    elif node["type"] == "vmess":
        vmess_conf = {
            "v": "2",
            "ps": node.get("name", ""),
            "add": node["server"],
            "port": str(node["port"]),
            "id": node["uuid"],
            "aid": str(node.get("alterId", 0)),
            "net": node.get("network", "ws"),
            "type": "none",
            "host": node.get("ws-opts", {}).get("headers", {}).get("Host", ""),
            "path": node.get("ws-opts", {}).get("path", "/"),
            "tls": node.get("tls", "")
        }
        b64_uri = base64.b64encode(json.dumps(vmess_conf).encode()).decode()
        full = f"vmess://{b64_uri}"
    elif node["type"] == "trojan":
        full = f"trojan://{node['password']}@{node['server']}:{node['port']}"
    else:
        return

    img = qrcode.make(full)
    filename = f"docs/qrs/{node['type']}_{index}.png"
    img.save(filename)

for idx, node in enumerate(ss_nodes + vmess_nodes + trojan_nodes):
    save_qr(node, idx)
# 获取当前更新时间
update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# 生成 index.html 内容
html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>节点订阅 - socks5-2025-proxy</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: Arial, sans-serif; background: #f7f9fb; color: #333; padding: 20px; }}
        h1 {{ color: #333; }}
        .section {{ margin-bottom: 30px; padding: 20px; background: #fff; border-radius: 10px; box-shadow: 0 0 8px rgba(0,0,0,0.1); }}
        .copy-btn {{ padding: 6px 10px; margin-left: 10px; cursor: pointer; border: none; background: #007bff; color: #fff; border-radius: 5px; }}
        .copy-btn:hover {{ background: #0056b3; }}
        code {{ background: #eee; padding: 4px 6px; border-radius: 4px; }}
        img.qr {{ width: 180px; margin-top: 10px; }}
    </style>
</head>
<body>
    <h1>🌐 节点订阅中心</h1>
    <p>最近更新：{update_time}</p>

    <div class="section">
        <h2>📥 通用订阅链接（Clash 配置）</h2>
        <code id="yaml">https://mingko3.github.io/socks5-2025-proxy/proxy.yaml</code>
        <button class="copy-btn" onclick="copy('yaml')">复制</button>

        <h3>📦 Base64 编码订阅</h3>
        <code id="b64">https://mingko3.github.io/socks5-2025-proxy/sub</code>
        <button class="copy-btn" onclick="copy('b64')">复制</button>

        <h3>📷 扫码订阅</h3>
        <img src="sub_qr.png" class="qr" alt="订阅二维码">
    </div>

    <div class="section">
        <h2>📊 节点分类统计</h2>
        <p>SS 节点：{len(ss_nodes)} 个</p>
        <p>VMess 节点：{len(vmess_nodes)} 个</p>
        <p>Trojan 节点：{len(trojan_nodes)} 个</p>
    </div>

    <script>
        function copy(id) {{
            const text = document.getElementById(id).innerText;
            navigator.clipboard.writeText(text).then(() => {{
                alert("复制成功：" + text);
            }});
        }}
    </script>
</body>
</html>
"""

# 写入 index.html 页面
with open("docs/index.html", "w", encoding="utf-8") as f:
    f.write(html_content)

print("✅ 所有订阅文件、二维码与网页已生成完毕！")
