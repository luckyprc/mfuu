#!/usr/bin/env python3
"""启动 mihomo，真连接测试，输出 raw.txt / base64.txt (scv=true)"""

import os
import re
import json
import base64
import time
import subprocess
import concurrent.futures
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit
import requests
import yaml

UPSTREAM = os.environ.get("UPSTREAM_SUB", "").strip()
MAX_MS = int(os.environ.get("MAX_LATENCY_MS", "800"))
PROBE_URL = os.environ.get("PROBE_URL", "http://connectivitycheck.platform.hicloud.com/generate_204")
PROBE_TIMEOUT = int(os.environ.get("PROBE_TIMEOUT_MS", "5000"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "50"))
MIHOMO_BIN = "/tmp/mihomo"
MIHOMO_API = "http://127.0.0.1:9090"


def decode_upstream(text: str) -> str:
    t = text.strip()
    if not t:
        return ""
    if any(x in t for x in ("vmess://", "vless://", "trojan://", "ss://")):
        return t
    clean = ''.join(t.split())
    if len(clean) < 20:
        return ""
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(clean + '==', validate=False).decode("utf-8", "ignore")
            if any(line.startswith(("vmess://", "vless://", "trojan://", "ss://")) for line in raw.splitlines()):
                return raw
        except Exception:
            continue
    return ""


def add_allow_insecure(link: str) -> str:
    if not link.startswith(("vless://", "trojan://")):
        return link
    u = urlsplit(link)
    qs = dict(parse_qsl(u.query, keep_blank_values=True))
    qs["allowInsecure"] = "1"
    new_query = urlencode(list(qs.items()))
    return urlunsplit((u.scheme, u.netloc, u.path, new_query, u.fragment))


def extract_host_port(link: str):
    try:
        if link.startswith("vmess://"):
            payload = link[len("vmess://"):]
            pad = 4 - len(payload) % 4
            if pad != 4:
                payload += "=" * pad
            d = json.loads(base64.b64decode(payload, validate=False).decode("utf-8", "ignore"))
            return d.get("add"), int(d.get("port", 0) or 0)
        else:
            u = urlsplit(link)
            return u.hostname, u.port or 0
    except Exception:
        return None, 0


def vmess_to_clash(link: str, name: str):
    payload = link[len("vmess://"):]
    pad = 4 - len(payload) % 4
    if pad != 4:
        payload += "=" * pad
    d = json.loads(base64.b64decode(payload, validate=False).decode("utf-8", "ignore"))
    p = {
        "name": name,
        "type": "vmess",
        "server": d.get("add"),
        "port": int(d.get("port") or 0),
        "uuid": d.get("id"),
        "alterId": int(d.get("aid", 0) or 0),
        "cipher": "auto",
        "udp": True,
        "network": d.get("net", "tcp"),
    }
    net = d.get("net", "tcp")
    if net == "ws":
        p["ws-opts"] = {"path": d.get("path") or "/", "headers": {}}
        if d.get("host"):
            p["ws-opts"]["headers"]["Host"] = d.get("host")
    if net == "grpc":
        p["grpc-opts"] = {"grpc-service-name": d.get("path") or ""}
    if str(d.get("tls") or "").lower() == "tls":
        p["tls"] = True
        p["skip-cert-verify"] = True
        if d.get("sni") or d.get("host"):
            p["servername"] = d.get("sni") or d.get("host")
    return p


def vless_trojan_to_clash(link: str, name: str):
    u = urlsplit(link)
    qs = dict(parse_qsl(u.query, keep_blank_values=True))
    proto = u.scheme
    p = {
        "name": name,
        "type": proto,
        "server": u.hostname,
        "port": int(u.port or 0),
        "udp": True,
    }
    if proto == "vless":
        p["uuid"] = u.username or ""
        p["cipher"] = "auto"
    else:
        p["password"] = u.username or ""

    net = qs.get("type") or qs.get("network") or "tcp"
    p["network"] = net

    security = (qs.get("security") or "").lower()
    if security in ("tls", "reality") or (qs.get("tls") in ("1", "true", "True")):
        p["tls"] = True
        p["skip-cert-verify"] = True

    sni = qs.get("sni") or qs.get("servername") or qs.get("host")
    if sni:
        p["servername"] = sni

    fp = qs.get("fp") or qs.get("fingerprint")
    if fp:
        p["client-fingerprint"] = fp

    flow = qs.get("flow")
    if flow and proto == "vless":
        p["flow"] = flow

    if security == "reality":
        pbk = qs.get("pbk") or qs.get("publicKey") or qs.get("public-key")
        sid = qs.get("sid") or qs.get("shortId") or qs.get("short-id")
        ro = {}
        if pbk:
            ro["public-key"] = pbk
        if sid:
            ro["short-id"] = sid
        if ro:
            p["reality-opts"] = ro

    if net == "ws":
        path = qs.get("path") or "/"
        host = qs.get("host")
        p["ws-opts"] = {"path": path, "headers": {}}
        if host:
            p["ws-opts"]["headers"]["Host"] = host

    if net == "grpc":
        sname = qs.get("serviceName") or qs.get("grpc-service-name") or ""
        p["grpc-opts"] = {"grpc-service-name": sname}

    return p


def ss_to_clash(link: str, name: str):
    u = urlsplit(link)
    server = u.hostname
    port = int(u.port or 0)
    userinfo = u.username or ""
    password = u.password or ""
    cipher = None

    if userinfo and password:
        cipher = userinfo
        pwd = password
    else:
        try:
            if userinfo and not password:
                decoded = base64.urlsafe_b64decode(userinfo + "===").decode("utf-8", "ignore")
                if ":" in decoded:
                    cipher, pwd = decoded.split(":", 1)
                else:
                    cipher, pwd = "aes-128-gcm", ""
            else:
                cipher, pwd = "aes-128-gcm", ""
        except Exception:
            cipher, pwd = "aes-128-gcm", ""

    return {
        "name": name,
        "type": "ss",
        "server": server,
        "port": port,
        "cipher": cipher or "aes-128-gcm",
        "password": pwd,
        "udp": True,
    }


def test_delay(name: str) -> int | None:
    try:
        r = requests.get(
            f"{MIHOMO_API}/proxies/{name}/delay",
            params={"url": PROBE_URL, "timeout": PROBE_TIMEOUT},
            timeout=15,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        delay = data.get("delay", 0)
        if 0 < delay <= MAX_MS:
            return delay
    except Exception:
        pass
    return None


def main():
    if not UPSTREAM:
        raise SystemExit("UPSTREAM_SUB not set")

    print(f"Fetching upstream: {UPSTREAM}")
    try:
        text = requests.get(UPSTREAM, timeout=30).text
    except Exception as e:
        print(f"Fetch error: {e}")
        return

    decoded = decode_upstream(text)
    if decoded:
        print("Decoded base64 upstream")
    else:
        print("Plain text or decode failed")
        decoded = text

    links = []
    for line in decoded.splitlines():
        line = line.strip()
        if line.startswith(("vmess://", "vless://", "trojan://", "ss://")):
            links.append(line)

    print(f"Total links: {len(links)}")

    # 构建 mihomo 节点
    mihomo_proxies = []
    name_to_link = {}
    for i, link in enumerate(links, 1):
        name = f"node-{i:03d}"
        try:
            if link.startswith("vmess://"):
                p = vmess_to_clash(link, name)
            elif link.startswith(("vless://", "trojan://")):
                p = vless_trojan_to_clash(link, name)
            elif link.startswith("ss://"):
                p = ss_to_clash(link, name)
            else:
                continue
            if p and p.get("server") and p.get("port"):
                mihomo_proxies.append(p)
                name_to_link[name] = link
        except Exception as e:
            print(f"  Parse error {name}: {e}")

    print(f"Mihomo proxies parsed: {len(mihomo_proxies)}")
    if not mihomo_proxies:
        print("No valid proxies")
        os.makedirs("output", exist_ok=True)
        open("output/raw.txt", "w").close()
        open("output/base64.txt", "w").close()
        return

    # 写 mihomo 配置
    cfg = {
        "mixed-port": 7890,
        "external-controller": "127.0.0.1:9090",
        "secret": "",
        "mode": "direct",
        "log-level": "error",
        "proxies": mihomo_proxies,
    }
    cfg_path = "/tmp/mihomo_config.yaml"
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)

    # 启动 mihomo
    print("Starting mihomo...")
    proc = subprocess.Popen(
        [MIHOMO_BIN, "-f", cfg_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # 等待 API 就绪
    time.sleep(2)
    api_ready = False
    for i in range(20):
        try:
            r = requests.get(f"{MIHOMO_API}/proxies", timeout=2)
            if r.status_code == 200:
                api_ready = True
                print("Mihomo API ready")
                break
        except Exception:
            pass
        time.sleep(1)

    if not api_ready:
        print("ERROR: mihomo API not ready")
        proc.terminate()
        proc.wait()
        return

    # 真连接测试
    names = list(name_to_link.keys())
    print(f"Testing {len(names)} proxies...")
    valid = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        future_to_name = {ex.submit(test_delay, n): n for n in names}
        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                delay = future.result(timeout=15)
                if delay:
                    valid[name] = delay
                    print(f"  OK {name}: {delay}ms")
                else:
                    print(f"  FAIL {name}")
            except Exception as e:
                print(f"  FAIL {name}: {e}")

    # 停止 mihomo
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()

    print(f"Valid proxies: {len(valid)}")

    # 按延迟排序，host:port 去重
    results = []
    for name, delay in valid.items():
        link = name_to_link[name]
        host, port = extract_host_port(link)
        if not host or not port:
            continue
        results.append({
            "link": add_allow_insecure(link),
            "host": host,
            "port": port,
            "delay": delay,
        })

    results.sort(key=lambda x: x["delay"])
    seen = set()
    unique = []
    for r in results:
        key = f"{r['host']}:{r['port']}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(r)

    raw = "\n".join([r["link"] for r in unique]) + "\n" if unique else ""

    os.makedirs("output", exist_ok=True)
    with open("output/raw.txt", "w", encoding="utf-8") as f:
        f.write(raw)
    with open("output/base64.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(raw.encode("utf-8")).decode("ascii"))

    print(f"Final unique: {len(unique)}")
    print("Written: output/raw.txt, output/base64.txt")


if __name__ == "__main__":
    main()
