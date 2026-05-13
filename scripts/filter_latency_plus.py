#!/usr/bin/env python3
"""订阅内容获取、真连接测试(mihomo API)、去重、输出"""

import os
import re
import json
import base64
import time
import asyncio
import socket
import ipaddress
import subprocess
import concurrent.futures
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit
import requests
import yaml

UPSTREAM_SUB = os.environ.get("UPSTREAM_SUB", "").strip()
MAX_LATENCY_MS = int(os.environ.get("MAX_LATENCY_MS", "800"))
PROBE_URL = os.environ.get("PROBE_URL", "http://connectivitycheck.platform.hicloud.com/generate_204")
PROBE_TIMEOUT_MS = int(os.environ.get("PROBE_TIMEOUT_MS", "5000"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "50"))

OUT_RAW = "output/raw.txt"
OUT_B64 = "output/base64.txt"
OUT_RAW_INSECURE = "output/raw.insecure.txt"
OUT_B64_INSECURE = "output/base64.insecure.txt"
OUT_JSON = "output/nodes.json"

SCHEMES = ("vmess://", "vless://", "trojan://", "ss://")
MIHOMO_BIN = "/tmp/mihomo"
MIHOMO_API = "http://127.0.0.1:9090"


# ========== 订阅解码 ==========

def try_b64_decode(s: str) -> str | None:
    t = s.strip()
    if not t:
        return None
    if any(x in t for x in SCHEMES):
        return None
    t_clean = ''.join(t.split())
    if len(t_clean) < 20:
        return None
    try:
        raw = base64.b64decode(t_clean, validate=False).decode("utf-8", "ignore")
        if any(line.startswith(SCHEMES) for line in raw.splitlines()):
            return raw
    except Exception:
        pass
    try:
        raw = base64.urlsafe_b64decode(t_clean + '==', validate=False).decode("utf-8", "ignore")
        if any(line.startswith(SCHEMES) for line in raw.splitlines()):
            return raw
    except Exception:
        pass
    return None


# ========== 链接解析（用于去重和输出） ==========

def parse_vmess(link: str):
    try:
        payload = link[len("vmess://"):]
        pad = 4 - len(payload) % 4
        if pad != 4:
            payload += "=" * pad
        data = json.loads(base64.b64decode(payload, validate=False).decode("utf-8", "ignore"))
        host = (data.get("add") or "").strip()
        port_raw = str(data.get("port", "") or "").strip()
        port = int(port_raw) if port_raw else 0
        return host, port
    except Exception:
        return None, 0


def extract_host_port(link: str):
    link = link.strip()
    if not link.startswith(SCHEMES):
        return None, 0

    if link.startswith("vmess://"):
        return parse_vmess(link)

    try:
        u = urlsplit(link)
        host = (u.hostname or "").strip("[]")
        port = int(u.port or 0)
        return host, port
    except Exception:
        return None, 0


def is_junk_host_port(host: str, port: int) -> bool:
    if not host or port <= 0 or port > 65535:
        return True
    hl = host.lower()
    if hl in ("localhost", "0.0.0.0", "127.0.0.1"):
        return True
    return False


async def resolve_ips(host: str):
    try:
        infos = await asyncio.get_event_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ips = []
        for af, _, _, _, sa in infos:
            ips.append(sa[0])
        return list(dict.fromkeys(ips))
    except Exception:
        return []


def has_private_or_loopback_ip(ips):
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                return True
        except Exception:
            continue
    return False


def make_insecure_link(link: str) -> str:
    if link.startswith(("vless://", "trojan://")):
        u = urlsplit(link)
        qs = dict(parse_qsl(u.query, keep_blank_values=True))
        qs["allowInsecure"] = "1"
        new_query = urlencode(list(qs.items()))
        return urlunsplit((u.scheme, u.netloc, u.path, new_query, u.fragment))
    return link


# ========== Clash/Mihomo 配置转换 ==========

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


def vless_or_trojan_to_clash(link: str, name: str):
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


# ========== Mihomo 真连接测试 ==========

def generate_mihomo_config(proxies: list):
    return {
        "mixed-port": 7890,
        "external-controller": "127.0.0.1:9090",
        "secret": "",
        "mode": "direct",
        "log-level": "error",
        "proxies": proxies,
    }


def test_proxy_delay(name: str, probe_url: str, timeout_ms: int, max_ms: int) -> int | None:
    try:
        r = requests.get(
            f"{MIHOMO_API}/proxies/{name}/delay",
            params={"url": probe_url, "timeout": timeout_ms},
            timeout=15,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        delay = data.get("delay", 0)
        if delay and 0 < delay <= max_ms:
            return delay
    except Exception:
        pass
    return None


def test_all_proxies(proxy_names: list, probe_url: str, timeout_ms: int, max_ms: int, workers: int):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_name = {
            executor.submit(test_proxy_delay, name, probe_url, timeout_ms, max_ms): name
            for name in proxy_names
        }
        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                delay = future.result(timeout=15)
                if delay:
                    results[name] = delay
                    print(f"  OK {name}: {delay}ms")
                else:
                    print(f"  FAIL {name}: timeout/error")
            except Exception as e:
                print(f"  FAIL {name}: {e}")
    return results


# ========== 主流程 ==========

async def main():
    if not UPSTREAM_SUB:
        raise SystemExit("UPSTREAM_SUB env not set")

    print(f"Fetching upstream: {UPSTREAM_SUB}")
    try:
        resp = requests.get(UPSTREAM_SUB, timeout=30)
        resp.raise_for_status()
        text = resp.text
    except Exception as e:
        print(f"ERROR fetching upstream: {e}")
        text = ""

    print(f"Upstream length: {len(text)}")
    if len(text) > 200:
        print(f"Upstream preview: {text[:200]}")

    decoded = try_b64_decode(text)
    if decoded is not None:
        print("Decoded base64 upstream")
        text = decoded
    else:
        print("Upstream treated as plain text")

    links = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(SCHEMES):
            links.append(line)
    links = list(dict.fromkeys(links))
    print(f"Total links found: {len(links)}")

    if not links:
        print("WARNING: No proxy links found.")
        os.makedirs("output", exist_ok=True)
        for path in (OUT_RAW, OUT_B64, OUT_RAW_INSECURE, OUT_B64_INSECURE, OUT_JSON):
            with open(path, "w", encoding="utf-8") as f:
                f.write("" if "json" not in path else "{}")
        print("Wrote empty placeholder files.")
        return

    # 预解析：过滤掉明显无效的（无 host/port、私网 IP）
    valid_links = []
    for link in links:
        host, port = extract_host_port(link)
        if is_junk_host_port(host, port):
            continue
        ips = await resolve_ips(host)
        if not ips or has_private_or_loopback_ip(ips):
            continue
        valid_links.append(link)

    print(f"After pre-filter: {len(valid_links)}")

    # 构建 mihomo 节点配置
    mihomo_proxies = []
    name_to_link = {}
    for i, link in enumerate(valid_links, 1):
        name = f"node-{i:03d}"
        try:
            if link.startswith("vmess://"):
                p = vmess_to_clash(link, name)
            elif link.startswith("vless://"):
                p = vless_or_trojan_to_clash(link, name)
            elif link.startswith("trojan://"):
                p = vless_or_trojan_to_clash(link, name)
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
        print("WARNING: No valid proxies for mihomo.")
        os.makedirs("output", exist_ok=True)
        for path in (OUT_RAW, OUT_B64, OUT_RAW_INSECURE, OUT_B64_INSECURE, OUT_JSON):
            with open(path, "w", encoding="utf-8") as f:
                f.write("" if "json" not in path else "{}")
        print("Wrote empty placeholder files.")
        return

    # 启动 mihomo
    cfg = generate_mihomo_config(mihomo_proxies)
    cfg_path = "/tmp/mihomo_config.yaml"
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)

    print("Starting mihomo...")
    proc = subprocess.Popen(
        [MIHOMO_BIN, "-f", cfg_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # 等待 API 就绪
    time.sleep(3)
    api_ready = False
    for i in range(15):
        try:
            r = requests.get(f"{MIHOMO_API}/proxies", timeout=2)
            if r.status_code == 200:
                api_ready = True
                print(f"Mihomo API ready after {i+4}s")
                break
        except Exception:
            pass
        time.sleep(1)

    if not api_ready:
        print("ERROR: mihomo API not ready, aborting.")
        proc.terminate()
        proc.wait()
        return

    # 真连接测试
    proxy_names = list(name_to_link.keys())
    print(f"Testing {len(proxy_names)} proxies via mihomo API...")
    valid_delays = test_all_proxies(proxy_names, PROBE_URL, PROBE_TIMEOUT_MS, MAX_LATENCY_MS, CONCURRENCY)

    # 停止 mihomo
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()

    print(f"Valid proxies passed: {len(valid_delays)}")

    # 构建结果（按延迟排序，host:port 去重）
    results = []
    for name, delay in valid_delays.items():
        link = name_to_link[name]
        host, port = extract_host_port(link)
        if is_junk_host_port(host, port):
            continue
        results.append({
            "link": link,
            "link_insecure_hint": make_insecure_link(link),
            "host": host,
            "port": port,
            "latency_ms": delay,
            "skip_cert_verify": True,
        })

    results.sort(key=lambda x: x["latency_ms"])
    seen_hostport = set()
    kept = []
    for r in results:
        hp = (r["host"], r["port"])
        if hp in seen_hostport:
            continue
        seen_hostport.add(hp)
        kept.append(r)

    raw = "\n".join([r["link"] for r in kept]) + ("\n" if kept else "")
    raw_insecure = "\n".join([r["link_insecure_hint"] for r in kept]) + ("\n" if kept else "")

    os.makedirs("output", exist_ok=True)
    with open(OUT_RAW, "w", encoding="utf-8") as f:
        f.write(raw)
    with open(OUT_B64, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(raw.encode("utf-8")).decode("ascii"))

    with open(OUT_RAW_INSECURE, "w", encoding="utf-8") as f:
        f.write(raw_insecure)
    with open(OUT_B64_INSECURE, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(raw_insecure.encode("utf-8")).decode("ascii"))

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(
            {
                "upstream": UPSTREAM_SUB,
                "max_latency_ms": MAX_LATENCY_MS,
                "probe_url": PROBE_URL,
                "tested": len(proxy_names),
                "passed": len(kept),
                "items": kept,
            },
            f,
            ensure_ascii=False,
            indent=2,
        )

    print(f"Tested={len(proxy_names)} Passed={len(kept)} (real-connect, <= {MAX_LATENCY_MS}ms)")


if __name__ == "__main__":
    asyncio.run(main())
