#!/usr/bin/env python3
"""解码上游订阅，强制 allowInsecure=1，去重，输出 raw.txt / base64.txt"""

import os
import re
import json
import base64
import requests
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit

UPSTREAM = os.environ.get("UPSTREAM_SUB", "").strip()


def decode_upstream(text: str) -> str:
    """尝试 base64 解码，失败则返回原文"""
    t = text.strip()
    if not t:
        return ""
    # 如果已经包含明文代理链接，直接返回
    if any(x in t for x in ("vmess://", "vless://", "trojan://", "ss://")):
        return t

    # 剔除空白后尝试标准 / URL-safe base64
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
    """对 vless/trojan 链接强制追加 allowInsecure=1"""
    if not link.startswith(("vless://", "trojan://")):
        return link
    u = urlsplit(link)
    qs = dict(parse_qsl(u.query, keep_blank_values=True))
    qs["allowInsecure"] = "1"
    new_query = urlencode(list(qs.items()))
    return urlunsplit((u.scheme, u.netloc, u.path, new_query, u.fragment))


def extract_host_port(link: str):
    """提取 host:port 用于去重"""
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


def main():
    if not UPSTREAM:
        raise SystemExit("UPSTREAM_SUB not set")

    print(f"Fetching: {UPSTREAM}")
    try:
        text = requests.get(UPSTREAM, timeout=30).text
    except Exception as e:
        print(f"Fetch error: {e}")
        return

    decoded = decode_upstream(text)
    if decoded:
        print("Decoded base64 upstream")
    else:
        print("Upstream treated as plain text (or decode failed)")
        decoded = text

    # 提取所有代理链接
    links = []
    for line in decoded.splitlines():
        line = line.strip()
        if line.startswith(("vmess://", "vless://", "trojan://", "ss://")):
            links.append(line)

    print(f"Total links extracted: {len(links)}")

    # 强制 allowInsecure=1（vless/trojan）
    processed = [add_allow_insecure(link) for link in links]

    # 按 host:port 去重
    seen = set()
    unique = []
    for link in processed:
        host, port = extract_host_port(link)
        if not host or not port:
            continue
        key = f"{host}:{port}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(link)

    raw = "\n".join(unique) + "\n" if unique else ""

    os.makedirs("output", exist_ok=True)
    with open("output/raw.txt", "w", encoding="utf-8") as f:
        f.write(raw)

    with open("output/base64.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(raw.encode("utf-8")).decode("ascii"))

    print(f"Unique after dedup: {len(unique)}")
    print("Written: output/raw.txt, output/base64.txt")


if __name__ == "__main__":
    main()
