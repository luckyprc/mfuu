#!/usr/bin/env python3
"""订阅内容获取、TCP延迟测试、去重、输出"""

import os
import re
import json
import base64
import time
import asyncio
import socket
import ipaddress
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit
import requests

UPSTREAM_SUB = os.environ.get("UPSTREAM_SUB", "").strip()
MAX_LATENCY_MS = int(os.environ.get("MAX_LATENCY_MS", "800"))
CONNECT_TIMEOUT_SEC = float(os.environ.get("CONNECT_TIMEOUT_SEC", "3"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "100"))

OUT_RAW = "output/raw.txt"
OUT_B64 = "output/base64.txt"
OUT_RAW_INSECURE = "output/raw.insecure.txt"
OUT_B64_INSECURE = "output/base64.insecure.txt"
OUT_JSON = "output/nodes.json"

SCHEMES = ("vmess://", "vless://", "trojan://", "ss://")


def try_b64_decode(s: str) -> str | None:
    t = s.strip()
    if not t:
        return None
    if any(x in t for x in SCHEMES):
        return None
    t_clean = re.sub(r'\s+', '', t)
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", t_clean):
        return None
    try:
        raw = base64.b64decode(t_clean, validate=False).decode("utf-8", "ignore")
        if any(line.startswith(SCHEMES) for line in raw.splitlines()):
            return raw
    except Exception:
        return None
    return None


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
        uuid = (data.get("id") or "").strip()
        tls_like = str(data.get("tls") or "").lower() in ("tls", "reality")
        return host, port, uuid, tls_like, data
    except Exception:
        return None


def extract_host_port_identity_tls(link: str):
    link = link.strip()
    if not link.startswith(SCHEMES):
        return None

    if link.startswith("vmess://"):
        r = parse_vmess(link)
        if not r:
            return None
        host, port, uuid, tls_like, _ = r
        return host, port, ("vmess", uuid), tls_like

    if link.startswith(("vless://", "trojan://")):
        try:
            u = urlsplit(link)
            host = (u.hostname or "").strip("[]")
            port = int(u.port or 0)
            qs = dict(parse_qsl(u.query, keep_blank_values=True))
            security = (qs.get("security") or "").lower()
            tls_like = security in ("tls", "reality") or (qs.get("tls") in ("1", "true", "True"))
            proto = "vless" if link.startswith("vless://") else "trojan"
            identity = (u.username or "").strip()
            return host, port, (proto, identity), tls_like
        except Exception:
            return None

    if link.startswith("ss://"):
        try:
            u = urlsplit(link)
            host = (u.hostname or "").strip("[]")
            port = int(u.port or 0)
            return host, port, ("ss", f"{host}:{port}"), False
        except Exception:
            return None

    return None


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


async def tcp_latency_ms(host: str, port: int, timeout: float) -> int | None:
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return int((time.per
