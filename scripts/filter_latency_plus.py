cd /path/to/mfuu

cat > scripts/filter_latency_plus.py << 'PYEOF'
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
    # 剔除所有空白后再判断，避免换行符干扰
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
        return int((time.perf_counter() - start) * 1000)
    except Exception:
        return None


def make_insecure_link(link: str) -> str:
    if link.startswith(("vless://", "trojan://")):
        u = urlsplit(link)
        qs = dict(parse_qsl(u.query, keep_blank_values=True))
        qs["allowInsecure"] = "1"
        new_query = urlencode(list(qs.items()))
        return urlunsplit((u.scheme, u.netloc, u.path, new_query, u.fragment))
    return link


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
        print("WARNING: No proxy links found. Check upstream format.")
        os.makedirs("output", exist_ok=True)
        for path in (OUT_RAW, OUT_B64, OUT_RAW_INSECURE, OUT_B64_INSECURE, OUT_JSON):
            with open(path, "w", encoding="utf-8") as f:
                f.write("" if "json" not in path else "{}")
        print("Wrote empty placeholder files.")
        return

    sem = asyncio.Semaphore(CONCURRENCY)
    results = []

    async def test_one(link: str):
        info = extract_host_port_identity_tls(link)
        if not info:
            return None
        host, port, ident, tls_like = info
        if is_junk_host_port(host, port):
            return None

        async with sem:
            ips = await resolve_ips(host)
            if not ips:
                return None
            if has_private_or_loopback_ip(ips):
                return None
            ms = await tcp_latency_ms(host, port, CONNECT_TIMEOUT_SEC)

        if ms is None or ms > MAX_LATENCY_MS:
            return None

        return {
            "link": link,
            "link_insecure_hint": make_insecure_link(link),
            "host": host,
            "port": port,
            "ips": ips,
            "latency_ms": ms,
            "protocol": ident[0],
            "identity": ident[1],
            "tls_like": tls_like,
            "skip_cert_verify": True
        }

    tasks = [asyncio.create_task(test_one(l)) for l in links]
    for t in asyncio.as_completed(tasks):
        r = await t
        if r:
            results.append(r)

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
                "connect_timeout_sec": CONNECT_TIMEOUT_SEC,
                "concurrency": CONCURRENCY,
                "skip_cert_verify": True,
                "tested": len(links),
                "passed": len(kept),
                "items": kept,
            },
            f,
            ensure_ascii=False,
            indent=2,
        )

    print(f"Tested={len(links)} Passed={len(kept)} (<= {MAX_LATENCY_MS}ms, host:port min kept)")


if __name__ == "__main__":
    asyncio.run(main())
PYEOF

git add scripts/filter_latency_plus.py
git commit -m "fix: strip whitespace before base64 regex match"
git push
