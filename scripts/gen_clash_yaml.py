#!/usr/bin/env python3
"""从 raw.txt 生成 Clash YAML 配置"""

import json
import base64
import yaml
from urllib.parse import urlsplit, parse_qsl, unquote

IN_RAW = "output/raw.txt"
OUT_YAML = "output/clash.yaml"


def safe_name(base, idx):
    base = (base or "").strip() or "node"
    return f"{base}-{idx:03d}"


def parse_vmess(link: str):
    payload = link[len("vmess://"):]
    pad = 4 - len(payload) % 4
    if pad != 4:
        payload += "=" * pad
    d = json.loads(base64.b64decode(payload, validate=False).decode("utf-8", "ignore"))
    server = d.get("add")
    port = int(d.get("port") or 0)
    uuid = d.get("id")
    aid = int(d.get("aid", 0) or 0)
    net = d.get("net", "tcp")
    tls = str(d.get("tls") or "").lower() == "tls"

    p = {
        "type": "vmess",
        "name": d.get("ps") or "vmess",
        "server": server,
        "port": port,
        "uuid": uuid,
        "alterId": aid,
        "cipher": "auto",
        "udp": True,
        "network": net,
    }

    if net == "ws":
        p["ws-opts"] = {"path": d.get("path") or "/", "headers": {}}
        host = d.get("host")
        if host:
            p["ws-opts"]["headers"]["Host"] = host

    if net == "grpc":
        p["grpc-opts"] = {"grpc-service-name": d.get("path") or ""}

    if tls:
        p["tls"] = True
        p["skip-cert-verify"] = True
        sni = d.get("sni") or d.get("host")
        if sni:
            p["servername"] = sni

    return p


def parse_vless_or_trojan(link: str, idx: int):
    u = urlsplit(link)
    qs = dict(parse_qsl(u.query, keep_blank_values=True))
    proto = u.scheme
    server = u.hostname
    port = int(u.port or 0)
    user = u.username or ""

    name = unquote(u.fragment) if u.fragment else proto
    p = {
        "type": proto,
        "name": name,
        "server": server,
        "port": port,
        "udp": True,
    }

    if proto == "vless":
        p["uuid"] = user
        p["cipher"] = "auto"
    else:
        p["password"] = user

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


def parse_ss(link: str):
    u = urlsplit(link)
    server = u.hostname
    port = int(u.port or 0)
    name = unquote(u.fragment) if u.fragment else "ss"

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
        "type": "ss",
        "name": name,
        "server": server,
        "port": port,
        "cipher": cipher or "aes-128-gcm",
        "password": pwd,
        "udp": True,
    }


def main():
    if not os.path.exists(IN_RAW):
        print(f"skip: {IN_RAW} not found")
        return

    with open(IN_RAW, "r", encoding="utf-8") as f:
        lines = [x.strip() for x in f if x.strip()]

    proxies = []
    for i, link in enumerate(lines, 1):
        try:
            if link.startswith("vmess://"):
                p = parse_vmess(link)
                p["name"] = safe_name(p.get("name"), i)
                proxies.append(p)
            elif link.startswith(("vless://", "trojan://")):
                p = parse_vless_or_trojan(link, i)
                p["name"] = safe_name(p.get("name"), i)
                proxies.append(p)
            elif link.startswith("ss://"):
                p = parse_ss(link)
                p["name"] = safe_name(p.get("name"), i)
                proxies.append(p)
        except Exception:
            continue

    cfg = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "warning",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "AUTO",
                "type": "url-test",
                "proxies": [p["name"] for p in proxies],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 600,
            },
            {
                "name": "PROXY",
                "type": "select",
                "proxies": ["AUTO"] + [p["name"] for p in proxies],
            },
        ],
        "rules": ["MATCH,PROXY"],
    }

    with open(OUT_YAML, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)

    print(f"generated {OUT_YAML} proxies={len(proxies)}")


if __name__ == "__main__":
    import os
    main()
