#!/usr/bin/env python3
"""从 nodes.json 生成 v2ray-core 配置"""

import json
import base64
from urllib.parse import urlsplit, parse_qsl

IN_REPORT = "output/nodes.json"
OUT_CFG = "output/v2ray-core.insecure.json"


def vmess_to_outbound(link):
    payload = link[len("vmess://"):]
    pad = 4 - len(payload) % 4
    if pad != 4:
        payload += "=" * pad
    d = json.loads(base64.b64decode(payload, validate=False).decode("utf-8", "ignore"))
    host = d.get("add")
    port = int(d.get("port") or 0)
    uuid = d.get("id")
    net = d.get("net", "tcp")
    tls = str(d.get("tls") or "").lower() == "tls"

    ob = {
        "protocol": "vmess",
        "tag": d.get("ps", "vmess"),
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{"id": uuid, "alterId": int(d.get("aid", 0) or 0)}]
            }]
        },
        "streamSettings": {"network": net}
    }
    if tls:
        ob["streamSettings"]["security"] = "tls"
        ob["streamSettings"]["tlsSettings"] = {"allowInsecure": True}
        sni = d.get("sni") or d.get("host")
        if sni:
            ob["streamSettings"]["tlsSettings"]["serverName"] = sni
    return ob


def vless_or_trojan_to_outbound(link):
    u = urlsplit(link)
    qs = dict(parse_qsl(u.query, keep_blank_values=True))
    host = u.hostname
    port = int(u.port or 0)
    user = u.username or ""
    proto = u.scheme
    security = (qs.get("security") or "").lower()

    ob = {
        "protocol": proto,
        "tag": u.fragment or proto,
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{"id": user}] if proto == "vless" else [{"password": user}]
            }]
        },
        "streamSettings": {"network": qs.get("type") or qs.get("network") or "tcp"}
    }

    if security in ("tls", "reality") or (qs.get("tls") in ("1", "true", "True")):
        ob["streamSettings"]["security"] = "tls" if security != "reality" else "reality"
        ob["streamSettings"]["tlsSettings"] = {"allowInsecure": True}
        sni = qs.get("sni") or qs.get("servername")
        if sni:
            ob["streamSettings"]["tlsSettings"]["serverName"] = sni
    return ob


def main():
    import os
    if not os.path.exists(IN_REPORT):
        print(f"skip: {IN_REPORT} not found")
        return

    with open(IN_REPORT, "r", encoding="utf-8") as f:
        report = json.load(f)

    items = report.get("items", [])
    outbounds = [{"protocol": "freedom", "tag": "direct"}]

    for it in items:
        link = it.get("link", "")
        try:
            if link.startswith("vmess://"):
                outbounds.append(vmess_to_outbound(link))
            elif link.startswith(("vless://", "trojan://")):
                outbounds.append(vless_or_trojan_to_outbound(link))
        except Exception:
            continue

    cfg = {
        "log": {"loglevel": "warning"},
        "outbounds": outbounds
    }

    with open(OUT_CFG, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

    print(f"generated {OUT_CFG} outbounds={len(outbounds)-1}")


if __name__ == "__main__":
    main()
