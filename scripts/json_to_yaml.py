#!/usr/bin/env python3
"""将 nodes.json 转换为 report.yaml"""

import json
import yaml
import os
import sys

IN_PATH = "output/nodes.json"
OUT_PATH = "output/report.yaml"

def main():
    if not os.path.exists(IN_PATH):
        print(f"skip: {IN_PATH} not found")
        sys.exit(0)

    with open(IN_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    print(f"written {OUT_PATH}")

if __name__ == "__main__":
    main()
