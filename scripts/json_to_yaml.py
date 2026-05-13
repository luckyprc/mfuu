import json, yaml

with open("output/nodes.json", "r", encoding="utf-8") as f:
    data = json.load(f)

with open("output/nodes.yaml", "w", encoding="utf-8") as f:
    yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)

print("wrote output/nodes.yaml")
