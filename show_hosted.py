content = open("patchi/cli/registry.py", encoding="utf-8").read()
i = content.find('Command(\n        "hosted"')
print(content[i : i + 800])
