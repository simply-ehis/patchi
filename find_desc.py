content = open("patchi/cli/registry.py", encoding="utf-8").read()
for name in ["hosted", "web"]:
    key = 'Command(\n        "' + name + '"'
    m = content.find(key)
    if m == -1:
        key = 'Command("' + name + '"'
        m = content.find(key)
    if m == -1:
        print(name, "NOT FOUND")
        continue
    end = content.find("),\n", m)
    if end == -1:
        end = m + 400
    block = content[m:end]
    for line in block.split("\n"):
        if "Hosted" in line or "Archived" in line or "monitor live" in line or "dashboard" in line.lower():
            print(name, "->", line.strip())
