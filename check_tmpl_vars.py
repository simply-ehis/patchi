import re
c = open(r"C:\Users\ehis\source\repos\Patchi_COMPLETE\patchi\web\templates_v2\dashboard_v2.html", encoding="utf-8").read()
# Find all {{ variable }} not inside init.
for m in re.finditer(r'\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}', c):
    var = m.group(1)
    if not var.startswith('init.'):
        print(var)