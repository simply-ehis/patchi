import re
c = open("patchi/web/templates_v2/dashboard_v2.html", encoding="utf-8").read()
ids = re.findall(r'id=["\']([^"\']+)', c)
print("IDs in dashboard_v2.html:")
for id in sorted(set(ids)):
    print(f"  {id}")