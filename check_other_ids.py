import re
for f in ['brain_map_v2.html', 'council_v2.html', 'attack_timeline_v2.html', 'live_tests_v2.html']:
    c = open(f"patchi/web/templates_v2/{f}", encoding="utf-8").read()
    ids = re.findall(r'id=["\']([^"\']+)', c)
    print(f"=== {f} ===")
    for id in sorted(set(ids)):
        print(f"  {id}")