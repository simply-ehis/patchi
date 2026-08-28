c = open("patchi/web/routes/dashboard_v2.py", encoding="utf-8").read()
for p in ["/v2", "/brain-map", "/council", "/attack-timeline", "/live-tests", "/hosted"]:
    if f'"{p}"' in c:
        print(f"Found {p}")
    else:
        print(f"MISSING {p}")