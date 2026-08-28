c = open("patchi/web/static/dashboard_v2.js", encoding="utf-8").read()
with open("begin.txt", "w", encoding="utf-8") as f:
    f.write(c[:500])
print("written")