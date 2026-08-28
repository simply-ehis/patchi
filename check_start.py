c = open("patchi/web/static/dashboard_v2.js", encoding="utf-8").read()
idx = c.find("const state = {")
ctx = c[max(0, idx-100):idx+200]
with open("ctx.txt", "w", encoding="utf-8") as f:
    f.write(ctx)
print("written")