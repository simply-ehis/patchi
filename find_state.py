c = open("patchi/web/static/dashboard_v2.js", encoding="utf-8").read()
for m in ["const state =", "var state =", "let state ="]:
    i = c.find(m)
    if i != -1:
        print(f"Found at {i}")
        with open("out4.txt", "w", encoding="utf-8") as f:
            f.write(c[i:i+800])
        break