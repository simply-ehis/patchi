c = open("patchi/web/static/dashboard_v2.js", encoding="utf-8").read()
for m in ["(() => {", "(function() {", "(()=>{", "const state", "var state"]:
    i = c.find(m)
    if i != -1:
        print(f"Found '{m}' at {i}")
        with open("out3.txt", "w", encoding="utf-8") as f:
            f.write(c[i:i+2000])
        break