p = "patchi/cli/registry.py"
c = open(p, encoding="utf-8").read()
bad = 'Hosted mode \u2014 monitor live apps" (experimental),'
good = 'Hosted mode \u2014 monitor live apps (experimental)",'
if bad in c:
    c = c.replace(bad, good)
    open(p, "w", encoding="utf-8").write(c)
    print("fixed quoting")
else:
    # fallback: find the substring and reinsert correctly
    needle = "Hosted mode"
    i = c.find(needle)
    j = c.find('apps"', i)
    # current state: 'apps" (experimental),' -> we want 'apps (experimental)"'
    # remove the misplaced (experimental) and reinsert
    k = c.find("(experimental)", j)
    c = c[:j+4] + c[k:k+len("(experimental)")] + '"' + c[k+len("(experimental)"):]
    open(p, "w", encoding="utf-8").write(c)
    print("re-fixed quoting")
k2 = c.find("Hosted mode")
print(repr(c[k2:c.find(chr(10), k2)]))
