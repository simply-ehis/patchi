import re, os
patterns = ['/v2', '/brain-map', '/council', '/attack-timeline', '/live-tests', '/hosted']
for f in os.listdir('patchi/web/routes'):
    if f.endswith('.py'):
        path = f'patchi/web/routes/{f}'
        c = open(path, encoding='utf-8').read()
        for p in patterns:
            if p in c and '@router.get' in c:
                # Check if the route is in a @router.get
                idx = c.find(p)
                if idx != -1:
                    # Look back for @router.get
                    before = c[max(0, idx-100):idx]
                    if '@router.get' in before or '@router.post' in before:
                        print(f"{f}: {p}")