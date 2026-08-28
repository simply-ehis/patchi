c = open("README.md", encoding="utf-8").read()
c = c.replace("What\u2019s New in 0.7.0-dev", "What\u2019s New in 0.6.0")
open("README.md", "w", encoding="utf-8").write(c)
print("Fixed version in README")