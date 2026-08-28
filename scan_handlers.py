import re, importlib

content = open("patchi/cli/registry.py", encoding="utf-8").read()
# find all handler specs
handlers = re.findall(r'"(patchi\.cli\.commands\.[a-z_]+):(run\w*)"', content)
# find which commands are namespace_handler
ns_blocks = set()
for m in re.finditer(r'Command\(\s*"(?:[^"]+)"', content):
    # crude: track if namespace_handler=True appears before next Command(
    pass

# Build map: command name -> (handler, is_ns)
# Simpler: parse top-level + subcommand Commands
cmds = []
for m in re.finditer(r'Command\(\s*"([^"]+)"', content):
    start = m.start()
    # find this command block end: next "),\n" at column 4 (top) — but subcommands use deeper indent
    # Heuristic: find the matching close by tracking parentheses
    depth = 0
    i = content.find("(", start)
    j = i
    while j < len(content):
        if content[j] == "(":
            depth += 1
        elif content[j] == ")":
            depth -= 1
            if depth == 0:
                break
        j += 1
    block = content[start : j + 1]
    is_ns = "namespace_handler=True" in block
    hm = re.search(r'"(patchi\.cli\.commands\.[a-z_]+):(run\w*)"', block)
    if hm:
        cmds.append((m.group(1), hm.group(1) + ":" + hm.group(2), is_ns))

print(f"{'CMD':<14} {'NS':<6} {'HANDLER':<55} {'SIG_TAKES_ARGS'}")
problem = []
for name, handler, is_ns in cmds:
    try:
        mod, fn = handler.split(":")
        module = importlib.import_module(mod)
        func = getattr(module, fn)
        import inspect
        sig = inspect.signature(func)
        params = list(sig.parameters)
        takes_args = len(params) >= 1 and params[0] == "args" and params[0] not in sig.parameters or True
        # Determine: does first param accept a single positional 'args' (not **kwargs)?
        first = params[0] if params else None
        is_namespace_style = (first == "args")
        kind = str(sig.parameters[first].kind) if first else "?"
        flag = ""
        if is_namespace_style and not is_ns:
            flag = "  <-- BROKEN"
            problem.append(name)
        print(f"{name:<14} {str(is_ns):<6} {handler:<55} {first}/{kind}{flag}")
    except Exception as e:
        print(f"{name:<14} {str(is_ns):<6} {handler:<55} ERR {e}")

print("\nBROKEN (namespace-style, not flagged):", problem)
