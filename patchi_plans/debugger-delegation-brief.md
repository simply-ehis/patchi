# Delegation Brief — Patchi Debugging Layer

## The actual goal (read this before anything else)

This is **not** a general-purpose interactive debugger. Patchi doesn't need breakpoint-driven,
human-in-the-loop stepping through code as a primary feature. The real goal:

> When a test fails, capture the *actual runtime state at the moment of failure* — variable
> values, call stack, the live object graph, not just a static stack trace — and hand that to
> Patchi's existing AI fix-agent pipeline as richer context than "here's the error message and
> the source code."

That's it. That's the whole point. Everything below serves that one goal.

## Where this sits in Patchi's pipeline (this matters — don't build it as a standalone tool)

Patchi has three phases: **Scan** (100% static — tree-sitter parsing, no running code, nothing
to attach a debugger to), **Test** (the *only* phase with an actual running process), and **Fix**
(AI-generated or deterministic patches, applied and re-verified). This debugging layer is
triggered **inside Test, at the moment of failure**, and its output is *consumed by* Fix. It is
not its own phase. Don't build a standalone `p debug` interactive command as the primary
deliverable — that can be a small stretch goal at the end if there's time, not the design center.

## The two halves — and they are NOT equally "just find existing tools"

### Half 1: Debug adapters — genuinely reuse these, don't build them

These are real, mature, standalone processes. Confirmed directly, not assumed:
- **Python: `debugpy`** — a full DAP implementation, decoupled from VS Code, confirmed it can be
  driven by any DAP client, not just the VS Code extension
- **Go: `dlv dap`** (Delve) — has a dedicated headless DAP-only mode built for exactly this
- **JS/TS: `vscode-js-debug`** — can run standalone outside VS Code
- **Rust/C++: `codelldb`**
- **C#: `netcoredbg`**

Install and drive these as separate processes. Do not reimplement per-language debugging logic —
that would be reinventing what these already do well.

### Half 2: The DAP client — this genuinely needs to be built, be honest about that

Checked this directly rather than assuming a library exists: **there is no established,
widely-used lightweight DAP client library** to just import. debugpy's own maintainers, asked
this exact question, said they don't know of one and pointed to their own test suite's minimal
internal client as the closest reference. Some prior art exists (`vimspector`, a Vim plugin;
`debugpy-run`, which just wraps VS Code's remote-attach flow) but nothing that's a clean,
reusable, embeddable Python library.

**Build one lean DAP client**, protocol-generic (DAP is a documented, JSON-over-stdio/socket
protocol — not enormous, but not nothing), that can drive *any* of the adapters above through
the same code path. This is the piece that makes the "reuse existing tools" strategy actually
work — build this once, well, and every language adapter plugs into it the same way.

## What the client actually needs to do (the real workflow)

1. Launch or attach to the process under test via the appropriate adapter (`debugpy`, `dlv dap`, etc.)
2. Set a "break on uncaught exception" condition (DAP supports this — don't hand-roll manual
   breakpoint placement guesswork; use the protocol's real exception-breakpoint capability)
3. When the exception fires: capture the full call stack, and for each frame, the local
   variables and their values (DAP's `stackTrace` + `scopes` + `variables` requests)
4. Serialize this into a **structured, compact format** — not a raw dump. Fix agents have limited
   context budget; this needs to be information-dense, not verbose. Think: "at `foo.py:42`,
   inside `process_order()`, `total` was `None` when the code assumed it was numeric" — not a
   1000-line variable dump.
5. Hand that structured capture to wherever Patchi's existing fix-agent prompt construction
   happens (in the actual codebase: `core/fix/fix_agents.py`) as additional context

## Constraints that matter (Patchi's own established patterns — follow them)

- **Start with Python only.** Get one language working end-to-end, verified against a real
  failing test, before touching a second. Patchi's own codebase is Python, so `debugpy` is the
  natural first target and gives you a real test case immediately.
- **Verify with a real run, not a plausible-looking implementation.** Write an intentionally
  failing test with a clear bug (e.g. a variable that's `None` when it shouldn't be), run the
  full capture pipeline against it for real, and confirm the captured output is actually correct
  and actually useful — not just that the code runs without crashing.
- **Log real failures, never swallow them silently.** If the adapter isn't installed, if attach
  fails, if the process hangs — log it clearly (`logging.getLogger("patchi.debug.<module>")`,
  matching the convention used everywhere else in this codebase) and degrade gracefully (skip
  the rich-context capture, fall back to the plain stack trace Patchi already has) rather than
  breaking the test run itself. A debugging feature must never be the reason a test suite fails
  to report results.
- **This must not slow down the common case.** Only the break-on-exception/capture machinery
  should activate when a test actually fails — passing tests should have zero overhead from this
  feature existing.

## Deliverable format

```
debug-layer-delivery/
  patchi_debug/
    dap_client.py       (the protocol-generic client — the core deliverable)
    adapters/
      python.py         (debugpy-specific launch/attach logic)
    capture.py           (structured capture format + serialization)
  tests/
    test_capture_real_failure.py   (an actual failing test + proof the capture works on it)
  INTEGRATION_NOTES.md   (exactly where in fix_agents.py this plugs in, and how)
```

## One architectural note, not a scope change

The piece of this that launches/attaches to a running process is a genuinely reusable primitive
— a separate, related gap exists where 42 security controls in Patchi's domain taxonomy are
tagged `check_method: "dynamic"` (meaning "can only be verified by actually running the target
and probing it," classic DAST territory) with zero current implementation. That future work
will need the same "launch and manage a running process" capability this debugger client needs.
**Don't scope that in here** — this delegation is Python test-failure debugging only, stay
focused — but write the process-launch code as its own clearly separated piece (not tangled
into debugpy-specific logic) so it's realistic to reuse later, rather than something that has to
be rebuilt from scratch for that next piece of work.

## What NOT to build (explicitly out of scope for this delegation)

- No GUI, no TUI, no interactive stepping UI
- No multi-language support beyond Python for this first pass
- No attempt to make this a general debugging tool for the human user to drive manually — that's
  a possible future stretch feature, not this deliverable
- No changes to Patchi's actual fix-agent logic itself — just get the structured capture ready
  to hand off; wiring it into the AI prompt is a follow-up integration step, not part of this
