---
PURPOSE: Documents where and how the debug capture output plugs into
         Patchi's fix-agent pipeline.
OWNS:   patchi/core/debug/
READ-WHEN: Adding a new fix agent that consumes debug context, or wiring
           the existing capture pipeline into CI / test-runner flow.
KEY-FILES: patchi/core/fix/fix_agents.py, patchi/core/debug/capture.py,
           patchi/core/debug/adapters/python.py, patchi/core/debug/adapters/powershell.py,
           patchi/core/debug/adapters/node.py, patchi/core/debug/adapters/codelldb.py
INVARIANTS: capture_exception() never blocks a test from completing.
            Debug output is *extra context*, never a required input.
GOTCHAS: The AI prompt templates in prompts.py need manual updating to
         actually *use* the debug context — the capture output is not
         automatically injected.
UPDATED: 2026-08-02
---

# Debug Layer Integration Notes

## How it's connected (wired in)

The debug capture pipeline is **available** to Patchi's fix-agent flow:

1. `patchi/core/debug/capture.py::debug_context_from_finding()` — checks if a
   finding has ``type == "test_failure"`` and if so, runs the failing test
   script under the debugger harness to capture runtime state. The file path
   is contained to the project root and restricted to harness-capable
   extensions (``.py/.js/.ts/.ps1``), so a malicious finding can never make
   the harness execute arbitrary files.

2. `patchi/core/fix/code_fixer.py` — ``CodeFixer`` calls
   ``debug_context_from_finding()`` before building its prompt and injects a
   ``RUNTIME STATE AT FAILURE`` section into the f-string prompt.

3. `patchi/core/fix/fix_agents.py` — ``_ai_fix()`` (used by ``EnvFixer``,
   ``TypeFixer``, etc.) calls ``debug_context_from_finding()`` and passes
   ``debug_context`` as a template variable to ``build_prompt()``.

4. `patchi/core/ai/prompts.py` — the ``CODE_FIX`` template now includes
   ``{debug_context}`` which renders the runtime capture when present, or
   disappears silently when absent.

**Routing is now wired:** ``UnitTestAgent`` tags ``test_failure`` findings with
``fix_agent="CodeFixer"`` (see ``unit_test_agent.py``). ``CodeFixer._get_findings``
accepts the ``"test_failure"`` type. When a ``test_failure`` finding arrives,
``CodeFixer`` resolves the crash-site file from the debug capture's trigger frame
(``frames[trigger_frame]["path"]``) and patches **that file**, not the test file
(which would weaken tests). The test file content is included in the prompt as
context. Falls back to the finding's file when no debug capture is available.

**Fix → verify → retry loop (``patchi/core/fix/verify_loop.py``):**
``p fix`` routes ``test_failure`` patches through ``run_verify_loop()`` instead of
plain apply. The loop applies the patch, re-runs the **specific failing test
file** from the finding (not just the applier's scoped test phase), and if it
still fails, rolls back and re-runs ``CodeFixer`` with a fresh finding carrying
the newest failure output — up to ``MAX_RETRIES = 2`` retries. A patch whose
only change is a test file is flagged ``requires_review`` (Patch field) and the
risk gate returns ``REQUIRE_REVIEW`` for it even in AUTOPILOT mode, so
weakening a test to make it pass can never auto-apply. Retry patches go through
the same test-file guard.

## Detection rule

A finding triggers debug capture when::

    finding.get("type") == "test_failure"

This matches the ``UnitTestAgent`` finding type. The failing test's relative
path is taken from ``finding.get("file")``.

### How a Python test failure is captured (two paths)

The Python adapter has two harnesses, tried in order:

1. **Standalone exec harness** — runs the file directly and installs a
   ``sys.excepthook`` that walks the traceback and prints structured JSON.
   Catches *module-level* crashes in plain scripts.
2. **Pytest harness** — if the standalone run exits cleanly (``0``) and the
   file looks like a test module (contains ``pytest``/``unittest`` imports or
   ``def test_``/``class Test``), the file is re-run under ``pytest`` with an
   in-process plugin that captures the **first failing test's** traceback and
   locals on ``pytest_runtest_makereport``.

The pytest path exists because a real test module *imports* cleanly — the
failure only happens inside a test function, which a plain ``exec`` cannot
reach. Verified live against ``tests/fixtures/debug_fail_pytest.py``.

## Example output injected into AI prompt

When present, the prompt gains this section::

    RUNTIME STATE AT FAILURE:
    {
      "exception": "TypeError: unsupported operand type(s) for +: 'NoneType' and 'int'",
      "trigger_frame": 0,
      "frames": [
        {
          "name": "process_order",
          "path": "myapp/orders.py",
          "line": 10,
          "locals": { "items": "[]", "total": null }
        }
      ]
    }

## Fallback behaviour

- **Script runs successfully**: returns ``None``, no debug section added.
- **Test file not found / outside project root / unsupported extension**:
  returns ``None``, no debug section added.
- **Finding is not a test failure**: returns ``None``, no overhead.
- **Adapter times out or crashes**: caught in try/except, logged, returns
  ``None``.

## Testing

Run the debug capture tests to confirm the pipeline works::

    pytest tests/test_debug_capture.py tests/test_debug_codelldb.py tests/test_debug_powershell.py tests/test_debug_node.py -v

Run the integration smoke test::

    python -c "from patchi.core.debug import debug_context_from_finding; from pathlib import Path; r = debug_context_from_finding({'type': 'test_failure', 'file': 'tests/fixtures/debug_fail_pytest.py'}, Path('.')); print(r['exception'] if r else 'None')"

## Supported Languages

| Language   | Adapter             | Method           | Runtime Required | Locals captured |
|------------|---------------------|------------------|------------------|-----------------|
| Python     | `adapters/python.py`| excepthook / pytest plugin | Python ≥3.11 | Yes (all user frames) |
| PowerShell | `adapters/powershell.py` | try/catch  | `pwsh` ≥7.0      | Script scope only |
| JavaScript | `adapters/node.py`  | try/catch        | Node.js ≥18      | No (stack-only) |
| Rust/C++   | `adapters/codelldb.py` | DAP over TCP | CodeLLDB binary  | Yes (via DAP) |

**Known limitations (honest):**
- **PowerShell** — the try/catch harness can only read variables visible in
  the *script* scope. Function-scoped locals (e.g. ``$total`` inside
  ``Process-Order``) are unreachable from the catch block and will appear as
  an empty ``locals`` dict on the function frame.
- **JavaScript** — Node's stack traces do not carry variable values, so every
  frame reports empty ``locals``. Capturing JS locals would require driving
  the V8 inspector (``vscode-js-debug``) — out of scope for the current
  harness approach.
- **Rust/C++** — requires a CodeLLDB binary; if absent the adapter returns
  ``None`` gracefully (and the integration test is skipped, not silently
  passed).

For other languages (e.g. Go), implement a new adapter (e.g. ``adapters/go.py`` using
``dlv dap`` via ``DAPClient``) and ``debug_context_from_finding()`` will pick
it up automatically.
