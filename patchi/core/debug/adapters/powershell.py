from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
import textwrap
from pathlib import Path

_log = logging.getLogger("patchi.debug.adapters.powershell")


class PowerShellDebugAdapter:
    def __init__(self, script: str | Path, args: list[str] | None = None):
        self._script = Path(script).resolve()
        self._args = args or []

    def available(self) -> bool:
        return _find_pwsh() is not None

    def capture_exception(self, timeout: float = 60) -> dict | None:
        pwsh_path = _find_pwsh()
        if pwsh_path is None:
            _log.warning("pwsh not found on PATH")
            return None

        harness_code = _build_harness(self._script, self._args)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ps1", delete=False, encoding="utf-8"
        ) as f:
            f.write(harness_code)
            tmp_path = Path(f.name)

        try:
            proc = subprocess.run(
                [str(pwsh_path), "-NoProfile", "-File", str(tmp_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            _log.warning("pwsh harness timed out after %s seconds", timeout)
            return None
        finally:
            tmp_path.unlink(missing_ok=True)

        if proc.returncode == 0:
            return None

        for line in proc.stdout.splitlines():
            stripped = line.strip()
            prefix = "PATCHI_DEBUG_CAPTURE:"
            if stripped.startswith(prefix):
                try:
                    return json.loads(stripped[len(prefix):])
                except json.JSONDecodeError:
                    _log.warning("PATCHI_DEBUG_CAPTURE JSON parse error: %.200s", stripped)
                    return None

        _log.debug(
            "pwsh exited code=%d but no PATCHI_DEBUG_CAPTURE token in stdout",
            proc.returncode,
        )
        return None

    def _resolve_variables(self, var_ref: int, max_depth: int = 2, depth: int = 0) -> dict:
        raise NotImplementedError("PowerShell adapter uses harness, not DAP protocol")


def _find_pwsh() -> Path | None:
    try:
        result = subprocess.run(
            ["where", "pwsh"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                p = Path(line.strip())
                if p.is_file():
                    return p
    except (subprocess.SubprocessError, OSError):
        pass
    return None


def _ps_quote(s: str) -> str:
    """PowerShell single-quote a string, doubling any embedded single quotes."""
    return "'" + s.replace("'", "''") + "'"


def _build_harness(script: Path, args: list[str] | None) -> str:
    script_quoted = _ps_quote(str(script))
    # args passed as a param block at top of target script, or use splatting
    # For simplicity, we'll set $args before dot-sourcing
    args_setup = ""
    if args:
        args_vals = ", ".join(_ps_quote(a) for a in args)
        args_setup = f"$args = @({args_vals})"
    return textwrap.dedent(f"""\
        $ErrorActionPreference = 'Stop'
        {args_setup}

        $__skip = @(
            '$', '^', '?', '_', 'args', 'input', 'true', 'false', 'null',
            'Host', 'MyInvocation', 'ExecutionContext', 'PSBoundParameters',
            'PSVersionTable', 'PSCulture', 'PSUICulture', 'PSEdition', 'ShellId',
            'HOME', 'PID', 'IsCoreCLR', 'IsWindows', 'IsLinux', 'IsMacOS',
            'PSCommandPath', 'PSScriptRoot', 'PSHOME', 'PSModulePath',
            'EnabledExperimentalFeatures', 'Error', 'ErrorActionPreference',
            'ProgressPreference', 'VerbosePreference', 'DebugPreference',
            'WarningPreference', 'InformationPreference', 'ConfirmPreference',
            'WhatIfPreference', 'NestedPromptLevel', 'FormatEnumerationLimit',
            'MaximumHistoryCount', 'OutputEncoding', 'PSDefaultParameterValues',
            'PSEmailServer', 'PSNativeCommandArgumentPassing',
            'PSNativeCommandUseErrorActionPreference', 'PSSessionApplicationName',
            'PSSessionConfigurationName', 'PSSessionOption', 'PSStyle', 'PWD',
            'PROFILE', 'StackTrace', 'PSItem'
        )

        try {{
            . {script_quoted}
        }} catch {{
            $__err = $_
            $__capture = @{{
                exception = "$($__err.Exception.GetType().Name): $($__err.Exception.Message)"
                thread_id = 1
                frames = @()
            }}

            # Parse ScriptStackTrace for frames
            $__stackText = $__err.ScriptStackTrace
            if ($__stackText) {{
                $__lines = $__stackText -split "`r?`n" | Where-Object {{ $_ -match '^at\\s' }}
                foreach ($__line in $__lines) {{
                    # Format: "at <Function>, <Path>: line <Number>"
                    if ($__line -match '^at\\s+(.+?),\\s+(.+?):\\s*line\\s+(\\d+)') {{
                        $__func = $matches[1].Trim()
                        $__path = $matches[2].Trim()
                        $__lineNum = [int]$matches[3]
                        $__capture.frames += @{{
                            name = $__func
                            path = $__path
                            line = $__lineNum
                            locals = @{{}}
                        }}
                    }}
                }}
            }}

            # Add InvocationInfo frame if not already in stack
            $__inv = $__err.InvocationInfo
            if ($__inv -and $__inv.ScriptName) {{
                $__found = $false
                foreach ($__f in $__capture.frames) {{
                    if ($__f.path -eq $__inv.ScriptName -and $__f.line -eq $__inv.ScriptLineNumber) {{
                        $__found = $true
                        break
                    }}
                }}
                if (-not $__found) {{
                    $__capture.frames += @{{
                        name = if ($__inv.CommandName) {{ $__inv.CommandName }} else {{ '<ScriptBlock>' }}
                        path = $__inv.ScriptName
                        line = $__inv.ScriptLineNumber
                        locals = @{{}}
                    }}
                }}
            }}

# Capture script-level variables from scope 0 (catch scope = script scope due to dot-source)
        $__locals = @{{}}
        $__vars = Get-Variable -Scope 0 -ErrorAction SilentlyContinue
        foreach ($__v in $__vars) {{
            $__n = $__v.Name
            # Skip internal harness vars (__*), automatic vars, preference vars, and regex match vars
            if ($__n -notlike '__*' -and $__n -notlike '*Preference' -and $__n -notin $__skip -and $__n -notin @('foreach','switch','Error','ErrorView','MyInvocation','PSBoundParameters','PSVersionTable','PSCulture','PSUICulture','PSEdition','ShellId','HOME','PID','IsCoreCLR','IsWindows','IsLinux','IsMacOS','PSCommandPath','PSScriptRoot','PSHOME','PSModulePath','EnabledExperimentalFeatures','ErrorActionPreference','ProgressPreference','VerbosePreference','DebugPreference','WarningPreference','InformationPreference','ConfirmPreference','WhatIfPreference','NestedPromptLevel','FormatEnumerationLimit','MaximumHistoryCount','OutputEncoding','PSDefaultParameterValues','PSEmailServer','PSNativeCommandArgumentPassing','PSNativeCommandUseErrorActionPreference','PSSessionApplicationName','PSSessionConfigurationName','PSSessionOption','PSStyle','PWD','PROFILE','StackTrace','PSItem','?','_','args','input','true','false','null','$','^','Host','ExecutionContext','matches')) {{
                try {{
                    if ($null -ne $__v.Value) {{
                        $__val = "$($__v.Value)"
                        if ($__val.Length -gt 200) {{ $__val = $__val.Substring(0,200) + '...' }}
                    }} else {{
                        $__val = '$null'
                    }}
                }} catch {{
                    $__val = '{{?}}'
                }}
                $__locals[$__n] = $__val
            }}
        }}
            # Assign captured locals to the SCRIPT frame (index 1 = script level), not function frame
            if ($__capture.frames.Count -gt 1) {{
                $__capture.frames[1].locals = $__locals
            }} elseif ($__capture.frames.Count -gt 0) {{
                $__capture.frames[0].locals = $__locals
            }}

            try {{
                $__json = $__capture | ConvertTo-Json -Depth 10 -Compress
                Write-Output "PATCHI_DEBUG_CAPTURE:$__json"
            }} catch {{
                Write-Output "PATCHI_DEBUG_CAPTURE:SERIALIZE_FAILED"
            }}
            exit 1
        }}
        """)