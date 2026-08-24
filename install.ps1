# Patchi installer for Windows (PowerShell)
[CmdletBinding()]
param(
    [switch]$CodeQL
)
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  ============================================"
Write-Host "   PATCHI v0.6.0 - Install"
Write-Host "   26 Security Agents · Hosted Guard"
Write-Host "  ============================================"
Write-Host ""

# Check Python version
$python = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd -c "import sys; print(sys.version_info[:2] >= (3, 11))" 2>$null
        if ($ver -eq "True") {
            $python = $cmd
            break
        }
    } catch {}
}

if (-not $python) {
    Write-Host "  Error: Python 3.11+ required. Install from https://python.org"
    exit 1
}

Write-Host "  Using Python $(& $python --version)"

# Create virtual environment (WIRE-09)
$venvDir = Join-Path $PWD ".venv"
if (-not (Test-Path $venvDir)) {
    Write-Host "  Creating virtual environment..."
    & $python -m venv $venvDir
}
$python = Join-Path $venvDir "Scripts\python.exe"

# Install in editable mode
& $python -m pip install -e ".[dev]" --quiet

# ── Security tooling ─────────────────────────────────────────────────────────
# Bandit (Apache-2.0) + Pysa (MIT, via pyre-check) are the default SAST stack.
# Semgrep (LGPL) is optional-heavy; install via `pip install -e ".[security]"`.
Write-Host ""
Write-Host "  Installing security tools (bandit, pyre-check, fb-sapp)..."
& $python -m pip install bandit pyre-check fb-sapp --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Warning: security tool install failed - agents will degrade gracefully."
}

# CodeQL (GitHub, Restricted license) — only with -CodeQL: binary download
# from GitHub releases. Skip by default; it is a large download.
if ($CodeQL) {
    $codeqlDir = Join-Path $env:USERPROFILE "codeql-cli"
    if (-not (Test-Path (Join-Path $codeqlDir "codeql\codeql.exe"))) {
        Write-Host "  Downloading CodeQL CLI (win64) ..."
        $zip = Join-Path $env:TEMP "codeql-win64.zip"
        Invoke-WebRequest -Uri "https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-win64.zip" -OutFile $zip
        New-Item -ItemType Directory -Path $codeqlDir -Force | Out-Null
        Expand-Archive -Path $zip -DestinationPath $codeqlDir -Force
        Remove-Item $zip
    }
    $codeqlBin = Join-Path $codeqlDir "codeql"
    if ($env:PATH -notlike "*$codeqlBin*") {
        Write-Host "  Add to PATH for 'codeql' to work:"
        Write-Host "    setx PATH `"%PATH%;$codeqlBin`""
    }
}

# Create wrapper script in user's path
$scriptsDir = Join-Path $env:USERPROFILE "patchi_scripts"
if (-not (Test-Path $scriptsDir)) {
    New-Item -ItemType Directory -Path $scriptsDir | Out-Null
}

$batContent = "@echo off`r`npatchi %*"
Set-Content -Path (Join-Path $scriptsDir "p.bat") -Value $batContent

# Check if already in PATH
$pathDirs = $env:PATH -split ";"
if ($scriptsDir -notin $pathDirs) {
    Write-Host ""
    Write-Host "  Add to PATH for 'p' alias to work:"
    Write-Host "    setx PATH `"%PATH%;$scriptsDir`""
}

Write-Host ""
Write-Host "  Done! Run 'p init' in your project directory to start."
