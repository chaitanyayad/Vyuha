# Windows convenience wrapper — the Makefile targets without needing make.
#
#   .\vyuha.ps1 setup | test | benchmark | dev | demo | attack A06 | verify | reset

param(
    [Parameter(Position = 0)][string]$Command = "help",
    [Parameter(Position = 1)][string]$Arg = "A04"
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Py = Join-Path $Root ".venv\Scripts\python.exe"
$env:PYTHONPATH = $Root

function Need-Venv {
    if (-not (Test-Path $Py)) {
        throw "No virtualenv found. Run: .\vyuha.ps1 setup"
    }
}

switch ($Command.ToLower()) {
    "setup" {
        python -m venv (Join-Path $Root ".venv")
        & $Py -m pip install --upgrade pip
        & $Py -m pip install -r (Join-Path $Root "requirements.txt")
        Write-Host "`n  ready. next: .\vyuha.ps1 test`n"
    }
    "test"      { Need-Venv; & $Py -m pytest tests -q }
    "benchmark" { Need-Venv; & $Py -m redteam.benchmark }
    "attack"    { Need-Venv; & $Py -m redteam.cli $Arg }
    "verify"    { Need-Venv; & $Py -m redteam.cli --verify }
    "reset"     { Need-Venv; & $Py -m redteam.cli --reset }
    "list"      { Need-Venv; & $Py -m redteam.cli --list }
    "dev"       { Need-Venv; & $Py -m uvicorn gateway.api:app --host 127.0.0.1 --port 8000 --reload }
    "demo" {
        Need-Venv
        & $Py -m redteam.cli --reset
        & $Py -m redteam.benchmark
        Write-Host "`n  Dashboard: http://127.0.0.1:8000`n"
        & $Py -m uvicorn gateway.api:app --host 127.0.0.1 --port 8000
    }
    default {
        Write-Host @"

  .\vyuha.ps1 setup        create .venv and install requirements
  .\vyuha.ps1 test         run the full suite
  .\vyuha.ps1 benchmark    regenerate results.json
  .\vyuha.ps1 dev          serve gateway + dashboard on :8000
  .\vyuha.ps1 demo         reset, benchmark, then serve
  .\vyuha.ps1 attack A06   run one scenario, gateway off then on
  .\vyuha.ps1 list         list all scenarios
  .\vyuha.ps1 verify       re-walk the ledger hash chain
  .\vyuha.ps1 reset        wipe and reseed the database

"@
    }
}
