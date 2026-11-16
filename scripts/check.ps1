# Полная проверка качества для Windows (PowerShell). Аналог scripts/check.sh.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
function Step($title, [scriptblock]$cmd) {
    Write-Host "== $title"
    & $cmd
    if ($LASTEXITCODE -ne 0) { Write-Host "ПРОВАЛ: $title" -ForegroundColor Red; exit $LASTEXITCODE }
}
Step "ruff"           { ruff check . }
Step "ruff format"    { ruff format --check . }
Step "mypy"           { mypy app }
Step "import-linter"  { lint-imports }
Step "pytest"         { python -m pytest @args }
Write-Host "Все проверки пройдены." -ForegroundColor Green
