# Run every backend quality gate. Usage (from backend/):  .\scripts\check.ps1
# Exits non-zero on the first failing gate.
$ErrorActionPreference = "Stop"
$py = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
Push-Location (Join-Path $PSScriptRoot "..")
try {
    $env:GUARDRAIL_ENVIRONMENT = "test"
    $gates = @(
        @("ruff lint",   @("-m", "ruff", "check", ".")),
        @("ruff format", @("-m", "ruff", "format", "--check", ".")),
        @("mypy",        @("-m", "mypy")),
        @("pytest",      @("-m", "pytest", "-q"))
    )
    foreach ($gate in $gates) {
        Write-Host "==> $($gate[0])" -ForegroundColor Cyan
        & $py @($gate[1])
        if ($LASTEXITCODE -ne 0) { throw "$($gate[0]) failed (exit $LASTEXITCODE)" }
    }
    Write-Host "All checks passed." -ForegroundColor Green
}
finally {
    Pop-Location
}
