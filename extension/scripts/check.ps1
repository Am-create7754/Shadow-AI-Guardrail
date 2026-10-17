# Run every extension quality gate. Usage (from extension/):  .\scripts\check.ps1
# Exits non-zero on the first failing gate.
$ErrorActionPreference = "Stop"
Push-Location (Join-Path $PSScriptRoot "..")
try {
    $gates = @("lint", "typecheck", "test", "build")
    foreach ($gate in $gates) {
        Write-Host "==> npm run $gate" -ForegroundColor Cyan
        & npm run $gate
        if ($LASTEXITCODE -ne 0) { throw "$gate failed (exit $LASTEXITCODE)" }
    }
    Write-Host "All extension checks passed." -ForegroundColor Green
}
finally {
    Pop-Location
}
