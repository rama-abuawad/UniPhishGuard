$ErrorActionPreference = "Stop"
$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$certificate = Join-Path $PSScriptRoot ".certs\localhost.crt"
$key = Join-Path $PSScriptRoot ".certs\localhost.key"

if (-not (Test-Path -LiteralPath $python)) {
    throw "The backend virtual environment is missing. Run: py -m venv .venv"
}
if (-not (Test-Path -LiteralPath $certificate) -or -not (Test-Path -LiteralPath $key)) {
    throw "The local certificate is missing. Run: npm run certs from the outlook-addin directory."
}

Set-Location $PSScriptRoot
& $python -m uvicorn app.main:app --host localhost --port 8000 `
    --ssl-certfile $certificate --ssl-keyfile $key
exit $LASTEXITCODE
