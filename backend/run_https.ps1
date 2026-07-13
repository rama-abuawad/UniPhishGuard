$ErrorActionPreference = "Stop"

$certFile = Join-Path $env:USERPROFILE ".office-addin-dev-certs\localhost.crt"
$keyFile = Join-Path $env:USERPROFILE ".office-addin-dev-certs\localhost.key"

if (-not (Test-Path -LiteralPath $certFile)) {
    throw "Certificate file not found: $certFile. Run 'npm.cmd run certs' inside outlook-addin first."
}

if (-not (Test-Path -LiteralPath $keyFile)) {
    throw "Key file not found: $keyFile. Run 'npm.cmd run certs' inside outlook-addin first."
}

python -m uvicorn app.main:app --host localhost --port 8000 --ssl-certfile $certFile --ssl-keyfile $keyFile
