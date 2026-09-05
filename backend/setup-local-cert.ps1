$ErrorActionPreference = "Stop"
$sourceDirectory = Join-Path $env:USERPROFILE ".office-addin-dev-certs"
$certificateDirectory = Join-Path $PSScriptRoot ".certs"
$sourceCertificate = Join-Path $sourceDirectory "localhost.crt"
$sourceKey = Join-Path $sourceDirectory "localhost.key"
$targetCertificate = Join-Path $certificateDirectory "localhost.crt"
$targetKey = Join-Path $certificateDirectory "localhost.key"
$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$python = if (Test-Path -LiteralPath $venvPython) { $venvPython } else { (Get-Command py -ErrorAction Stop).Source }

if (-not (Test-Path -LiteralPath $sourceCertificate) -or -not (Test-Path -LiteralPath $sourceKey)) {
    throw "Office development certificates are missing. Run npx office-addin-dev-certs install, accept the trust prompt, and retry."
}
New-Item -ItemType Directory -Force -Path $certificateDirectory | Out-Null
Copy-Item -LiteralPath $sourceCertificate -Destination $targetCertificate -Force
Copy-Item -LiteralPath $sourceKey -Destination $targetKey -Force

$validation = @"
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(r'$targetCertificate', r'$targetKey')
print('Certificate and private key match and can be loaded by Python.')
"@
$validation | & $python -
if ($LASTEXITCODE -ne 0) { throw "The Office certificate and private key could not be loaded." }

Write-Host "Local HTTPS files are ready in backend\.certs."
