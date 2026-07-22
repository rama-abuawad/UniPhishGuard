$ErrorActionPreference = "Stop"

Write-Host "Setting up UniPhishGuard..."

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  throw "Python was not found. Install Python, then run this script again."
}

if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
  throw "npm was not found. Install Node.js, then run this script again."
}

Push-Location "$PSScriptRoot\backend"
try {
  python -m pip install -r requirements.txt
} finally {
  Pop-Location
}

Push-Location "$PSScriptRoot\outlook-addin"
try {
  npm.cmd install
  npm.cmd run certs
} finally {
  Pop-Location
}

Write-Host "Setup complete. Run .\start-dev.ps1 to start local testing."
