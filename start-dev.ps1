$ErrorActionPreference = "Stop"

$backend = Join-Path $PSScriptRoot "backend"
$addin = Join-Path $PSScriptRoot "outlook-addin"

Write-Host "Starting UniPhishGuard backend..."
Start-Process powershell.exe `
  -WorkingDirectory $backend `
  -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", ".\run_https.ps1" `
  -WindowStyle Hidden

Write-Host "Starting UniPhishGuard Outlook add-in server..."
Start-Process powershell.exe `
  -WorkingDirectory $addin `
  -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", "npm.cmd run start" `
  -WindowStyle Hidden

Write-Host "Backend: https://localhost:8000/health"
Write-Host "Add-in preview: https://localhost:3000/taskpane.html"
Write-Host "Use Outlook sideloading with outlook-addin\manifest.xml for real email scans."
