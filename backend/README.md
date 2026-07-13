# UniPhishGuard Backend

FastAPI service used by the Outlook add-in.

## Install

```powershell
cd C:\Users\rama\UniPhishGuard\backend
python -m pip install -r requirements.txt
```

For tests:

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest tests
```

## Run for API-Only Testing

```powershell
python -m uvicorn app.main:app --reload --port 8000
```

Open:

```text
http://127.0.0.1:8000/docs
```

## Run for Outlook Add-in Testing

Use HTTPS when testing inside Outlook:

```powershell
.\run_https.ps1
```

From Command Prompt:

```cmd
run_https.cmd
```

Open:

```text
https://localhost:8000/docs
```

For a quick health check:

```text
https://localhost:8000/health
```

The HTTPS certificate files are created by:

```powershell
cd C:\Users\rama\UniPhishGuard\outlook-addin
npm run certs
```
