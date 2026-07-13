# UniPhishGuard Backend

FastAPI backend used by the Outlook add-in.

## Install

```powershell
cd C:\Users\rama\UniPhishGuard\backend
python -m pip install -r requirements.txt
```

## Train the ML Model

```powershell
python train_model.py
```

This trains a TF-IDF + Logistic Regression model from
`data/training_emails.csv`, saves it as `app/email_model.joblib`, and writes
test metrics to `app/model_metrics.json`.

To rebuild the 1000-email generated dataset:

```powershell
python generate_training_data.py
python train_model.py
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

Use HTTPS for Outlook testing:

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

The certificate files are created by:

```powershell
cd C:\Users\rama\UniPhishGuard\outlook-addin
npm run certs
```
