# UniPhishGuard

Phishing detection add-in for university email environments.

UniPhishGuard is an Outlook add-in connected to a FastAPI backend. It sends
details from the opened email to the backend and shows a phishing risk report.

## Repository Structure

```text
backend/          FastAPI backend and phishing checks
outlook-addin/    Outlook add-in UI and manifest
docs/             Roadmap and setup notes
```

## Current Flow

```text
Outlook Email
  -> Scan with UniPhishGuard
  -> Read email details
  -> Send to FastAPI
  -> Rule checks + AI text prediction
  -> Risk score and verdict
  -> Display report in Outlook
```

## Features

- Outlook add-in with a Scan Email button
- Subject, sender, body, header, and attachment extraction
- FastAPI `/analyze-email` endpoint
- Sender and Reply-To mismatch checks
- SPF, DKIM, and DMARC result parsing
- URL and attachment indicator analysis
- Risk score and verdict
- AI text prediction with confidence score
- Scan history without storing the full email body
- Local SQLite storage for scan results

## Quick Start

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Open `http://127.0.0.1:8000/docs` to test the API.

Train or retrain the AI text model:

```powershell
cd backend
python train_model.py
```

The training data is in `backend/data/training_emails.csv`. It has 1000 labeled
emails generated from university and phishing templates. Training metrics are
saved to `backend/app/model_metrics.json`.

### Outlook Add-in

The add-in files are in `outlook-addin/`. For local testing, serve this folder
over HTTPS and sideload `outlook-addin/manifest.xml` in Outlook.

See `docs/OUTLOOK_SIDELOADING.md` for the full Outlook testing flow.

Short version:

```powershell
cd outlook-addin
npm install
npm run certs
npm run start
```

In another terminal, run the backend over HTTPS:

```powershell
cd backend
.\run_https.ps1
```

Then validate and sideload the manifest:

```powershell
cd outlook-addin
npm run validate
npm run sideload
```

## Status

Final local version is ready for Outlook testing.
