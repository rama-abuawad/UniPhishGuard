# UniPhishGuard

AI-powered phishing detection system for university email environments.

UniPhishGuard is built as an Outlook task-pane add-in connected to a FastAPI
backend. The add-in extracts safe metadata from the opened email, sends it to
the backend, and displays an explainable phishing risk report.

## Repository Structure

```text
backend/          FastAPI API, phishing checks, scoring, and future AI model code
outlook-addin/    Outlook task-pane UI, Office.js email extraction, manifest
docs/             Roadmap, API contract, and team responsibilities
```

## Current Prototype Flow

```text
Outlook Email
  -> Scan with UniPhishGuard
  -> Extract email information
  -> Send to FastAPI
  -> Technical analysis + AI placeholder
  -> Risk score and verdict
  -> Display report in Outlook
```

## Features

- Outlook task-pane prototype with a Scan Email button
- Subject, sender, body, header, and attachment extraction
- FastAPI `/analyze-email` endpoint
- Sender and Reply-To mismatch checks
- SPF, DKIM, and DMARC result parsing
- URL and attachment indicator analysis
- Explainable risk score and verdict
- Placeholder AI module ready for a trained classifier

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

### Outlook Add-in

The add-in files live in `outlook-addin/`. For local development, serve this
folder over HTTPS and sideload `outlook-addin/manifest.xml` in Outlook.

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

Initial prototype scaffold is ready for local integration testing.
