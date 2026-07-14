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

### Outlook Add-in

- Outlook task pane with a Scan Email button
- Reads the opened email subject, sender, Reply-To, body, headers, links, and attachments
- Browser preview mode with sample email data for quick testing
- Report to IT summary generator inside the task pane
- Scan history view for recent email checks

### Backend Analysis

- FastAPI `/analyze-email` endpoint
- Rule-based phishing indicators
- AI text prediction with confidence score
- Sender and Reply-To mismatch detection
- SPF, DKIM, and DMARC authentication parsing
- Clear authentication warnings, including user-friendly DKIM explanations
- Suspicious URL checks, including IP-address links and unusual domains
- Attachment checks for dangerous extensions and double-extension files
- Local SQLite scan history without storing full email bodies

### Phishing Category Detection

- Credential Theft
- Business Email Compromise
- Scholarship Scam
- Internship Scam
- Fake HR
- Invoice Scam
- Malware Delivery
- Microsoft Login Scam

Categories are only shown when there is real suspicious context, so normal
emails that mention words like internship, scholarship, HR, or Microsoft 365 are
not marked suspicious just because of those keywords.

### University-Specific Detection

- Trusted university and Microsoft domain whitelist
- ADU domain checks for `adu.ac.ae`, `info.adu.ac.ae`, and `students.adu.ac.ae`
- ADU SharePoint/OneDrive link trust for legitimate student file links
- Fake ADU lookalike detection, such as `adu-help.com` or `aduniversity-login.com`
- Fake campus-service detection for:
  - HR
  - Student Affairs
  - IT Helpdesk
  - Blackboard
  - Microsoft 365
  - Scholarships
  - Internships

### Threat Level Meter

- Safe
- Suspicious
- High Risk
- Critical
- Colored risk gauge in the Outlook task pane
- Risk score remains visible as a number out of 100

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
