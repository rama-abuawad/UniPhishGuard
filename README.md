# UniPhishGuard

UniPhishGuard is a hybrid AI phishing detector delivered as an Outlook task-pane add-in. The add-in collects data from the opened message with Office.js, sends it to a FastAPI API, and presents a risk score with evidence and recommended actions.

## How it works

1. `outlook-addin/taskpane.js` reads the subject, sender, Reply-To, body, internet headers, links, and attachment metadata.
2. FastAPI validates the request and sends it to the hybrid analyzer.
3. A TF-IDF pipeline with calibrated Logistic Regression estimates phishing probability.
4. Deterministic checks inspect sender identity, SPF/DKIM/DMARC results, URLs, attachments, QR links, and university impersonation.
5. Capped score categories combine the model signal and rule evidence into a 0–100 risk score.
6. SQLite retains a limited, redacted, per-user scan history. Full message bodies are not stored.

```text
Outlook + Office.js -> FastAPI -> ML model + rules -> risk report -> SQLite history
```

## Project structure

```text
backend/
  app/
    main.py                 FastAPI routes, authentication, CORS, and rate limits
    schemas.py              Pydantic API and persistence schemas
    analyzer.py             Rule checks and hybrid risk scoring
    ai.py                   Model loading and prediction
    db.py                   SQLite history storage and retention
    settings.json           Organization trust and scoring configuration
    email_model.joblib      Trained model artifact
    model_metrics.json      Evaluation metrics and selected threshold
  data/training_dataset.csv Final training dataset
  tests/test_analyzer.py    Backend tests
  train_model.py            TF-IDF + Logistic Regression training
outlook-addin/
  manifest.xml              Outlook add-in manifest
  taskpane.html             Task-pane markup
  taskpane.css              Task-pane styles
  taskpane.js               Office.js, API, and UI logic
  assets/                   Required Outlook PNG icons
```

## Local setup

Prerequisites: Python 3.11 or later, Node.js/npm, and Outlook with add-in sideloading enabled.

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --port 8000
```

In another terminal:

```powershell
cd outlook-addin
npm install
npm run certs
npm run start
```

Validate and sideload the add-in:

```powershell
cd outlook-addin
npm run validate
npm run sideload
```

The manifest requires HTTPS. Its local URLs point to the backend-hosted `/addin` static directory. For separate local hosting, update the manifest URLs to `https://localhost:3000`.

## API

- `GET /health`, `/health/live`, `/health/ready` — health checks.
- `POST /api/v1/analyze-email` — analyze an email and store the redacted result.
- `GET /api/v1/history` — return recent scans for the authenticated user.
- `DELETE /api/v1/history` — clear that user's history.

Legacy `/analyze-email` and `/history` aliases remain for the add-in. Interactive API documentation is available at `/docs` during development.

Copy `backend/.env.example` to `.env` and configure allowed origins, limits, retention, and optional API-token or Microsoft Entra authentication. Never place production secrets in `taskpane.js` or commit them to Git.

## Model training

`backend/data/training_dataset.csv` is the only training input. It contains `label` and `text` columns and combines the curated university examples with the final labeled phishing/legitimate corpus.

```powershell
cd backend
python train_model.py
```

Training performs exact-text deduplication, stratified train/validation/test splitting, word and character TF-IDF feature extraction, calibrated Logistic Regression, and validation-set threshold selection. It writes `app/email_model.joblib` and `app/model_metrics.json`.

The model is an English-focused baseline. Treat its probability as one signal, not proof that a message is malicious. Dataset provenance, licensing, language coverage, class balance, false-positive rate, and false-negative rate should be reviewed before production use.

## Rule-based analysis

Rules cover:

- sender and Reply-To mismatch;
- SPF, DKIM, DMARC, alignment, forwarding, and unavailable headers;
- misleading link text, IP-address URLs, punycode, shorteners, encoded URLs, unusual ports, and optional reputation checks;
- dangerous, double-extension, macro-enabled, MIME-mismatched, and archive attachments;
- QR-code links and archive contents within bounded processing limits;
- university-domain lookalikes and fake campus services.

Weights and category caps are configured in `backend/app/settings.json`. High-impact rule evidence can outweigh the statistical model, while per-category caps prevent repeated similar indicators from dominating the score.

## Privacy and security

SQLite stores a redacted subject, pseudonymized sender, score, verdict, and scan time. It does not store the full body, headers, attachment contents, or raw sender address. History is scoped by user and trimmed by age and count.

Email content still crosses the network between the add-in and API. Production deployments must use HTTPS, restrictive CORS, authentication, rate limits, protected logs, and an approved retention policy. URL reputation is optional because it sends URLs to an external provider when configured.

## Testing

```powershell
cd backend
python -m pytest
python -m compileall -q app tests train_model.py

cd ..\outlook-addin
node --check taskpane.js
npm run validate
```

The retained automated suite is backend-focused. Playwright and frontend automated tests were intentionally removed to keep the project small; the Outlook task pane should be smoke-tested through sideloading after UI changes.

## Deployment

`render.yaml` describes the FastAPI service and `netlify.toml` can publish the static add-in. Replace all placeholder origins, configure environment variables, update the single `manifest.xml` with production HTTPS URLs and Entra application details when required, validate it, and then deploy or distribute it through the Microsoft 365 admin workflow.

Before production, verify model performance on representative university email, document dataset rights, add Arabic/mixed-language evaluation if claimed, conduct abuse and privacy review, and arrange a user reporting/escalation process.
