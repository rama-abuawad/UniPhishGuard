# UniPhishGuard

UniPhishGuard is an AI-powered, rule-based phishing detection Outlook add-in designed for university students and staff. It analyzes email content, sender details, authentication results, links, attachments, and QR codes to estimate phishing risk. Users receive a clear risk score, an explanation of the warning signs found, and recommended actions to help them decide whether an email should be trusted or reported to IT.

UniPhishGuard uses two understandable detection methods together:

- A trained text model looks for language patterns learned from labelled legitimate and phishing emails.
- Security rules look for concrete warning signs such as a different Reply-To domain, failed DMARC authentication, misleading links, lookalike university domains, or dangerous attachments.

Neither method makes the decision alone. Their evidence is combined into one result that supports the user and IT team when reviewing the message.

## What happens when an email is scanned

1. The Outlook add-in reads the currently opened email using Office.js.
2. It sends the necessary message information to the local FastAPI backend.
3. The text model estimates whether the email wording resembles known phishing or legitimate messages.
4. Security rules inspect the sender, Reply-To address, SPF/DKIM/DMARC results, links, attachments, QR codes, and university impersonation signs.
5. The backend combines the useful evidence into a risk score from 0 to 100.
6. Outlook displays the result, reasons, and recommended actions.
7. The user can open a prepared Outlook draft to report the email to IT. Nothing is sent automatically.
8. SQLite keeps a small, privacy-aware scan history without storing full message bodies.

## How it works

1. `outlook-addin/taskpane.js` reads the subject, sender, Reply-To, body, internet headers, links, and attachment metadata.
2. FastAPI validates the request and sends it to the email analyzer.
3. A TF-IDF pipeline with calibrated Logistic Regression estimates phishing probability.
4. Deterministic checks inspect sender identity, SPF/DKIM/DMARC results, URLs, attachments, QR links, and university impersonation.
5. Capped score categories combine the model signal and rule evidence into a 0–100 risk score.
6. SQLite retains a limited, redacted, per-user scan history. Full message bodies are not stored.
7. The report action opens a new Outlook draft containing the scan summary; the user chooses the IT recipient and sends it manually.

```text
Outlook + Office.js -> FastAPI -> ML model + rules -> risk report -> SQLite history
```

## Project structure

```text
backend/
  app/
    main.py                 FastAPI routes, authentication, CORS, and rate limits
    schemas.py              Pydantic API and persistence schemas
    analyzer.py             Email checks, scoring, and recommendations
    ai.py                   Model loading and prediction
    config.py               Validated detection configuration
    db.py                   SQLite history storage and retention
    html_text.py            Safe conversion of HTML email into visible text
    rate_limit.py           Lightweight local request limiter
    settings.json           Organization trust and scoring configuration
    email_model.joblib      Trained model artifact
    model_integrity.json    Trusted artifact checksums
    model_metrics.json      Evaluation metrics and selected threshold
  data/
    training_dataset.csv    Consolidated training dataset
    DATASET_CARD.md         Dataset provenance and limitations
  tests/                    Backend security, model, API, and analyzer tests
  train_model.py            TF-IDF + Logistic Regression training
  evaluate_external.py      Evaluation against a separate labelled dataset
outlook-addin/
  manifest.xml              Outlook add-in manifest
  taskpane.html             Task-pane markup
  taskpane.css              Task-pane styles
  taskpane.js               Office.js, API, and UI logic
  taskpane-utils.js         Pure formatting and reporting helpers
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

`APP_ENV` supports `development`, `testing`, and `production`. Development permits the explicitly insecure local identity header so the add-in can be demonstrated without Entra. Production requires Microsoft Entra tenant/client configuration, ignores the client identity header, rejects anonymous history access, and refuses startup with the development history-HMAC secret. Do not put a shared API token in frontend JavaScript.

The prototype rate limiter is bounded and separates authenticated user/IP keys. Proxy headers are ignored unless `TRUST_PROXY_HEADERS=true`. It is process-local and is not reliable across multiple Uvicorn workers or service instances; production scaling should use a shared implementation such as Redis behind the same limiter interface. Enforce the request-body limit at Render or any other reverse proxy as well as in FastAPI.

## Model training

`backend/data/training_dataset.csv` is the only training input. It contains `label` and `text` columns and combines the curated university examples with the final labeled phishing/legitimate corpus.

```powershell
cd backend
python train_model.py
```

Training performs exact-text deduplication, stratified train/validation/test splitting, word and character TF-IDF feature extraction, calibrated Logistic Regression, and validation-set threshold selection. It writes `app/email_model.joblib` and `app/model_metrics.json`.

Splits are group-aware: normalized template fingerprints keep related messages in one partition. Threshold selection targets at least 95% phishing recall by default and then minimizes false positives. Training also writes `app/model_integrity.json` with SHA-256 checksums for the model, metrics, and dataset. Joblib artifacts use pickle-based deserialization and must come only from the trusted offline training process.

Evaluate a completely separate labelled CSV without retraining or merging it into training:

```powershell
cd backend
python evaluate_external.py path\to\external.csv --output external_evaluation_metrics.json
```

The external CSV must contain `label` and `text`. No third-party dataset is downloaded automatically and no external result is claimed until such a dataset is supplied.

The model is an English-focused baseline. Treat its probability as one signal, not proof that a message is malicious. Dataset provenance, licensing, language coverage, class balance, false-positive rate, and false-negative rate should be reviewed before production use.

The complete provenance and limitations record is in [`backend/data/DATASET_CARD.md`](backend/data/DATASET_CARD.md). The consolidated file contains 11,000 records: repository history identifies 1,000 as locally template-generated, while the source and licence for the other 10,000 cannot currently be verified. **Source or licence requires verification before public redistribution.**

Internal evaluation results may not represent real-world university email performance. External validation is required before production use. Current language coverage is primarily English; the project does not claim Arabic or multilingual phishing-detection performance.

## Rule-based analysis

Rules cover:

- sender and Reply-To mismatch;
- SPF, DKIM, DMARC, alignment, forwarding, and unavailable headers;
- misleading link text, IP-address URLs, punycode, shorteners, encoded URLs, and unusual ports;
- dangerous, double-extension, macro-enabled, MIME-mismatched, and archive attachments;
- QR-code links and archive contents within bounded processing limits;
- university-domain lookalikes and fake campus services.

URL analysis is heuristic and does not confirm whether a domain is currently listed as malicious. UniPhishGuard does not send URLs or email content to an external reputation provider.

Authentication results are accepted only from configured trusted `authserv-id` values. Missing results are treated as unavailable, and untrusted `Authentication-Results` headers are not accepted as proof of SPF, DKIM, or DMARC. Header availability and forwarding/ARC behavior vary by Outlook and Exchange configuration, so these checks remain supporting evidence rather than definitive authentication.

Weights and category caps are configured in `backend/app/settings.json`. High-impact rule evidence can outweigh the statistical model, while per-category caps prevent repeated similar indicators from dominating the score.

## Privacy and security

SQLite stores a redacted subject, pseudonymized sender, score, verdict, and scan time. It does not store the full body, headers, attachment contents, or raw sender address. History is scoped by user and trimmed by age and count.

Email content still crosses the network between the add-in and API. Production deployments must use HTTPS, restrictive CORS, authentication, rate limits, protected logs, and an approved retention policy.

The **Report to IT** action opens a draft and never sends automatically or adds the message to training. A safe future feedback workflow is: collect limited feedback, remove sensitive data, have an administrator verify the label, add only approved examples to a controlled dataset, retrain offline, compare against the previous model, and deploy only after validation.

## Future work

- Curate and license representative Arabic phishing samples.
- Evaluate Arabic and mixed Arabic-English messages separately.
- Add reviewed Arabic university-branding and social-engineering terms.
- Validate on an independently sourced university-email dataset.
- Consider an optional reputation-provider interface only after privacy and data-sharing review; no provider is enabled now.

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

Pure task-pane utilities use Node's built-in test runner (`npm test`); Playwright is not used. Manual smoke test: start the HTTPS backend, sideload the validated manifest, open both legitimate and suspicious messages, scan each, inspect technical details and history, open the IT-report draft, verify that no message is sent automatically, and confirm error handling after stopping the backend.

UniPhishGuard estimates phishing risk and supports user and IT review. It does not detect all phishing, and a low-risk result does not guarantee that an email is safe.

## Deployment

`render.yaml` describes the FastAPI service and `netlify.toml` can publish the static add-in. Replace all placeholder origins, configure environment variables, update the single `manifest.xml` with production HTTPS URLs and Entra application details when required, validate it, and then deploy or distribute it through the Microsoft 365 admin workflow.

Before production, verify model performance on representative university email, document dataset rights, add Arabic/mixed-language evaluation if claimed, conduct abuse and privacy review, and arrange a user reporting/escalation process.
