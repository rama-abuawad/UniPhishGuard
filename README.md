# UniPhishGuard

UniPhishGuard is an AI-powered, rule-based phishing detection Outlook add-in designed for university students and staff. It analyzes email content, sender details, authentication results, links, attachments, and QR codes to estimate phishing risk. Users receive a clear risk score, an explanation of the warning signs found, and recommended actions to help them decide whether an email should be trusted or reported to IT.

UniPhishGuard uses two understandable detection methods together:

- A trained text model looks for language patterns learned from labelled legitimate and phishing emails.
- Security rules look for concrete warning signs such as a different Reply-To domain, failed DMARC authentication, misleading links, lookalike university domains, or dangerous attachments.

Machine learning can increase suspicion and recommend review, while high-risk phishing classifications rely on corroborating technical evidence whenever possible. UniPhishGuard is a decision-support tool; it does not replace the university secure email gateway, SOC, or IT investigation process.

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

1. `outlook-addin/taskpane.js` reads the subject, sender, Reply-To, body, available internet headers, links, and attachment metadata. On Outlook clients supporting Mailbox 1.8, it also retrieves bounded attachment content for QR, ZIP, and hash inspection.
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
    training_dataset.csv    Attributed, source-aware training dataset
    DATASET_CARD.md         Dataset provenance and limitations
  tests/                    Backend security, model, API, and analyzer tests
  prepare_training_data.py  Licensed-corpus preparation and sanitization
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

## Run the Outlook add-in locally

Prerequisites: Python 3.14, Node.js/npm, and classic Outlook for Windows with add-in sideloading available. The saved model was trained with Python 3.14.3, scikit-learn 1.9.0, and joblib 1.5.3; the exact scikit-learn and joblib versions are pinned for artifact compatibility.

The current manifest loads both the task pane and API from `https://localhost:8000`. FastAPI serves the files in `outlook-addin/` under `/addin`, so `npm run start` is not needed.

### First-time setup

Open **Command Prompt (CMD)** in the cloned `UniPhishGuard` folder, then install the add-in dependencies and local HTTPS certificate:

```bat
cd outlook-addin
npm install
npm run certs
npm run validate
```

Accept the certificate trust prompt if Windows displays one. Return to the project folder and install the Python dependencies:

```bat
cd ..\backend
python -m pip install -r requirements-dev.txt
```

### Start UniPhishGuard

Open a Command Prompt window in the `UniPhishGuard` folder and start the HTTPS backend:

```bat
cd backend
python -m uvicorn app.main:app --host localhost --port 8000 --ssl-certfile "%USERPROFILE%\.office-addin-dev-certs\localhost.crt" --ssl-keyfile "%USERPROFILE%\.office-addin-dev-certs\localhost.key"
```

Keep that window open. Confirm that the backend responds by opening `https://localhost:8000/health` in a browser. A JSON health response means the backend and certificate are working.

Open a second Command Prompt window in the `UniPhishGuard` folder and sideload the manifest:

```bat
cd outlook-addin
npm run validate
npm run sideload
```

Keep the backend running, open an email in classic Outlook, open **UniPhishGuard**, and select **Scan Email**.

To stop the sideloaded debugging session later, run:

```bat
cd outlook-addin
npm run stop
```

If startup reports that port 8000 is already in use, an older backend process is still running. Close its Command Prompt window before starting the backend again. Do not change the port unless the URLs in `outlook-addin/manifest.xml` are changed to match.

## API

- `GET /health`, `/health/live`, `/health/ready` — health checks.
- `POST /api/v1/analyze-email` — analyze an email and store the redacted result.
- `GET /api/v1/history` — return recent scans for the authenticated user.
- `DELETE /api/v1/history` — clear that user's history.

Legacy `/analyze-email` and `/history` aliases remain for the add-in. Interactive API documentation is available at `/docs` during development.

Copy `backend/.env.example` to `backend/.env` and configure allowed origins, limits, retention, organization domains, trusted authentication servers, and authentication. The application loads this file during package initialization. Never place production secrets in frontend JavaScript or commit them to Git.

`APP_ENV` supports `development`, `testing`, and `production`, and startup logs the selected mode without logging secrets. Development permits the local identity header for demonstrations. Production requires Microsoft Entra tenant/client configuration and a strong history HMAC secret, ignores the client identity header, rejects anonymous access, validates JWT signature, issuer, tenant, audience, expiry and claims, and fails startup instead of downgrading to development authentication. The project validates backend tokens but does not claim complete production Microsoft SSO until the operator has completed and tested the matching Entra app registration and Outlook deployment configuration.

The prototype rate limiter is bounded and separates authenticated user/IP keys. Proxy headers are ignored unless `TRUST_PROXY_HEADERS=true`. It is process-local and is not reliable across multiple Uvicorn workers or service instances; production scaling should use a shared implementation such as Redis behind the same limiter interface. Enforce the request-body limit at Render or any other reverse proxy as well as in FastAPI.

## Model training

`backend/data/training_dataset.csv` is the only training input. It contains `label`, `text`, `source`, `template_id`, `is_synthetic`, and `split` columns. The dataset combines real CC BY 4.0 phishing mail from the Nazario corpus, legitimate ham from the CC BY 4.0 Figshare curated release, and a small deduplicated set of reviewed university hard cases. Spam rows are excluded rather than treated as phishing. Full provenance, source notices, limitations, and evaluation counts are documented in `backend/data/DATASET_CARD.md`.

```powershell
cd backend
python train_model.py
```

Training verifies the declared source-aware splits, checks for group leakage, performs word and character TF-IDF feature extraction, fits calibrated Logistic Regression with group-aware calibration folds, and selects the decision threshold on validation data. The 2025 Nazario phishing messages are reserved for testing. It stages and publishes `app/email_model.joblib`, `app/model_metrics.json`, and `app/model_integrity.json` together so stale checksums are not silently trusted.

Splits are group-aware: normalized template fingerprints keep related messages in one partition. Threshold selection targets at least 95% phishing recall by default and then minimizes false positives. Training also writes `app/model_integrity.json` with SHA-256 checksums for the model, metrics, and dataset. Joblib artifacts use pickle-based deserialization and must come only from the trusted offline training process.

Evaluate a completely separate labelled CSV without retraining or merging it into training:

```powershell
cd backend
python evaluate_external.py path\to\external.csv --output external_evaluation_metrics.json
```

The external CSV must contain `label` and `text`. No third-party dataset is downloaded automatically and no external result is claimed until such a dataset is supplied.

The model is an English-focused baseline. Treat its probability as one signal, not proof that a message is malicious. Dataset provenance, licensing, language coverage, class balance, false-positive rate, and false-negative rate should be reviewed before production use.

The complete provenance and limitations record is in [`backend/data/DATASET_CARD.md`](backend/data/DATASET_CARD.md). The consolidated file contains 11,000 records: repository history identifies 1,000 as locally template-generated, while the source and licence for the other 10,000 cannot currently be verified. **Source or licence requires verification before public redistribution.**

The saved text model records 98.03% accuracy, 98.69% phishing precision, and 84.30% phishing recall on the source-aware test split, including 446 unseen Nazario phishing emails from 2025. This is an **Internal grouped holdout evaluation**, not guaranteed real-world accuracy or an end-to-end detector metric. Current language coverage is primarily English; the project does not claim Arabic or multilingual phishing-detection performance.

## Rule-based analysis

Rules cover:

- sender and Reply-To mismatch;
- SPF, DKIM, DMARC, alignment, forwarding, and unavailable headers;
- misleading link text, IP-address URLs, punycode, shorteners, encoded URLs, and unusual ports;
- dangerous, double-extension, macro-enabled, MIME-mismatched, and archive attachments;
- QR-code links and ZIP contents when Outlook supplies supported attachment bytes, within bounded processing limits;
- university-domain lookalikes and fake campus services.

URL analysis is heuristic and does not confirm whether a domain is currently listed as malicious. UniPhishGuard does not send URLs or email content to an external reputation provider.

Authentication results are accepted only from configured trusted `authserv-id` values. Missing results are treated as unavailable, and untrusted `Authentication-Results` headers are not accepted as proof of SPF, DKIM, or DMARC. Header availability and forwarding/ARC behavior vary by Outlook and Exchange configuration, so these checks remain supporting evidence rather than definitive authentication.

Weights, category caps, and verdict thresholds are configured in `backend/app/settings.json`. High-confidence AI-only evidence can recommend review but is capped below the high-risk classifications; corroborating technical evidence enables stronger scores. Per-category caps prevent repeated similar indicators from dominating the score.

## Privacy and security

SQLite stores a redacted subject, pseudonymized sender, score, verdict, and scan time. It does not store the full body, headers, attachment contents, credentials, tokens, or raw sender address. History is scoped by user and enforces the configured age and item-count limits.

Email content still crosses the network between the add-in and API. Production deployments must use HTTPS, restrictive CORS, authentication, rate limits, protected logs, and an approved retention policy.

The **Report to IT** action opens a draft and never sends automatically, deletes, quarantines, or adds the message to training. The draft includes the scan ID, available Internet Message ID, sender, subject, timestamp, score, verdict, categories, important rule indicators, and URL/attachment counts without including the email body or ML probability. The recipient remains empty unless an operator configures a recipient workflow.

## Outlook capabilities and production URLs

The manifest keeps Mailbox 1.5 compatibility. Internet headers and attachment content require Mailbox 1.8; the add-in checks support at runtime and reports unavailable or partial inspection instead of claiming those checks passed.

Local development uses `https://localhost:8000`. For production, generate a deployment manifest and frontend API configuration without editing application logic:

```bat
cd outlook-addin
npm run configure:production -- --app-url https://addin.example.edu --api-url https://api.example.edu
```

This creates `dist/manifest.xml` and `dist/config.js`. Publish the task-pane files with `dist/config.js` deployed as `config.js`, distribute `dist/manifest.xml`, and validate the production manifest before deployment. Use only real HTTPS origins approved by the university.

## Current limitations and future work

- Curate and license representative Arabic phishing samples.
- Evaluate Arabic and mixed Arabic-English messages separately.
- Add reviewed Arabic university-branding and social-engineering terms.
- Validate on an independently sourced university-email dataset.
- Some Outlook clients do not expose internet headers or attachment bytes; the UI reports those capabilities as unavailable.
- The process-local rate limiter is suitable for the local demo, not a multi-instance production deployment.

## Testing

```powershell
cd backend
python -m pytest
python -m compileall -q app tests train_model.py

cd ..\outlook-addin
node --check taskpane.js
npm test
npm run validate
```

Backend security and integration tests use pytest. Pure task-pane utilities use Node's built-in test runner. Manual Outlook testing remains necessary for Office.js host behavior: start the HTTPS backend, sideload the validated manifest, scan the deterministic scenarios in `backend/demo/`, inspect capabilities and technical details, verify history, open the IT-report draft, and confirm that no message is sent automatically.

UniPhishGuard estimates phishing risk and supports user and IT review. It does not detect all phishing, and a low-risk result does not guarantee that an email is safe.

## Deployment

`render.yaml` describes the FastAPI service and `netlify.toml` can publish the static add-in. Replace all placeholder origins, configure environment variables, update the single `manifest.xml` with production HTTPS URLs and Entra application details when required, validate it, and then deploy or distribute it through the Microsoft 365 admin workflow.

Before production, verify model performance on representative university email, document dataset rights, add Arabic/mixed-language evaluation if claimed, conduct abuse and privacy review, and arrange a user reporting/escalation process.
