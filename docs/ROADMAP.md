# UniPhishGuard Roadmap

## Phase 1: Project Setup

- Keep backend code in `backend/`.
- Keep Outlook add-in code in `outlook-addin/`.
- Store shared project notes in `docs/`.
- Use `docs/API_CONTRACT.md` so both parts send the same data.

## Phase 2: Outlook Add-in

- Create a task-pane add-in.
- Add a Scan Email button.
- Read the currently opened email.
- Extract subject, sender, body, headers, and attachment details.

## Phase 3: Backend Connection

- Build the FastAPI backend.
- Create an email analysis endpoint.
- Send email data from Outlook to FastAPI.
- Return and display the scan report in Outlook.

## Phase 4: Email Rule Checks

- Detect sender and Reply-To mismatches.
- Parse SPF, DKIM, and DMARC authentication results.
- Extract and analyze URLs.
- Inspect attachment names, content types, and extensions.

## Phase 5: AI Phishing Detection

- Prepare phishing and legitimate email datasets.
- Train a text-classification model.
- Analyze subject and body text.
- Return prediction and confidence.

## Phase 6: Risk Scoring

- Combine AI output with technical indicators.
- Calculate a final score from 0 to 100.
- Assign verdicts: likely legitimate, suspicious, likely phishing, or high-risk
  phishing.

## Phase 7: Report

- Display verdict, risk score, and AI confidence.
- List detected indicators.
- Show recommended actions in the Outlook task pane.

## Phase 8: Data Storage

- Save scan results and history.
- Avoid storing sensitive email content unless allowed.
- Prefer storing indicators instead of the full email.
- Show recent scans from the Outlook task pane.

## Phase 9: Testing and Improvement

- Test legitimate and phishing scenarios.
- Measure false positives and false negatives.
- Improve rules, weights, and model quality.

## Phase 10: Security and Release

- Use HTTPS.
- Validate requests.
- Restrict backend access to approved add-in clients.
- Never execute attachments.
- Test by sideloading first.
- Request university approval before sharing it widely.
