# Limitations and Privacy

## Limitations

- The current ML model is an English baseline.
- The project never executes attachment contents.
- If attachment content is provided, the backend can hash it, inspect ZIP metadata with strict limits, and decode QR-code image destinations.
- Outlook may only provide attachment metadata in some clients; in that case content-level checks are shown only when available.
- External URL reputation checking uses Google Web Risk when `GOOGLE_WEB_RISK_API_KEY` is configured.
- Reputation lookups send the complete URLs to Google. Keep the key server-side and obtain university privacy approval before production use.
- Production SSO requires real Microsoft Entra configuration from ADU.

## Privacy

- The backend avoids logging full email bodies.
- Scan history stores reduced metadata.
- Sender identity in history is pseudonymized with keyed HMAC.
- History is separated by user and can be deleted through `/api/v1/history`.
- Retention is bounded in the local database.

## Ethics

UniPhishGuard should support user judgment, not replace it. The UI uses terms such as "likely" and "no strong indicators" instead of claiming an email is completely safe.
