# UniPhishGuard API Contract

## `POST /analyze-email`

Checks email details sent by the Outlook add-in.

### Request Body

```json
{
  "subject": "Urgent password reset",
  "sender": {
    "name": "IT Support",
    "email": "support@example.com"
  },
  "reply_to": "external-reply@example.net",
  "body": "Please verify your account...",
  "headers": "Authentication-Results: spf=pass dkim=pass dmarc=fail",
  "attachments": [
    {
      "name": "invoice.pdf.exe",
      "content_type": "application/octet-stream",
      "size": 51200
    }
  ]
}
```

### Response Body

```json
{
  "scan_id": 1,
  "scanned_at": "2026-07-13 14:30:00",
  "verdict": "Likely phishing",
  "risk_score": 72,
  "ai_prediction": "phishing",
  "ai_confidence": 0.62,
  "url_count": 1,
  "attachment_count": 1,
  "indicators": [
    {
      "code": "reply_to_mismatch",
      "severity": "medium",
      "message": "Reply-To domain is different from sender domain."
    }
  ],
  "recommended_actions": [
    "Do not click links or open attachments.",
    "Check the sender using an official university channel."
  ]
}
```

## Privacy Notes

- The add-in sends the email body to the backend for checking.
- Later versions should not store full email bodies unless the university allows it.
- Store the result and indicators instead of the full email when possible.

## `GET /history`

Returns recent scan results saved by the backend.

### Response Body

```json
[
  {
    "scan_id": 1,
    "scanned_at": "2026-07-13 14:30:00",
    "subject": "Urgent password reset",
    "sender": "support@example.com",
    "verdict": "Likely phishing",
    "risk_score": 72,
    "indicator_count": 3
  }
]
```
