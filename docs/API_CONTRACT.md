# UniPhishGuard API Contract

## `POST /analyze-email`

Analyzes email metadata and content extracted by the Outlook add-in.

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
  "verdict": "Likely phishing",
  "risk_score": 72,
  "ai_prediction": "phishing",
  "ai_confidence": 0.62,
  "indicators": [
    {
      "code": "reply_to_mismatch",
      "severity": "medium",
      "message": "Reply-To domain does not match sender domain."
    }
  ],
  "recommended_actions": [
    "Do not click links or open attachments.",
    "Verify the sender through an official university channel."
  ]
}
```

## Privacy Notes

- The prototype sends the body to the backend for analysis.
- Production deployments should avoid storing full email bodies unless explicit
  authorization exists.
- Store only derived indicators and minimal metadata when possible.
