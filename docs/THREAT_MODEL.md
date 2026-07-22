# STRIDE Threat Model

## Assets

- Email metadata and body text submitted for scanning.
- Sender addresses and scan history.
- Model file and scoring configuration.
- API token or Microsoft Entra bearer token.

## Trust Boundaries

- Outlook add-in to backend API.
- Backend API to local database.
- Backend API to model artifact.
- Production identity provider to backend token validation.

## STRIDE Summary

| Category | Risk | Control |
| --- | --- | --- |
| Spoofing | Fake client calls the API | Token or Entra validation, CORS restrictions |
| Tampering | Modified payload or malformed URLs | Pydantic validation, URL normalization, safe parsing |
| Repudiation | Hard to debug user reports | Request ID header and non-sensitive error logging |
| Information disclosure | Email data in logs/history | No full body logging, HMAC sender pseudonymization, reduced history |
| Denial of service | Huge/repeated requests | Request-size limit, rate limit, bounded history |
| Elevation of privilege | User reads another user's history | Per-user history key from token/mailbox |

## Remaining Production Work

- Use real Microsoft Entra tenant/client configuration.
- Review retention and reporting rules with ADU.
- Enable repository secret scanning and dependency monitoring.
