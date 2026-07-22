# Microsoft Entra Production Setup

This must be done by someone with access to the ADU Microsoft tenant.

## 1. Create App Registration

In Microsoft Entra admin center:

1. Create an app registration for UniPhishGuard.
2. Set the supported account type required by ADU.
3. Add the hosted add-in URL as a web redirect URI.
4. Expose an API and create an Application ID URI.
5. Grant Office add-in SSO scopes required by the manifest.

## 2. Update Backend Environment

Set these on the hosted backend:

```text
REQUIRE_AUTH=true
ENTRA_TENANT_ID=<ADU tenant ID>
ENTRA_CLIENT_ID=<app registration client ID>
ALLOWED_ORIGINS=https://<hosted add-in site>
```

Do not use `UNIPHISHGUARD_API_TOKEN` for production once Entra is configured.

## 3. Update Production Manifest

Replace the placeholders in:

```text
outlook-addin/manifest.production.xml
```

Required values:

- hosted add-in URL
- hosted backend URL
- Entra client ID
- Application ID URI

## 4. Validate

From the project root:

```powershell
cd backend
python check_production_config.py
```

The command fails if required environment variables or manifest values are missing.

## 5. Admin Consent and Deployment

Upload the production manifest through Microsoft 365 admin center and grant the required admin consent before pilot testing.
