# Deploy UniPhishGuard

This setup makes UniPhishGuard available without running CMD on the user's
computer.

## Production Flow

```text
Outlook -> hosted taskpane -> hosted FastAPI backend
```

## 1. Deploy the Backend

Use Render, Azure App Service, Railway, or another Python host.

For Render:

1. Push this repository to GitHub.
2. Create a Render Blueprint from `render.yaml`.
3. Set `ALLOWED_ORIGINS` to the hosted add-in site URL.
4. Set `REQUIRE_AUTH=true`.
5. For a quick demo, set `UNIPHISHGUARD_API_TOKEN` to a secret value.
6. For production, configure Microsoft Entra and set `ENTRA_TENANT_ID` and `ENTRA_CLIENT_ID` instead of using a static token.
7. Optionally tune `MAX_REQUEST_BYTES` and `RATE_LIMIT_MAX_REQUESTS`.
8. After deploy, copy the backend URL.

Health check:

```text
https://your-backend-api.example.com/health
```

## 2. Deploy the Add-in Files

Use Netlify, Azure Static Web Apps, Vercel, or any HTTPS static host.

For Netlify:

1. Connect the GitHub repository.
2. Use `netlify.toml`.
3. Publish directory is `outlook-addin`.
4. After deploy, copy the site URL.

Edit `outlook-addin/taskpane.config.js`:

```js
window.UNIPHISHGUARD_API_BASE_URL = "https://your-backend-api.example.com";
window.UNIPHISHGUARD_ALLOW_API_OVERRIDE = false;
window.UNIPHISHGUARD_API_TOKEN = "";
```

For a real Microsoft 365 rollout, use Office SSO to obtain an Entra token in
the task pane and send it as `Authorization: Bearer <token>`. Keep secrets out
of static add-in files.

## 3. Create the Production Manifest

Copy `outlook-addin/manifest.production.xml` and replace:

```text
https://your-addin-site.example.com
https://your-backend-api.example.com
00000000-0000-0000-0000-000000000000
api://your-addin-site.example.com/00000000-0000-0000-0000-000000000000
```

with the real deployed URLs, Entra application client ID, and application ID URI.

## 4. Install for Users

For one user, sideload the production manifest once.

For real university users, upload the production manifest in the Microsoft 365
admin center:

```text
Microsoft 365 admin center -> Settings -> Integrated apps -> Upload custom apps
```

After that, users open Outlook and use UniPhishGuard without running CMD.

## Production Checklist

- Production config has no `localhost` URLs.
- `UNIPHISHGUARD_ALLOW_API_OVERRIDE` is `false`.
- Backend requires authentication before `/analyze-email` and `/history`.
- Microsoft Entra app registration values are configured when using SSO.
- CORS allows only the hosted add-in URL.
- History retention, request size, and rate limits are set.
- Manifest URLs, rollback steps, logging, and support contact are reviewed.
