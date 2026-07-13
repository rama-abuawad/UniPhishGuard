# Outlook Add-in Testing

Outlook add-ins are web apps loaded inside Outlook through a manifest. The
`manifest.xml` file makes UniPhishGuard appear in Outlook as an add-in instead
of a normal browser page.

## 1. Install Backend Dependencies

```powershell
cd C:\Users\rama\UniPhishGuard\backend
python -m pip install -r requirements.txt
```

## 2. Install Add-in Dependencies and Local HTTPS Certificates

```powershell
cd C:\Users\rama\UniPhishGuard\outlook-addin
npm install
npm run certs
```

Accept the certificate trust prompt if Windows asks. Outlook requires the task
pane to load over HTTPS.

## 3. Start the Backend Over HTTPS

```powershell
cd C:\Users\rama\UniPhishGuard\backend
.\run_https.ps1
```

If you are using Command Prompt instead of PowerShell:

```cmd
cd C:\Users\rama\UniPhishGuard\backend
run_https.cmd
```

Check:

```text
https://localhost:8000/docs
```

If Outlook shows `Failed to fetch`, open this URL once in Microsoft Edge and
confirm it shows `{"status":"ok"}`:

```text
https://localhost:8000/health
```

This confirms the backend is running and the local HTTPS certificate is trusted
by the same browser engine Outlook uses.

## 4. Start the Add-in HTTPS Server

Open a second PowerShell window:

```powershell
cd C:\Users\rama\UniPhishGuard\outlook-addin
npm run start
```

Check:

```text
https://localhost:3000/taskpane.html
```

## 5. Validate the Manifest

Open a third PowerShell window:

```powershell
cd C:\Users\rama\UniPhishGuard\outlook-addin
npm run validate
```

## 6. Sideload Into Outlook

Try the automated sideload command:

```powershell
cd C:\Users\rama\UniPhishGuard\outlook-addin
npm run sideload
```

If automated sideloading does not work with your Outlook version, manually
sideload `outlook-addin/manifest.xml` from Outlook's add-in management page.

## Expected Add-in Flow

1. Open Outlook.
2. Open an email.
3. Click UniPhishGuard or Scan Email from the message read ribbon.
4. The task pane opens inside Outlook.
5. Click Scan Email.
6. UniPhishGuard sends the email metadata to `https://localhost:8000`.
7. The task pane shows the verdict, risk score, indicators, and recommended
   actions.

## Important Notes

- Keep both servers running while testing.
- The backend and task pane must use HTTPS for real Outlook testing.
- Browser fallback testing is still possible by opening the task pane directly,
  but the final demo should happen inside Outlook.
