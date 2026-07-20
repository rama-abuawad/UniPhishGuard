# Outlook Add-in Testing

Outlook add-ins use web files, but Outlook loads them through `manifest.xml`.
That is why we test the page in the browser first and then sideload it.

## 1. Install Backend Dependencies

```powershell
cd backend
python -m pip install -r requirements.txt
```

## 2. Install Add-in Dependencies and HTTPS Certificates

```powershell
cd outlook-addin
npm install
npm run certs
```

Accept the certificate prompt if Windows asks. Outlook needs HTTPS.

## 3. Start the Backend Over HTTPS

```powershell
cd backend
.\run_https.ps1
```

If you are using Command Prompt instead of PowerShell:

```cmd
cd backend
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

This checks that the backend is running and Edge trusts the local certificate.

## 4. Start the Add-in HTTPS Server

Open a second PowerShell window:

```powershell
cd outlook-addin
npm run start
```

Check:

```text
https://localhost:3000/taskpane.html
```

## 5. Validate the Manifest

Open a third PowerShell window:

```powershell
cd outlook-addin
npm run validate
```

## 6. Sideload Into Outlook

Try the automated sideload command:

```powershell
cd outlook-addin
npm run sideload
```

This starts the add-in without the debug popup.

If this command does not work, manually sideload `outlook-addin/manifest.xml`
from Outlook's add-in page.

## Expected Add-in Flow

1. Open Outlook.
2. Open an email.
3. Click UniPhishGuard or Scan Email from the message read ribbon.
4. The task pane opens inside Outlook.
5. Click Scan Email.
6. UniPhishGuard sends the email details to `https://localhost:8000`.
7. The task pane shows the verdict, risk score, indicators, and actions.

## Important Notes

- Keep both servers running while testing.
- The backend and task pane must use HTTPS for real Outlook testing.
- Browser testing is useful, but the final demo should be inside Outlook.
