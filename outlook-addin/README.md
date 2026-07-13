# UniPhishGuard Outlook Add-in

This folder has the Outlook add-in files.

## Main Files

- `manifest.xml` tells Outlook how to load the add-in.
- `taskpane.html` is the side panel page.
- `taskpane.js` reads the opened email with Office.js.
- The task pane sends the email details to the backend.

## Install Tooling

```powershell
cd C:\Users\rama\UniPhishGuard\outlook-addin
npm install
npm run certs
```

## Start Add-in Server

```powershell
npm run start
```

This serves the task pane at:

```text
https://localhost:3000/taskpane.html
```

## Validate and Sideload

```powershell
npm run validate
npm run sideload
```

The sideload command uses `--no-debug`, so Outlook should not show the debug
handler popup each time.

Keep the backend running at `https://localhost:8000` while testing.
