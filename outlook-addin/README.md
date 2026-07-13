# UniPhishGuard Outlook Add-in

This folder contains the Outlook task-pane add-in.

## What Makes It an Outlook Add-in

- `manifest.xml` tells Outlook where the add-in appears.
- `taskpane.html` is loaded inside Outlook's side panel.
- `taskpane.js` uses Office.js to read the currently opened email.
- The task pane sends email metadata to the FastAPI backend.

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

Keep the backend running at `https://localhost:8000` while testing.
