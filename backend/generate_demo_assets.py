"""Generate deterministic, non-confidential committee demo attachments."""

import json
import zipfile
from pathlib import Path

import cv2


ROOT = Path(__file__).resolve().parent
DEMO = ROOT / "demo"


def main() -> None:
    DEMO.mkdir(exist_ok=True)
    qr = cv2.QRCodeEncoder_create().encode("http://192.0.2.10/login")
    qr = cv2.resize(qr, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    cv2.imwrite(str(DEMO / "qr-phishing.png"), qr)
    with zipfile.ZipFile(DEMO / "suspicious.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("invoice.pdf.exe", b"DEMO ONLY - NOT AN EXECUTABLE")

    messages = [
        {"id": "legitimate", "subject": "Class schedule update", "sender": "registrar@adu.ac.ae", "body": "Your class schedule has been updated in the student portal.", "expected": "Low Risk"},
        {"id": "credential-phishing", "subject": "Urgent password verification", "sender": "helpdesk@example.net", "body": "Your account will close today. Sign in at http://192.0.2.10/login.", "expected": "Likely phishing or higher"},
        {"id": "university-impersonation", "subject": "ADU IT account notice", "sender": "support@adu-help.example", "body": "Verify your ADU password at https://aduniversity-login.example/.", "expected": "University impersonation indicators"},
        {"id": "reply-to", "subject": "Payment update", "sender": "finance@adu.ac.ae", "reply_to": "payment@example.net", "body": "Reply with the requested details.", "expected": "Reply-To mismatch"},
        {"id": "deceptive-link", "subject": "Portal", "sender": "notice@example.net", "display": "https://students.adu.ac.ae", "url": "https://evil-login.example/", "expected": "Deceptive hyperlink indicator"},
        {"id": "qr-phishing", "subject": "Scan to sign in", "sender": "notice@example.net", "attachment": "qr-phishing.png", "expected": "QR and IP-address URL indicators"},
        {"id": "malicious-archive", "subject": "Invoice", "sender": "vendor@example.net", "attachment": "suspicious.zip", "expected": "Risky file inside ZIP"},
    ]
    (DEMO / "demo_messages.json").write_text(json.dumps(messages, indent=2) + "\n", encoding="utf-8")
    print(f"Generated demo assets in {DEMO}")


if __name__ == "__main__":
    main()
