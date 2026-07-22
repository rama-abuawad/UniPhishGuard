import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_MANIFEST = ROOT / "outlook-addin" / "manifest.production.xml"


def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    if "00000000-0000-0000-0000-000000000000" in value or "your-" in value:
        raise SystemExit(f"Environment variable still has placeholder value: {name}")
    return value


def main() -> None:
    tenant_id = require_env("ENTRA_TENANT_ID")
    client_id = require_env("ENTRA_CLIENT_ID")
    allowed_origins = require_env("ALLOWED_ORIGINS")

    if not PRODUCTION_MANIFEST.exists():
        raise SystemExit("Missing outlook-addin/manifest.production.xml")

    manifest = PRODUCTION_MANIFEST.read_text(encoding="utf-8")
    placeholders = [
        "https://your-addin-site.example.com",
        "https://your-backend-api.example.com",
        "00000000-0000-0000-0000-000000000000",
        "api://your-addin-site.example.com",
    ]
    for placeholder in placeholders:
        if placeholder in manifest:
            raise SystemExit(f"Production manifest still contains placeholder: {placeholder}")

    if client_id not in manifest:
        raise SystemExit("Production manifest does not contain ENTRA_CLIENT_ID.")

    print("Production configuration looks ready.")
    print(f"Tenant: {tenant_id}")
    print(f"Client: {client_id}")
    print(f"Allowed origins: {allowed_origins}")


if __name__ == "__main__":
    main()
