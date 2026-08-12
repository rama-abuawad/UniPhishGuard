"""UniPhishGuard backend package."""
"""UniPhishGuard backend package initialization."""

from pathlib import Path

from dotenv import load_dotenv


# Load backend/.env before application modules read environment variables.
load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)
