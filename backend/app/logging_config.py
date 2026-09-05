import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path


class RequestIdFilter(logging.Filter):
    """Ensure non-request lifecycle records can use the request-aware format."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = "-"
        return True


def configure_logger(path: Path, app_env: str) -> logging.Logger:
    path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("uniphishguard")
    logger.setLevel(logging.DEBUG if app_env == "development" else logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        handler.addFilter(RequestIdFilter())
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s request_id=%(request_id)s %(message)s"))
        logger.addHandler(handler)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return logger
