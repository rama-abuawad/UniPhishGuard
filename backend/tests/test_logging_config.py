import logging

from app.logging_config import RequestIdFilter


def test_request_id_filter_supplies_default_for_lifecycle_log() -> None:
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "startup", (), None)
    assert RequestIdFilter().filter(record) is True
    assert record.request_id == "-"


def test_request_id_filter_preserves_explicit_request_id() -> None:
    record = logging.LogRecord("test", logging.ERROR, __file__, 1, "failed", (), None)
    record.request_id = "request-123"
    RequestIdFilter().filter(record)
    assert record.request_id == "request-123"
