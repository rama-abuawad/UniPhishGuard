from prepare_training_data import sanitize_text


def test_sanitize_text_defangs_active_indicators_and_addresses():
    result = sanitize_text("Visit https://bad.example/a and reply to victim@example.com from 192.0.2.1")
    assert "https://" not in result
    assert "victim@example.com" not in result
    assert "192.0.2.1" not in result
    assert "URL" in result and "EMAIL" in result and "IP_ADDRESS" in result
