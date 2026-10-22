from aegis.guard.sensitive.engine import mask_text, scan_text


def test_scan_text_finds_email():
    matches = scan_text("notify user@example.com")
    assert any(m.kind == "email" for m in matches)


def test_mask_text_replaces_matches():
    text = "email user@example.com end"
    matches = scan_text(text)
    masked = mask_text(text, matches)
    assert "user@example.com" not in masked
    assert "[REDACTED:EMAIL]" in masked
