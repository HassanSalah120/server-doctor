from server_doctor.utils.redaction import redact_text, redact_value


def test_env_password_line_is_redacted():
    assert redact_text("DB_PASSWORD=secret") == "DB_PASSWORD=<redacted>"


def test_normal_nginx_config_is_unchanged():
    line = "location / { try_files $uri $uri/ /index.php?$query_string; }"
    assert redact_text(line) == line


def test_private_key_block_is_redacted():
    text = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
    assert redact_text(text) == "<redacted>"


def test_nested_values_are_redacted_without_mutating_original():
    original = {"env": ["APP_KEY=base64:abc"], "password": "secret"}
    redacted = redact_value(original)

    assert redacted["env"] == ["APP_KEY=<redacted>"]
    assert redacted["password"] == "<redacted>"
    assert original["password"] == "secret"
