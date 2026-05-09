from server_doctor.model.server import HttpProbeResult
from server_doctor.scanner.http_probe import (
    is_exposed_sensitive_path,
    is_sensitive_path_soft_404,
)


def test_sensitive_composer_manifest_is_exposed():
    result = HttpProbeResult(
        url="https://example.com/composer.json",
        method="GET",
        status_code=200,
        final_url="https://example.com/composer.json",
        redirect_chain=[],
        headers={},
        body_sample='{"require": {"laravel/framework": "^11.0"}}',
        error=None,
        elapsed_ms=10,
    )

    assert is_exposed_sensitive_path(result) is True


def test_sensitive_403_is_not_exposed():
    result = HttpProbeResult(
        url="https://example.com/.env",
        method="GET",
        status_code=403,
        final_url="https://example.com/.env",
        redirect_chain=[],
        headers={},
        body_sample="",
        error=None,
        elapsed_ms=10,
    )

    assert is_exposed_sensitive_path(result) is False


def test_spa_fallback_is_soft_404_not_exposed():
    result = HttpProbeResult(
        url="https://example.com/composer.json",
        method="GET",
        status_code=200,
        final_url="https://example.com/composer.json",
        redirect_chain=[],
        headers={"content-type": "text/html"},
        body_sample='<!doctype html><div id="root"></div>',
        error=None,
        elapsed_ms=10,
    )

    assert is_exposed_sensitive_path(result) is False
    assert is_sensitive_path_soft_404(result) is True
