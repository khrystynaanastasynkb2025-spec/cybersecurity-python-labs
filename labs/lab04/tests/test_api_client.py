"""Unit tests for NVD API HTTP client."""

from __future__ import annotations

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client


def test_build_headers_without_key() -> None:
    """Return only Accept header when NVD_API_KEY is unset."""
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_build_headers_with_whitespace_only_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ignore blank or whitespace-only NVD_API_KEY values."""
    monkeypatch.setenv("NVD_API_KEY", "   \t  ")
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_build_headers_with_fake_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip outer spaces and include apiKey header when NVD_API_KEY is set."""
    monkeypatch.setenv("NVD_API_KEY", "  fake-secret-key-123  ")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-secret-key-123",
    }


def test_fetch_uses_expected_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify URL, params, headers, timeout, and redirect settings."""
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    assert api_client.fetch_response("CVE-2099-10001") == payload
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_raises_on_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Propagate HTTPError when raise_for_status fails."""
    err_response = Mock(spec=requests.Response)
    err_response.status_code = 404
    err_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "Not Found", response=err_response
    )

    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=err_response))

    with pytest.raises(requests.exceptions.HTTPError):
        api_client.fetch_response("CVE-2099-10001")


def test_fetch_raises_on_unexpected_status(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reject non-200 responses such as 302 redirects."""
    redirect_response = Mock(spec=requests.Response)
    redirect_response.status_code = 302
    redirect_response.raise_for_status.return_value = None

    monkeypatch.setattr(
        api_client.requests, "get", Mock(return_value=redirect_response)
    )

    with pytest.raises(api_client.UnexpectedStatusError) as exc_info:
        api_client.fetch_response("CVE-2099-10001")
    assert exc_info.value.status_code == 302


def test_fetch_raises_on_network_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Propagate Timeout exceptions from requests.get."""
    monkeypatch.setattr(
        api_client.requests,
        "get",
        Mock(side_effect=requests.exceptions.Timeout("Timed out")),
    )

    with pytest.raises(requests.exceptions.Timeout):
        api_client.fetch_response("CVE-2099-10001")


def test_fetch_raises_on_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """Propagate JSONDecodeError when response body is not valid JSON."""
    bad_json_response = Mock(spec=requests.Response)
    bad_json_response.status_code = 200
    bad_json_response.raise_for_status.return_value = None
    bad_json_response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )

    monkeypatch.setattr(
        api_client.requests, "get", Mock(return_value=bad_json_response)
    )

    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response("CVE-2099-10001")
