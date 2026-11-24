"""Integration and CLI tests for labs.lab04.main."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import main as lab_main


def test_cli_local_input_success(
    tmp_path: Path,
    sample_payload: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Local --input run prints valid JSON report to stdout without network access."""
    input_file = tmp_path / "sample.json"
    input_file.write_text(json.dumps(sample_payload), encoding="utf-8")

    exit_code = lab_main.main(["--cve", "CVE-2099-10001", "--input", str(input_file)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["cve_id"] == "CVE-2099-10001"
    assert report["variant"] == 1
    assert report["decision"] == "review"


def test_cli_missing_input_file_returns_1(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Missing input file exits with code 1 and writes message to stderr."""
    missing_file = tmp_path / "does_not_exist.json"

    exit_code = lab_main.main(["--cve", "CVE-2099-10001", "--input", str(missing_file)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "Error:" in captured.err


def test_cli_invalid_json_file_returns_1(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Malformed JSON file exits with code 1 and writes message to stderr."""
    bad_file = tmp_path / "broken.json"
    bad_file.write_text("{not-valid-json", encoding="utf-8")

    exit_code = lab_main.main(["--cve", "CVE-2099-10001", "--input", str(bad_file)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "Error:" in captured.err


def test_cli_invalid_cve_format_exits_with_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Lowercase or malformed --cve triggers argparse SystemExit(2)."""
    with pytest.raises(SystemExit) as exc_info:
        lab_main.main(["--cve", "cve-2099-10001"])

    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err != ""


@pytest.mark.parametrize("bad_variant", [True, 0, 16, "1"])
def test_cli_invalid_variant_returns_2(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    bad_variant: Any,
) -> None:
    """Invalid VARIANT_NUMBER returns exit code 2 with stderr message."""
    monkeypatch.setattr(lab_main, "VARIANT_NUMBER", bad_variant)

    exit_code = lab_main.main(["--cve", "CVE-2099-10001"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert "VARIANT_NUMBER" in captured.err


def test_cli_network_http_error_does_not_leak_secret(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """HTTP errors print status code to stderr without leaking API keys."""
    monkeypatch.setenv("NVD_API_KEY", "SUPER_SECRET_TOKEN_999")
    err_response = Mock(spec=requests.Response)
    err_response.status_code = 503

    monkeypatch.setattr(
        lab_main.api_client,
        "fetch_response",
        Mock(
            side_effect=requests.exceptions.HTTPError(
                "Service Unavailable", response=err_response
            )
        ),
    )

    exit_code = lab_main.main(["--cve", "CVE-2099-10001"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "503" in captured.err
    assert "SUPER_SECRET_TOKEN_999" not in captured.err
