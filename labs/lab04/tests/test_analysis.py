"""Unit tests for NVD payload validation and Variant 1 rule logic."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from labs.lab04 import analysis


@pytest.mark.parametrize(
    ("score", "attack_vector", "expected_decision"),
    [
        (6.9, "NETWORK", "other"),
        (7.0, "NETWORK", "review"),
        (9.8, "NETWORK", "review"),
        (9.8, "LOCAL", "other"),
    ],
)
def test_variant_1_threshold_and_feature(
    sample_payload: dict[str, Any],
    score: float,
    attack_vector: str,
    expected_decision: str,
) -> None:
    """Check below, on, and above threshold 7.0 and non-matching attackVector."""
    cvss_data = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
        0
    ]["cvssData"]
    cvss_data["baseScore"] = score
    cvss_data["attackVector"] = attack_vector

    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", variant=1)

    assert report["decision"] == expected_decision
    assert report["observed"] == attack_vector
    assert report["score"] == score
    assert report["rule"] == {
        "threshold": 7.0,
        "field": "attackVector",
        "expected": "NETWORK",
    }


def test_not_found_returns_null_data_fields() -> None:
    """Empty vulnerabilities list yields not_found with null data fields."""
    payload = {"vulnerabilities": []}
    record = analysis.extract_record(payload, "CVE-2099-10001")
    assert record is None

    report = analysis.build_report(record, "CVE-2099-10001", variant=1)
    assert report == {
        "cve_id": "CVE-2099-10001",
        "variant": 1,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {
            "threshold": 7.0,
            "field": "attackVector",
            "expected": "NETWORK",
        },
        "observed": None,
        "decision": "not_found",
    }


def test_rejected_status_skips_cvss_analysis(sample_payload: dict[str, Any]) -> None:
    """Rejected status produces decision='rejected' even if a high CVSS score exists."""
    sample_payload["vulnerabilities"][0]["cve"]["vulnStatus"] = "Rejected"
    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", variant=1)

    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_vuln_status_gives_insufficient_data(
    sample_payload: dict[str, Any],
) -> None:
    """Absent vulnStatus produces insufficient_data without analyzing scores."""
    del sample_payload["vulnerabilities"][0]["cve"]["vulnStatus"]
    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", variant=1)

    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["score"] is None


def test_missing_cvss_v31_gives_insufficient_data(
    sample_payload: dict[str, Any],
) -> None:
    """Absent cvssMetricV31 produces insufficient_data."""
    del sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"]
    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", variant=1)

    assert report["decision"] == "insufficient_data"
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_variant_field_gives_insufficient_data(
    sample_payload: dict[str, Any],
) -> None:
    """Absent attackVector in cvssData results in insufficient_data."""
    cvss_data = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
        0
    ]["cvssData"]
    del cvss_data["attackVector"]

    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", variant=1)

    assert report["decision"] == "insufficient_data"
    assert report["observed"] is None


@pytest.mark.parametrize("bad_value", [None, 123, "INTERNET", ""])
def test_invalid_variant_field_raises_value_error(
    sample_payload: dict[str, Any],
    bad_value: Any,
) -> None:
    """Null or disallowed values for attackVector raise ValueError."""
    cvss_data = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
        0
    ]["cvssData"]
    cvss_data["attackVector"] = bad_value

    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    with pytest.raises(ValueError):
        analysis.build_report(record, "CVE-2099-10001", variant=1)


@pytest.mark.parametrize("bad_score", ["9.8", True, float("nan"), float("inf"), 10.5])
def test_invalid_base_score_raises_value_error(
    sample_payload: dict[str, Any],
    bad_score: Any,
) -> None:
    """Non-numeric, boolean, NaN, infinite, or out-of-range scores raise ValueError."""
    cvss_data = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
        0
    ]["cvssData"]
    cvss_data["baseScore"] = bad_score

    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, "CVE-2099-10001")


def test_primary_metric_has_priority_over_earlier_secondary(
    sample_payload: dict[str, Any],
) -> None:
    """First Primary rating is chosen over an earlier Secondary rating."""
    secondary = {
        "source": "cna@example.com",
        "type": "Secondary",
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
            "attackVector": "LOCAL",
            "baseScore": 2.5,
        },
    }
    primary = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [
        secondary,
        primary,
    ]
    snapshot = copy.deepcopy(sample_payload)

    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", variant=1)

    assert sample_payload == snapshot
    assert report["score"] == 9.8
    assert report["score_source"] == "nvd@nist.gov"
    assert report["observed"] == "NETWORK"
    assert report["decision"] == "review"


def test_first_metric_chosen_when_no_primary_exists(
    sample_payload: dict[str, Any],
) -> None:
    """Fallback to the first element when no Primary rating is present."""
    first_secondary = {
        "source": "cna1@example.com",
        "type": "Secondary",
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "attackVector": "LOCAL",
            "baseScore": 6.2,
        },
    }
    second_secondary = {
        "source": "cna2@example.com",
        "type": "Secondary",
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "attackVector": "NETWORK",
            "baseScore": 9.8,
        },
    }
    sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [
        first_secondary,
        second_secondary,
    ]

    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", variant=1)

    assert report["score"] == 6.2
    assert report["score_source"] == "cna1@example.com"
    assert report["observed"] == "LOCAL"
    assert report["decision"] == "other"
