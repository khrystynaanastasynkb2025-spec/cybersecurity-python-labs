"""Validation of NVD CVE responses and variant rule evaluation."""

from __future__ import annotations

import math
from typing import Any, TypeGuard

VARIANT_RULES: dict[int, tuple[float, str, str]] = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}

ALLOWED_CVSS_VALUES: dict[str, set[str]] = {
    "attackVector": {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"},
    "attackComplexity": {"LOW", "HIGH"},
    "privilegesRequired": {"NONE", "LOW", "HIGH"},
    "userInteraction": {"NONE", "REQUIRED"},
    "scope": {"UNCHANGED", "CHANGED"},
    "confidentialityImpact": {"NONE", "LOW", "HIGH"},
    "integrityImpact": {"NONE", "LOW", "HIGH"},
    "availabilityImpact": {"NONE", "LOW", "HIGH"},
}


def _is_dict(value: Any) -> TypeGuard[dict[str, Any]]:
    """Return True if value is a dictionary."""
    return isinstance(value, dict)


def _is_list(value: Any) -> TypeGuard[list[Any]]:
    """Return True if value is a list."""
    return isinstance(value, list)


def _is_str(value: Any) -> TypeGuard[str]:
    """Return True if value is a string."""
    return isinstance(value, str)


def _extract_english_description(cve_obj: dict[str, Any]) -> str | None:
    """Validate descriptions list and return the first non-empty English value."""
    if "descriptions" not in cve_obj:
        return None
    descriptions = cve_obj["descriptions"]
    if not _is_list(descriptions):
        raise ValueError("'descriptions' must be a list.")

    english_text: str | None = None
    for entry in descriptions:
        if not _is_dict(entry):
            raise ValueError("Each item in 'descriptions' must be a dict.")
        lang = entry.get("lang")
        value = entry.get("value")
        if not _is_str(lang) or not _is_str(value):
            raise ValueError(
                "Description items must contain string 'lang' and 'value'."
            )
        if english_text is None and lang == "en" and value.strip():
            english_text = value
    return english_text


def _validate_optional_nonempty_str(container: dict[str, Any], key: str) -> str | None:
    """Return None if key is absent, or validate that its value is a non-empty str."""
    if key not in container:
        return None
    val = container[key]
    if not isinstance(val, str) or not val.strip():
        raise ValueError(f"Field '{key}' must be a non-empty string when present.")
    return val


def _extract_cvss_v31(cve_obj: dict[str, Any]) -> dict[str, Any] | None:
    """Extract and validate the selected CVSS v3.1 metric entry."""
    if "metrics" not in cve_obj:
        return None
    metrics = cve_obj["metrics"]
    if not _is_dict(metrics):
        raise ValueError("'metrics' must be a dict.")

    if "cvssMetricV31" not in metrics:
        return None
    metric_list = metrics["cvssMetricV31"]
    if not _is_list(metric_list):
        raise ValueError("'cvssMetricV31' must be a list.")
    if not metric_list:
        return None

    for item in metric_list:
        if not _is_dict(item):
            raise ValueError("Each item in 'cvssMetricV31' must be a dict.")

    selected = next(
        (item for item in metric_list if item.get("type") == "Primary"),
        metric_list[0],
    )

    cvss_data = selected.get("cvssData")
    if not _is_dict(cvss_data):
        raise ValueError("'cvssData' must be a dict.")

    base_score = cvss_data.get("baseScore")
    if (
        isinstance(base_score, bool)
        or not isinstance(base_score, (int, float))
        or not math.isfinite(base_score)
        or not (0.0 <= float(base_score) <= 10.0)
    ):
        raise ValueError("'baseScore' must be a finite number between 0 and 10.")

    version = _validate_optional_nonempty_str(cvss_data, "version")
    if version is not None and version != "3.1":
        raise ValueError("'cvssData.version' must be '3.1'.")

    vector = _validate_optional_nonempty_str(cvss_data, "vectorString")
    score_source = _validate_optional_nonempty_str(selected, "source")

    return {
        "cvss_version": version,
        "score": float(base_score),
        "score_source": score_source,
        "vector": vector,
        "cvss_data": dict(cvss_data),
    }


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Validate NVD response payload and extract normalized CVE data.

    Returns None when the CVE is not found (empty vulnerabilities list).
    Internal record format:
    {
        "cve_id": str,
        "vuln_status": str | None,
        "description": str | None,
        "cvss": {
            "cvss_version": str | None,
            "score": float,
            "score_source": str | None,
            "vector": str | None,
            "cvss_data": dict[str, Any],
        } | None,
    }
    """
    if not _is_dict(payload):
        raise ValueError("NVD payload must be a JSON object.")

    if "vulnerabilities" not in payload or not _is_list(payload["vulnerabilities"]):
        raise ValueError("NVD payload must contain a 'vulnerabilities' list.")

    vulnerabilities = payload["vulnerabilities"]
    if len(vulnerabilities) == 0:
        return None
    if len(vulnerabilities) > 1:
        raise ValueError("Expected at most one vulnerability entry for exact cveId.")

    wrapper = vulnerabilities[0]
    if not _is_dict(wrapper) or not _is_dict(wrapper.get("cve")):
        raise ValueError("Vulnerability entry must contain a 'cve' object.")

    cve_obj = wrapper["cve"]
    if cve_obj.get("id") != cve_id:
        raise ValueError("Returned CVE ID does not match requested CVE ID.")

    vuln_status = _validate_optional_nonempty_str(cve_obj, "vulnStatus")
    description = _extract_english_description(cve_obj)

    if vuln_status == "Rejected" or vuln_status is None:
        cvss_info = None
    else:
        cvss_info = _extract_cvss_v31(cve_obj)

    return {
        "cve_id": cve_id,
        "vuln_status": vuln_status,
        "description": description,
        "cvss": cvss_info,
    }


def build_report(
    record: dict[str, Any] | None,
    cve_id: str,
    variant: int,
) -> dict[str, Any]:
    """Evaluate variant rule on extracted CVE record and build final report."""
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or variant not in VARIANT_RULES
    ):
        raise ValueError("Variant must be an integer between 1 and 15.")

    threshold, field, expected = VARIANT_RULES[variant]
    rule = {
        "threshold": threshold,
        "field": field,
        "expected": expected,
    }

    if record is None:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": None,
            "vuln_status": None,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "not_found",
        }

    if not _is_dict(record):
        raise ValueError("Record must be a dictionary or None.")

    vuln_status = record.get("vuln_status")
    description = record.get("description")

    if vuln_status == "Rejected":
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": description,
            "vuln_status": vuln_status,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "rejected",
        }

    cvss = record.get("cvss")
    if vuln_status is None or cvss is None:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": description,
            "vuln_status": vuln_status,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "insufficient_data",
        }

    cvss_data = cvss["cvss_data"]
    if field not in cvss_data:
        observed: str | None = None
        decision = "insufficient_data"
    else:
        raw_observed = cvss_data[field]
        allowed_values = ALLOWED_CVSS_VALUES[field]
        if not isinstance(raw_observed, str) or raw_observed not in allowed_values:
            raise ValueError(f"Invalid value for CVSS field '{field}'.")
        observed = raw_observed
        score = cvss["score"]
        decision = (
            "review" if (score >= threshold and observed == expected) else "other"
        )

    return {
        "cve_id": cve_id,
        "variant": variant,
        "description": description,
        "vuln_status": vuln_status,
        "cvss_version": cvss["cvss_version"],
        "score": cvss["score"],
        "score_source": cvss["score_source"],
        "vector": cvss["vector"],
        "rule": rule,
        "observed": observed,
        "decision": decision,
    }
