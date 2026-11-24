from __future__ import annotations

import os
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_TIMEOUT: tuple[float, float] = (3.05, 10)


class UnexpectedStatusError(Exception):
    """Raised when the NVD API responds with a non-200 HTTP status code."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"Unexpected HTTP status code: {status_code}")


def build_headers() -> dict[str, str]:
    """Build HTTP headers for NVD API requests without logging secrets."""
    headers: dict[str, str] = {"Accept": "application/json"}
    raw_key = os.getenv("NVD_API_KEY")
    if raw_key is not None:
        cleaned_key = raw_key.strip()
        if cleaned_key:
            headers["apiKey"] = cleaned_key
    return headers


def fetch_response(cve_id: str) -> Any:
    """Fetch a single CVE record from NVD API 2.0 and decode JSON payload."""
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=DEFAULT_TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise UnexpectedStatusError(response.status_code)
    return response.json()
