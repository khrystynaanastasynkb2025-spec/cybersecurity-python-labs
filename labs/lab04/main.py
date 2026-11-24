from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def _validate_cve_arg(value: str) -> str:
    """Validate --cve CLI option format (case-sensitive)."""
    if not CVE_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "CVE ID must match format CVE-YYYY-NNNN (at least 4 digits in sequence)."
        )
    return value


def _is_valid_variant(value: Any) -> bool:
    """Return True if value is an int in 1..15 and not a bool."""
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 15


def load_response(path: str | Path) -> Any:
    """Read and parse a UTF-8 encoded JSON file from disk."""
    file_path = Path(path)
    content = file_path.read_text(encoding="utf-8")
    return json.loads(content)


def _build_parser() -> argparse.ArgumentParser:
    """Configure command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Inspect an NVD CVE record and apply variant filtering rules."
    )
    parser.add_argument(
        "--cve",
        required=True,
        type=_validate_cve_arg,
        help="Target CVE identifier (e.g., CVE-2099-10001).",
    )
    parser.add_argument(
        "--input",
        default=None,
        help="Optional path to a local UTF-8 JSON NVD response file.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run CLI workflow and return exit code (0, 1, or 2)."""
    if not _is_valid_variant(VARIANT_NUMBER):
        print(
            "Error: VARIANT_NUMBER must be an integer between 1 and 15.",
            file=sys.stderr,
        )
        return 2

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.input is not None:
        try:
            payload = load_response(args.input)
        except OSError:
            print(
                "Error: Unable to read the specified input JSON file.", file=sys.stderr
            )
            return 1
        except UnicodeDecodeError:
            print("Error: Input file is not valid UTF-8.", file=sys.stderr)
            return 1
        except json.JSONDecodeError:
            print("Error: Invalid JSON format in input file.", file=sys.stderr)
            return 1
    else:
        try:
            payload = api_client.fetch_response(args.cve)
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "unknown"
            print(f"Error: NVD API returned HTTP status {status}.", file=sys.stderr)
            return 1
        except api_client.UnexpectedStatusError as exc:
            print(
                f"Error: NVD API returned unexpected HTTP status {exc.status_code}.",
                file=sys.stderr,
            )
            return 1
        except requests.exceptions.Timeout:
            print(
                "Error: Connection or read timeout while querying NVD API.",
                file=sys.stderr,
            )
            return 1
        except requests.exceptions.JSONDecodeError:
            print("Error: Invalid JSON format in NVD API response.", file=sys.stderr)
            return 1
        except requests.exceptions.RequestException:
            print(
                "Error: Network error occurred while querying NVD API.", file=sys.stderr
            )
            return 1

    try:
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except ValueError as exc:
        print(f"Error: Invalid NVD data structure ({exc}).", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
