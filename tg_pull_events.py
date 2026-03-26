#!/usr/bin/env python3
"""
tg_pull_events.py

Pulls sample/submission data from Cisco Secure Malware Analytics
(formerly Threat Grid) using the /api/v2/samples endpoint and writes
ONLY the raw JSON response to a log file.

Usage:
    python3 tg_pull_events.py                          # defaults to /var/log/Threatgrid.log
    python3 tg_pull_events.py -l /path/to/custom.log   # custom log file path
    python3 tg_pull_events.py --logfile /tmp/tg.log     # long-form flag

Requirements:
  - Python 3.6+
  - requests library (pip install requests)
  - tg_config.py in the same directory (or on PYTHONPATH)

Cisco Secure Malware Analytics API Reference:
  https://panacea.threatgrid.com/mask/doc/mask/index
"""

import argparse
import json
import os
import sys

import requests

# ── Import authentication parameters from the separate config file ──────────
try:
    from tg_config import API_KEY, BASE_URL
except ImportError:
    sys.exit(
        "ERROR: Cannot import tg_config.py. "
        "Ensure tg_config.py exists in the same directory and contains "
        "API_KEY and BASE_URL."
    )

# ── Default log file path ──────────────────────────────────────────────────
DEFAULT_LOG_FILE = "/var/log/Threatgrid.log"


# ── Argument parsing ───────────────────────────────────────────────────────

def parse_arguments() -> argparse.Namespace:
    """
    Parses command-line arguments.

    Returns:
        Namespace with the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Pull sample/submission data from Cisco Secure Malware Analytics "
            "(Threat Grid) and write the JSON events to a log file."
        )
    )
    parser.add_argument(
        "-l", "--logfile",
        type=str,
        default=DEFAULT_LOG_FILE,
        help=(
            f"Path to the output log file. "
            f"Default: {DEFAULT_LOG_FILE}"
        ),
    )
    return parser.parse_args()


# ── API interaction ─────────────────────────────────────────────────────────

def get_samples(api_key: str, base_url: str) -> dict | None:
    """
    Fetches sample/submission records from Cisco Secure Malware Analytics.

    Endpoint:
        GET /api/v2/samples

    This endpoint returns metadata for submitted samples including:
      - Sample ID
      - SHA256, SHA1, MD5 hashes
      - File name and type
      - Threat score
      - Submission timestamp
      - Analysis status
      - OS and VM used for analysis

    Docs: https://panacea.threatgrid.com/mask/doc/mask/index

    The /api/v2/ endpoints accept the API key as a query parameter.

    Args:
        api_key:  Cisco Secure Malware Analytics API key.
        base_url: Base URL of the Threat Grid cloud instance.

    Returns:
        Parsed JSON response as a Python dict, or None on failure.
    """

    url = f"{base_url}/api/v2/samples"

    headers = {
        "Accept": "application/json",
    }

    # The v2 samples endpoint accepts the API key as a query parameter.
    # Common filters:
    #   - after/before : ISO 8601 timestamps to bound the query window
    #   - limit        : max number of records to return (default 20, max 1000)
    #   - offset       : pagination offset
    #   - org_only     : if true, return only samples from your organisation
    #   - state        : filter by analysis state (e.g. "succ", "fail")
    params = {
        "api_key": api_key,
        "after": "2026-03-07T00:00:00Z",
        "before": "2026-03-14T23:59:59Z",
        "org_only": "true",
        "limit": 500,
        "offset": 0,
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=60)
        response.raise_for_status()
        return response.json()

    except requests.exceptions.HTTPError as http_err:
        print(
            f"[ERROR] HTTP error: {http_err} | "
            f"Status: {response.status_code} | Body: {response.text}",
            file=sys.stderr,
        )
    except requests.exceptions.ConnectionError as conn_err:
        print(f"[ERROR] Connection error: {conn_err}", file=sys.stderr)
    except requests.exceptions.Timeout as timeout_err:
        print(f"[ERROR] Timeout error: {timeout_err}", file=sys.stderr)
    except requests.exceptions.RequestException as req_err:
        print(f"[ERROR] Request error: {req_err}", file=sys.stderr)

    return None


def save_events_to_file(events: dict, log_file: str) -> None:
    """
    Writes ONLY the raw structured JSON sample data to the specified file.
    No timestamps, log levels, or diagnostic metadata are included.

    Args:
        events:   The parsed JSON response dictionary from the API.
        log_file: Path to the output file.
    """
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError as e:
            print(
                f"[ERROR] Cannot create log directory '{log_dir}': {e}",
                file=sys.stderr,
            )
            return

    try:
        with open(log_file, "a", encoding="utf-8") as f:
            json.dump(events, f, indent=4, default=str)
            f.write("\n")
    except OSError as e:
        print(
            f"[ERROR] Cannot write to '{log_file}': {e}",
            file=sys.stderr,
        )


# ── Main entry point ───────────────────────────────────────────────────────

def main() -> None:
    args = parse_arguments()
    log_file = args.logfile

    print(f"[INFO] Log file path: {log_file}")
    print("[INFO] Fetching samples from Cisco Secure Malware Analytics …")

    result = get_samples(api_key=API_KEY, base_url=BASE_URL)

    if result:
        save_events_to_file(result, log_file)
        # Report count if available
        items = result.get("data", {}).get("items", [])
        print(f"[INFO] {len(items)} sample(s) written to {log_file}")
    else:
        print(
            "[WARNING] Failed to retrieve samples from Threat Grid.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
