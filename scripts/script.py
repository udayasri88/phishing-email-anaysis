import os
import json
import time
import base64
import requests
from pathlib import Path

# Configuration
INPUT_DIR = Path("/root/phishing-project/output")
OUTPUT_DIR = Path("/root/phishing-project/enriched")
API_KEY = os.getenv("VT_API_KEY")

if not API_KEY:
    raise SystemExit("ERROR: VT_API_KEY is not set.")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

HEADERS = {"x-apikey": API_KEY}
BASE_URL = "https://www.virustotal.com/api/v3"

 def find_indicators(data):
    """Recursively extract URLs and SHA256 hashes from JSON."""
    urls = set()
    hashes = set()

    def scan(item):
        if isinstance(item, dict):
            for key, value in item.items():
                key_lower = key.lower()

                if key_lower in ("url", "urls", "url_list"):
                    if isinstance(value, str):
                        if value.startswith(("http://", "https://")):
                            urls.add(value.strip())

                    elif isinstance(value, list):
                        for url in value:
                            if isinstance(url, str) and url.startswith(
                                ("http://", "https://")
                            ):
                                urls.add(url.strip())

                if key_lower in ("sha256", "sha_256"):
                    if isinstance(value, str):
                        if len(value) == 64 and all(
                            c in "0123456789abcdefABCDEF"
                            for c in value
                        ):
                            hashes.add(value.lower())

                scan(value)

        elif isinstance(item, list):
            for element in item:
                scan(element)

    scan(data)
    return urls, hashes 


def check_url(url):
    """Look up an existing URL report; does not submit the URL."""
    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().rstrip("=")

    response = requests.get(
        f"{BASE_URL}/urls/{url_id}",
        headers=HEADERS,
        timeout=30
    )

    if response.status_code == 404:
        return {"status": "not_found_in_virustotal"}

    if response.status_code == 429:
        return {"status": "rate_limit_reached"}

    response.raise_for_status()
    attributes = response.json()["data"]["attributes"]

    return {
        "status": "found",
        "reputation": attributes.get("reputation"),
        "analysis_stats": attributes.get("last_analysis_stats", {}),
        "last_analysis_date": attributes.get("last_analysis_date")
    }


def check_hash(sha256):
    """Look up an existing file report by SHA256."""
    response = requests.get(
        f"{BASE_URL}/files/{sha256}",
        headers=HEADERS,
        timeout=30
    )

    if response.status_code == 404:
        return {"status": "not_found_in_virustotal"}

    if response.status_code == 429:
        return {"status": "rate_limit_reached"}

    response.raise_for_status()
    attributes = response.json()["data"]["attributes"]

    return {
        "status": "found",
        "file_name": attributes.get("meaningful_name"),
        "file_type": attributes.get("type_description"),
        "reputation": attributes.get("reputation"),
        "analysis_stats": attributes.get("last_analysis_stats", {}),
        "last_analysis_date": attributes.get("last_analysis_date")
    }


if __name__ == "__main__":
    json_files = list(INPUT_DIR.glob("*.json"))

    if not json_files:
        print(f"No JSON files found in {INPUT_DIR}")
        raise SystemExit(0)

    for json_file in json_files:
        print(f"\nProcessing: {json_file.name}")

        with json_file.open(encoding="utf-8") as f:
            email_data = json.load(f)

        urls, hashes = find_indicators(email_data)

        results = {
            "virustotal": {
                "urls": {},
                "files": {}
            }
        }

        print(f"URLs found: {len(urls)}")
        print(f"SHA256 hashes found: {len(hashes)}")

        for url in sorted(urls):
            print(f"Checking URL: {url}")

            try:
                results["virustotal"]["urls"][url] = check_url(url)
            except requests.RequestException as e:
                results["virustotal"]["urls"][url] = {
                    "status": "request_error",
                    "error": str(e)
                }

            time.sleep(16)

        for sha256 in sorted(hashes):
            print(f"Checking SHA256: {sha256}")

            try:
                results["virustotal"]["files"][sha256] = check_hash(
                    sha256
                )
            except requests.RequestException as e:
                results["virustotal"]["files"][sha256] = {
                    "status": "request_error",
                    "error": str(e)
                }

            time.sleep(16)

        output_data = {
            "email_analysis": email_data,
            "threat_intelligence": results
        }

        output_file = OUTPUT_DIR / f"{json_file.stem}_enriched.json"

        with output_file.open("w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=4)

        print(f"Saved: {output_file}")

    print("\nVirusTotal enrichment completed.")
