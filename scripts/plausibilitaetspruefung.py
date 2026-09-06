"""
Collects real GitHub Pull Requests that contain or remove hard-coded secrets.
Used for plausibility validation of a synthetic dataset in a bachelor thesis
on LLM-based secret detection robustness.

Usage:
    export GITHUB_TOKEN=ghp_your_token_here
    python3 scripts/plausibilitaetspruefung.py

Output:
    - collected_prs.json: Structured metadata of found PRs
    - collected_prs_summary.csv: Summary table for the thesis
    - diffs/: Directory with raw PR diffs
"""

import requests
import json
import csv
import os
import time
from datetime import datetime
from pathlib import Path

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
HEADERS = {
    "Accept": "application/vnd.github.v3+json",
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"

OUTPUT_DIR = Path("collected_prs")
DIFF_DIR = OUTPUT_DIR / "diffs"
OUTPUT_DIR.mkdir(exist_ok=True)
DIFF_DIR.mkdir(exist_ok=True)

SEARCH_QUERIES = [
    # PRs that remove/fix hardcoded secrets
    '"remove hardcoded" "api key" OR "password" OR "token"',
    '"hardcoded secret" OR "hardcoded credential"',
    '"accidentally committed" "key" OR "token" OR "secret"',
    '"move secret to env" OR "use environment variable"',
    '"remove api key" OR "remove secret key"',
    '"credential leak" OR "secret leak"',
    '"leaked token" OR "leaked key" OR "leaked secret"',
    '"revoke token" OR "rotate secret" OR "rotate key"',
    # German repos (since your thesis is in German context)
    '"Passwort entfernt" OR "Schlüssel entfernt" OR "API-Schlüssel"',
]

TARGET_COUNT = 30  # collect more than 20 to have selection buffer


def rate_limit_wait():
    """Respect GitHub API rate limits."""
    if not GITHUB_TOKEN:
        time.sleep(6)  # unauthenticated: 10 req/min
    else:
        time.sleep(1)  # authenticated: 30 req/min for search


def search_prs(query: str, max_results: int = 10) -> list:
    """Search GitHub for merged PRs matching the query."""
    url = "https://api.github.com/search/issues"
    params = {
        "q": f"{query} is:pr is:merged",
        "sort": "updated",
        "order": "desc",
        "per_page": min(max_results, 30),
    }

    rate_limit_wait()
    resp = requests.get(url, headers=HEADERS, params=params)

    if resp.status_code == 403:
        print(f"  Rate limited. Waiting 60s...")
        time.sleep(60)
        resp = requests.get(url, headers=HEADERS, params=params)

    if resp.status_code != 200:
        print(f"  Error {resp.status_code}: {resp.text[:200]}")
        return []

    data = resp.json()
    print(f"  Found {data.get('total_count', 0)} results for: {query[:60]}...")
    return data.get("items", [])


def get_pr_details(owner: str, repo: str, pr_number: int) -> dict | None:
    """Fetch PR details including diff stats."""
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
    rate_limit_wait()
    resp = requests.get(url, headers=HEADERS)
    if resp.status_code != 200:
        return None
    return resp.json()


def get_pr_diff(owner: str, repo: str, pr_number: int) -> str | None:
    """Fetch the raw diff of a PR."""
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
    diff_headers = {**HEADERS, "Accept": "application/vnd.github.v3.diff"}
    rate_limit_wait()
    resp = requests.get(url, headers=diff_headers)
    if resp.status_code != 200:
        return None
    return resp.text


def extract_owner_repo(pr_item: dict) -> tuple[str, str, int]:
    """Extract owner, repo, and PR number from a search result item."""
    repo_url = pr_item["repository_url"]
    parts = repo_url.rstrip("/").split("/")
    owner = parts[-2]
    repo = parts[-1]
    pr_number = pr_item["number"]
    return owner, repo, pr_number


def contains_secret_indicators(diff_text: str) -> dict:
    """Check if the diff likely contains secret-related changes."""
    indicators = {
        "api_key": ["api_key", "apikey", "api-key", "API_KEY"],
        "password": ["password", "passwd", "pwd", "PASSWORD"],
        "token": ["token", "TOKEN", "access_token", "auth_token"],
        "secret": ["secret", "SECRET", "client_secret"],
        "private_key": ["private_key", "PRIVATE_KEY", "-----BEGIN"],
        "credential": ["credential", "CREDENTIAL", "cred"],
        "aws": ["AKIA", "aws_access_key", "aws_secret"],
        "database": ["db_password", "database_url", "connection_string"],
    }

    diff_lower = diff_text.lower()
    found = {}
    for category, keywords in indicators.items():
        for kw in keywords:
            if kw.lower() in diff_lower:
                found[category] = True
                break
    return found


def sanitize_secrets_in_diff(diff_text: str) -> str:
    """
    Basic sanitization: replaces potential real secret values with placeholders.
    IMPORTANT: Manual review is still necessary.
    """
    import re
    # Replace long hex/base64 strings that look like real secrets
    sanitized = re.sub(
        r'(?<=["\'=>:\s])([A-Za-z0-9+/=_-]{32,})(?=["\'\s,;\n])',
        r"<REDACTED_FOR_THESIS>",
        diff_text,
    )
    return sanitized


def main():
    print("=" * 60)
    print("GitHub PR Collector for Secret Detection Research")
    print("=" * 60)

    if not GITHUB_TOKEN:
        print("\nWARNING: No GITHUB_TOKEN set. Rate limits will be very strict.")
        print("Set it with: export GITHUB_TOKEN=ghp_your_token_here\n")

    all_prs = []
    seen_urls = set()

    for i, query in enumerate(SEARCH_QUERIES, 1):
        print(f"\n[{i}/{len(SEARCH_QUERIES)}] Searching: {query[:70]}...")
        results = search_prs(query, max_results=10)

        for item in results:
            pr_url = item["html_url"]
            if pr_url in seen_urls:
                continue
            seen_urls.add(pr_url)

            owner, repo, pr_number = extract_owner_repo(item)
            print(f"  Processing: {owner}/{repo}#{pr_number}")

            diff = get_pr_diff(owner, repo, pr_number)
            if not diff:
                print(f"    Skipped: could not fetch diff")
                continue

            if len(diff) > 500_000:
                print(f"    Skipped: diff too large ({len(diff)} bytes)")
                continue

            indicators = contains_secret_indicators(diff)
            if not indicators:
                print(f"    Skipped: no secret indicators in diff")
                continue

            details = get_pr_details(owner, repo, pr_number)

            pr_record = {
                "id": len(all_prs) + 1,
                "url": pr_url,
                "owner": owner,
                "repo": repo,
                "pr_number": pr_number,
                "title": item.get("title", ""),
                "body": (item.get("body") or "")[:500],
                "created_at": item.get("created_at", ""),
                "merged_at": details.get("merged_at", "") if details else "",
                "changed_files": details.get("changed_files", 0) if details else 0,
                "additions": details.get("additions", 0) if details else 0,
                "deletions": details.get("deletions", 0) if details else 0,
                "secret_indicators": list(indicators.keys()),
                "diff_length": len(diff),
                "search_query": query,
            }
            all_prs.append(pr_record)

            # Save diff
            diff_filename = f"{len(all_prs):03d}_{owner}_{repo}_{pr_number}.diff"
            sanitized_diff = sanitize_secrets_in_diff(diff)
            (DIFF_DIR / diff_filename).write_text(sanitized_diff, encoding="utf-8")

            print(f"    Collected! Indicators: {list(indicators.keys())}")

            if len(all_prs) >= TARGET_COUNT:
                break

        if len(all_prs) >= TARGET_COUNT:
            print(f"\nReached target of {TARGET_COUNT} PRs.")
            break

    # Save results
    json_path = OUTPUT_DIR / "collected_prs.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(all_prs, f, indent=2, ensure_ascii=False)

    csv_path = OUTPUT_DIR / "collected_prs_summary.csv"
    if all_prs:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "id", "url", "owner", "repo", "pr_number", "title",
                    "created_at", "merged_at", "changed_files",
                    "additions", "deletions", "secret_indicators",
                ],
            )
            writer.writeheader()
            for pr in all_prs:
                row = {k: v for k, v in pr.items() if k in writer.fieldnames}
                row["secret_indicators"] = ", ".join(pr["secret_indicators"])
                writer.writerow(row)

    print(f"\n{'=' * 60}")
    print(f"RESULTS")
    print(f"{'=' * 60}")
    print(f"Total PRs collected: {len(all_prs)}")
    print(f"JSON output: {json_path}")
    print(f"CSV output:  {csv_path}")
    print(f"Diffs saved: {DIFF_DIR}/")

    if all_prs:
        print(f"\nSecret type distribution:")
        type_counts = {}
        for pr in all_prs:
            for t in pr["secret_indicators"]:
                type_counts[t] = type_counts.get(t, 0) + 1
        for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"  {t}: {c}")

    print(f"\n--- IMPORTANT ---")
    print(f"1. Review each diff manually before using in your thesis")
    print(f"2. Verify that secrets are truly hard-coded (not env vars, not test fixtures)")
    print(f"3. Check that secrets are already revoked/rotated (ethical requirement)")
    print(f"4. The sanitize function is basic - do a manual pass for real values")
    print(f"5. Select your final 20 from the {len(all_prs)} collected for diversity")


if __name__ == "__main__":
    main()