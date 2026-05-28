#!/usr/bin/env python3
"""Scan .github/workflows/*.yml for referenced secret names.

Reads existing per-token JSON files from enumerate.py, fetches workflow
files for each repo, and writes a separate {user}_{prefix}_workflows.json.
Skips tokens that already have a workflows file.
"""

import argparse
import base64
import json
import logging
import os
import re
import time
from datetime import datetime, timezone

import requests

BASE_URL = "https://api.github.com"
RATE_LIMIT_PAUSE_THRESHOLD = 10
WORKFLOW_SECRET_RE = re.compile(r'\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}')

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def make_session(token: str) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    return session


def api_get(session: requests.Session, path: str):
    url = BASE_URL + path
    try:
        resp = session.get(url, timeout=30)
    except requests.RequestException as exc:
        logger.error(f"Network error on {path}: {exc}")
        return None, 0

    remaining = int(resp.headers.get("X-RateLimit-Remaining", 999))
    if remaining <= RATE_LIMIT_PAUSE_THRESHOLD:
        reset_at = int(resp.headers.get("X-RateLimit-Reset", 0))
        sleep_for = max(60, reset_at - int(time.time()) + 5)
        logger.warning(f"Rate limit low ({remaining} remaining), sleeping {sleep_for}s")
        time.sleep(sleep_for)

    try:
        return resp.json(), resp.status_code
    except ValueError:
        return None, resp.status_code


def scan_repo_workflows(session: requests.Session, owner: str, repo: str) -> list:
    data, status = api_get(session, f"/repos/{owner}/{repo}/contents/.github/workflows")
    if status != 200 or not isinstance(data, list):
        return []

    found = set()
    for entry in data:
        if not entry.get("name", "").endswith((".yml", ".yaml")):
            continue
        file_data, fstatus = api_get(session, f"/repos/{owner}/{repo}/contents/.github/workflows/{entry['name']}")
        if fstatus != 200 or not isinstance(file_data, dict):
            continue
        try:
            content = base64.b64decode(file_data.get("content", "")).decode("utf-8", errors="replace")
        except Exception:
            continue
        found.update(WORKFLOW_SECRET_RE.findall(content))

    return sorted(found)


def find_token_jsons(output_dir: str) -> list:
    """Return all per-token JSON files (excluding *_workflows.json and merged_all.json)."""
    results = []
    for fname in sorted(os.listdir(output_dir)):
        if fname.endswith(".json") and not fname.endswith("_workflows.json") and fname != "merged_all.json":
            results.append(os.path.join(output_dir, fname))
    return results


def scan_token(token_json_path: str, token: str, output_dir: str) -> dict:
    basename = os.path.basename(token_json_path)
    workflows_path = token_json_path.replace(".json", "_workflows.json")

    if os.path.exists(workflows_path):
        logger.info(f"Skipping {basename} — workflows file already exists")
        with open(workflows_path) as f:
            return json.load(f)

    with open(token_json_path) as f:
        token_data = json.load(f)

    token_prefix = token_data.get("token_prefix", "?")
    login = token_data.get("user", {}).get("login", "unknown")
    repos = token_data.get("repos", [])

    logger.info(f"Scanning workflows for {login} ({token_prefix}) — {len(repos)} repos")
    session = make_session(token)

    result_repos = []
    total = len(repos)
    for i, repo in enumerate(repos, 1):
        owner = repo.get("owner", "")
        name = repo.get("name", "")
        full_name = repo.get("full_name", f"{owner}/{name}")
        logger.info(f"  [{i}/{total}] {full_name}")
        workflow_secrets = scan_repo_workflows(session, owner, name)
        result_repos.append({
            "full_name": full_name,
            "workflow_secrets": workflow_secrets,
        })

    result = {
        "token_prefix": token_prefix,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "repos": result_repos,
    }

    with open(workflows_path, "w") as f:
        json.dump(result, f, indent=2)
    logger.info(f"  Written: {os.path.basename(workflows_path)}")
    return result


def merge_workflow_results(output_dir: str) -> None:
    """Merge all *_workflows.json files into merged_workflows.json."""
    results = []
    for fname in sorted(os.listdir(output_dir)):
        if fname.endswith("_workflows.json"):
            with open(os.path.join(output_dir, fname)) as f:
                results.append(json.load(f))

    merged = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tokens": results,
    }
    path = os.path.join(output_dir, "merged_workflows.json")
    with open(path, "w") as f:
        json.dump(merged, f, indent=2)
    logger.info(f"Merged workflow output written to {path}")


def load_tokens(filepath: str) -> list:
    with open(filepath) as f:
        lines = f.readlines()
    tokens = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            tokens.append(stripped)
    return tokens


def main():
    parser = argparse.ArgumentParser(description="Scan GitHub workflow files for referenced secret names.")
    parser.add_argument("tokens_file", help="Same tokens.txt used with enumerate.py")
    parser.add_argument("--output-dir", default="./output", help="Directory with enumerate.py output (default: ./output)")
    args = parser.parse_args()

    tokens = load_tokens(args.tokens_file)
    token_jsons = find_token_jsons(args.output_dir)

    if not token_jsons:
        logger.error(f"No token JSON files found in {args.output_dir}. Run enumerate.py first.")
        return

    if len(tokens) != len(token_jsons):
        logger.warning(f"Token count ({len(tokens)}) differs from JSON file count ({len(token_jsons)}) — matching by order")

    skipped = 0
    scanned = 0
    for token, json_path in zip(tokens, token_jsons):
        existed = os.path.exists(json_path.replace(".json", "_workflows.json"))
        scan_token(json_path, token, args.output_dir)
        if existed:
            skipped += 1
        else:
            scanned += 1

    merge_workflow_results(args.output_dir)
    logger.info(f"Done. {scanned} scanned, {skipped} skipped. Output: {args.output_dir}/")


if __name__ == "__main__":
    main()
