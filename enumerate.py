#!/usr/bin/env python3
"""GitHub PAT enumerator — collects repos, permissions, secrets, variables, branch protections, and workflow secrets."""

import argparse
import base64
import json
import logging
import os
import re
import time
import urllib.parse
from datetime import datetime, timezone

import requests

BASE_URL = "https://api.github.com"
RATE_LIMIT_PAUSE_THRESHOLD = 10
PER_PAGE = 100

WORKFLOW_SECRET_RE = re.compile(r'\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}')

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def load_tokens(filepath: str) -> list:
    with open(filepath) as f:
        lines = f.readlines()
    tokens = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            tokens.append(stripped)
    return tokens


def make_session(token: str) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    return session


def api_get(session: requests.Session, path: str, params: dict = None):
    url = BASE_URL + path
    try:
        resp = session.get(url, params=params, timeout=30)
    except requests.RequestException as exc:
        logger.error(f"Network error on {path}: {exc}")
        return None, 0, {}

    remaining = int(resp.headers.get("X-RateLimit-Remaining", 999))
    if remaining <= RATE_LIMIT_PAUSE_THRESHOLD:
        reset_at = int(resp.headers.get("X-RateLimit-Reset", 0))
        sleep_for = max(60, reset_at - int(time.time()) + 5)
        logger.warning(f"Rate limit low ({remaining} remaining), sleeping {sleep_for}s")
        time.sleep(sleep_for)

    try:
        data = resp.json()
    except ValueError:
        data = None

    return data, resp.status_code, dict(resp.headers)


def paginate(session: requests.Session, path: str, params: dict = None) -> list:
    params = dict(params or {})
    params["per_page"] = PER_PAGE
    accumulated = []
    page = 1
    while True:
        params["page"] = page
        data, status, _ = api_get(session, path, params)
        if not isinstance(data, list):
            break
        accumulated.extend(data)
        if len(data) < PER_PAGE:
            break
        page += 1
    return accumulated


def paginate_wrapped(session: requests.Session, path: str, key: str, params: dict = None):
    params = dict(params or {})
    params["per_page"] = PER_PAGE
    accumulated = []
    page = 1
    while True:
        params["page"] = page
        data, status, _ = api_get(session, path, params)
        if page == 1:
            if status == 403:
                return "permission_denied"
            if status == 404:
                return "not_found"
        if not isinstance(data, dict):
            break
        items = data.get(key, [])
        accumulated.extend(items)
        if len(items) < PER_PAGE:
            break
        page += 1
    return accumulated


def get_user_identity(session: requests.Session):
    data, status, headers = api_get(session, "/user")
    if status != 200 or not isinstance(data, dict):
        return {}, [], status
    scopes_raw = headers.get("X-OAuth-Scopes", "")
    scopes = [s.strip() for s in scopes_raw.split(",") if s.strip()] if scopes_raw else []
    user = {
        "login": data.get("login"),
        "id": data.get("id"),
        "name": data.get("name"),
        "email": data.get("email"),
        "company": data.get("company"),
        "type": data.get("type"),
    }
    return user, scopes, status


def get_privileged_repos(session: requests.Session) -> list:
    return paginate(session, "/user/repos", {
        "affiliation": "owner,collaborator,organization_member",
        "visibility": "all",
        "sort": "full_name",
    })


PERMISSION_PRIORITY = ["admin", "maintain", "push", "triage", "pull"]


def derive_permission_level(permissions: dict) -> str:
    for level in PERMISSION_PRIORITY:
        if permissions.get(level):
            return level
    return "none"


def get_repo_secrets(session: requests.Session, owner: str, repo: str):
    return paginate_wrapped(session, f"/repos/{owner}/{repo}/actions/secrets", "secrets")


def get_repo_variables(session: requests.Session, owner: str, repo: str):
    return paginate_wrapped(session, f"/repos/{owner}/{repo}/actions/variables", "variables")


def get_repo_branches(session: requests.Session, owner: str, repo: str) -> list:
    return paginate(session, f"/repos/{owner}/{repo}/branches")


def get_branch_protection(session: requests.Session, owner: str, repo: str, branch: str):
    encoded_branch = urllib.parse.quote(branch, safe="")
    data, status, _ = api_get(session, f"/repos/{owner}/{repo}/branches/{encoded_branch}/protection")
    if status == 403:
        return "permission_denied"
    if status == 404:
        return "not_protected"
    if status == 200 and isinstance(data, dict):
        return data
    return "not_protected"


def get_workflow_secrets(session: requests.Session, owner: str, repo: str) -> list:
    """Fetch .github/workflows/*.yml and extract referenced secret names."""
    data, status, _ = api_get(session, f"/repos/{owner}/{repo}/contents/.github/workflows")
    if status != 200 or not isinstance(data, list):
        return []

    found = set()
    for entry in data:
        if not entry.get("name", "").endswith((".yml", ".yaml")):
            continue
        file_data, fstatus, _ = api_get(session, f"/repos/{owner}/{repo}/contents/.github/workflows/{entry['name']}")
        if fstatus != 200 or not isinstance(file_data, dict):
            continue
        content_b64 = file_data.get("content", "")
        try:
            content = base64.b64decode(content_b64).decode("utf-8", errors="replace")
        except Exception:
            continue
        found.update(WORKFLOW_SECRET_RE.findall(content))

    return sorted(found)


def find_existing_output(token_prefix: str, output_dir: str) -> str | None:
    if not os.path.isdir(output_dir):
        return None
    for fname in os.listdir(output_dir):
        if fname.endswith(f"_{token_prefix}.json"):
            return os.path.join(output_dir, fname)
    return None


def patch_workflow_secrets(existing_path: str, session: requests.Session) -> dict:
    """Load existing JSON, add workflow_secrets to each repo that lacks it, save in place."""
    with open(existing_path) as f:
        result = json.load(f)

    repos = result.get("repos", [])
    total = len(repos)
    needs_patch = sum(1 for r in repos if "workflow_secrets" not in r)

    if needs_patch == 0:
        logger.info(f"  Already up to date: {os.path.basename(existing_path)}")
        return result

    logger.info(f"  Patching workflow secrets for {needs_patch}/{total} repos in {os.path.basename(existing_path)}")
    for i, repo in enumerate(repos, 1):
        if "workflow_secrets" in repo:
            continue
        owner = repo.get("owner", "")
        name = repo.get("name", "")
        logger.info(f"  [{i}/{total}] {repo.get('full_name')} — scanning workflows")
        repo["workflow_secrets"] = get_workflow_secrets(session, owner, name)

    with open(existing_path, "w") as f:
        json.dump(result, f, indent=2)
    logger.info(f"  Patched and saved: {os.path.basename(existing_path)}")
    return result


def enumerate_token(token: str, output_dir: str) -> dict:
    token_prefix = token[:12]
    session = make_session(token)

    existing = find_existing_output(token_prefix, output_dir)
    if existing:
        logger.info(f"Existing output found for {token_prefix} — checking for missing workflow secrets...")
        return patch_workflow_secrets(existing, session)

    logger.info(f"Processing token {token_prefix}...")
    errors = []

    user, scopes, status = get_user_identity(session)
    if not user:
        logger.error(f"Could not authenticate token {token_prefix} (HTTP {status})")
        result = {
            "token_prefix": token_prefix,
            "user": {},
            "scopes": [],
            "repos": [],
            "errors": [{"endpoint": "/user", "status": status, "reason": "unauthorized_or_error"}],
        }
        _write_json(result, output_dir, f"unknown_{token_prefix}.json")
        return result

    login = user["login"]
    logger.info(f"  Authenticated as: {login}")

    repos_raw = get_privileged_repos(session)
    logger.info(f"  Found {len(repos_raw)} privileged repos")
    repos = []

    total = len(repos_raw)
    for i, repo in enumerate(repos_raw, 1):
        owner = repo.get("owner", {}).get("login", "")
        name = repo.get("name", "")
        full_name = repo.get("full_name", f"{owner}/{name}")
        default_branch = repo.get("default_branch")
        permissions = repo.get("permissions", {})
        permission_level = derive_permission_level(permissions)

        logger.info(f"  [{i}/{total}] {full_name} ({permission_level})")

        secrets = get_repo_secrets(session, owner, name)
        variables = get_repo_variables(session, owner, name)
        workflow_secrets = get_workflow_secrets(session, owner, name)

        if isinstance(secrets, str):
            errors.append({"endpoint": f"/repos/{full_name}/actions/secrets", "status": 403, "reason": secrets})
        if isinstance(variables, str):
            errors.append({"endpoint": f"/repos/{full_name}/actions/variables", "status": 403, "reason": variables})

        branches = []
        if default_branch is not None:
            branches_raw = get_repo_branches(session, owner, name)
            for branch in branches_raw:
                branch_name = branch.get("name", "")
                protected = branch.get("protected", False)
                protection = None
                if protected:
                    protection = get_branch_protection(session, owner, name, branch_name)
                    if isinstance(protection, str) and protection == "permission_denied":
                        errors.append({
                            "endpoint": f"/repos/{full_name}/branches/{branch_name}/protection",
                            "status": 403,
                            "reason": "permission_denied",
                        })
                branches.append({
                    "name": branch_name,
                    "protected": protected,
                    "protection": protection,
                })

        repos.append({
            "full_name": full_name,
            "owner": owner,
            "name": name,
            "private": repo.get("private", False),
            "default_branch": default_branch,
            "permissions": permissions,
            "permission_level": permission_level,
            "secrets": secrets,
            "variables": variables,
            "workflow_secrets": workflow_secrets,
            "branches": branches,
        })

    result = {
        "token_prefix": token_prefix,
        "user": user,
        "scopes": scopes,
        "repos": repos,
        "errors": errors,
    }

    filename = f"{login}_{token_prefix}.json"
    _write_json(result, output_dir, filename)
    logger.info(f"  Written: {filename} ({len(repos)} repos, {len(errors)} endpoints with restricted access)")
    return result


def _write_json(data: dict, output_dir: str, filename: str) -> None:
    path = os.path.join(output_dir, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def merge_results(results: list, output_dir: str) -> None:
    merged = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tokens": results,
    }
    path = os.path.join(output_dir, "merged_all.json")
    with open(path, "w") as f:
        json.dump(merged, f, indent=2)
    logger.info(f"Merged output written to {path}")


def main():
    parser = argparse.ArgumentParser(description="Enumerate GitHub PATs: repos, permissions, secrets, branch protections, workflow secrets.")
    parser.add_argument("tokens_file", help="Text file with one PAT per line (# for comments)")
    parser.add_argument("--output-dir", default="./output", help="Directory to write JSON output (default: ./output)")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    tokens = load_tokens(args.tokens_file)
    if not tokens:
        logger.error("No tokens found in file.")
        return

    logger.info(f"Loaded {len(tokens)} token(s)")

    results = []
    failed = 0
    skipped = 0
    patched = 0
    for i, token in enumerate(tokens, 1):
        logger.info(f"[{i}/{len(tokens)}]")
        try:
            existing_before = find_existing_output(token[:12], args.output_dir)
            result = enumerate_token(token, args.output_dir)
            results.append(result)
            if not result.get("user"):
                failed += 1
            elif existing_before:
                patched += 1
        except Exception as exc:
            logger.error(f"Unexpected error on token {i}: {exc}")
            failed += 1

    merge_results(results, args.output_dir)
    fetched = len(tokens) - failed - patched
    logger.info(f"Done. {fetched} fetched, {patched} patched with workflow secrets, {failed} failed. Output: {args.output_dir}/")


if __name__ == "__main__":
    main()
