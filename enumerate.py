#!/usr/bin/env python3
"""GitHub PAT enumerator — collects repos, permissions, secrets, variables, and branch protections."""

import argparse
import json
import logging
import os
import time
import urllib.parse
from datetime import datetime, timezone

import requests

BASE_URL = "https://api.github.com"
RATE_LIMIT_PAUSE_THRESHOLD = 10
PER_PAGE = 100

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


def get_user_orgs(session: requests.Session) -> list:
    return paginate(session, "/user/orgs")


def get_org_secrets(session: requests.Session, org_login: str):
    return paginate_wrapped(session, f"/orgs/{org_login}/actions/secrets", "secrets")


def get_org_variables(session: requests.Session, org_login: str):
    return paginate_wrapped(session, f"/orgs/{org_login}/actions/variables", "variables")


def get_org_repos(session: requests.Session, org: str) -> list:
    all_repos = paginate(session, "/user/repos", {
        "visibility": "all",
        "affiliation": "owner,collaborator,organization_member",
        "sort": "full_name",
    })
    return [r for r in all_repos if r.get("owner", {}).get("login", "").lower() == org.lower()]


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


def find_existing_output(token_prefix: str, output_dir: str) -> str | None:
    if not os.path.isdir(output_dir):
        return None
    for fname in os.listdir(output_dir):
        if fname.endswith(f"_{token_prefix}.json"):
            return os.path.join(output_dir, fname)
    return None


def enumerate_token(token: str, output_dir: str, org: str) -> dict:
    token_prefix = token[:12]

    existing = find_existing_output(token_prefix, output_dir)
    if existing:
        logger.info(f"Skipping {token_prefix} — output already exists: {os.path.basename(existing)}")
        with open(existing) as f:
            return json.load(f)

    logger.info(f"Processing token {token_prefix}...")

    session = make_session(token)
    errors = []

    user, scopes, status = get_user_identity(session)
    if not user:
        logger.error(f"Could not authenticate token {token_prefix} (HTTP {status})")
        result = {
            "token_prefix": token_prefix,
            "user": {},
            "scopes": [],
            "orgs": [],
            "repos": [],
            "errors": [{"endpoint": "/user", "status": status, "reason": "unauthorized_or_error"}],
        }
        _write_json(result, output_dir, f"unknown_{token_prefix}.json")
        return result

    login = user["login"]
    logger.info(f"  Authenticated as: {login}")

    # Orgs
    orgs_raw = get_user_orgs(session)
    orgs = []
    for org in orgs_raw:
        org_login = org.get("login", "")
        secrets = get_org_secrets(session, org_login)
        variables = get_org_variables(session, org_login)

        if isinstance(secrets, str):
            errors.append({"endpoint": f"/orgs/{org_login}/actions/secrets", "status": 403, "reason": secrets})
            secrets = []
        if isinstance(variables, str):
            errors.append({"endpoint": f"/orgs/{org_login}/actions/variables", "status": 403, "reason": variables})
            variables = []

        orgs.append({
            "login": org_login,
            "id": org.get("id"),
            "secrets": secrets,
            "variables": variables,
        })

    # Repos
    repos_raw = get_org_repos(session, org)
    logger.info(f"  Found {len(repos_raw)} repos")
    repos = []

    for repo in repos_raw:
        owner = repo.get("owner", {}).get("login", "")
        name = repo.get("name", "")
        full_name = repo.get("full_name", f"{owner}/{name}")
        default_branch = repo.get("default_branch")
        permissions = repo.get("permissions", {})
        permission_level = derive_permission_level(permissions)

        secrets = get_repo_secrets(session, owner, name)
        variables = get_repo_variables(session, owner, name)

        if isinstance(secrets, str):
            errors.append({"endpoint": f"/repos/{full_name}/actions/secrets", "status": 403, "reason": secrets})
            secrets_val = secrets
        else:
            secrets_val = secrets

        if isinstance(variables, str):
            errors.append({"endpoint": f"/repos/{full_name}/actions/variables", "status": 403, "reason": variables})
            variables_val = variables
        else:
            variables_val = variables

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
            "secrets": secrets_val,
            "variables": variables_val,
            "branches": branches,
        })

    result = {
        "token_prefix": token_prefix,
        "user": user,
        "scopes": scopes,
        "orgs": orgs,
        "repos": repos,
        "errors": errors,
    }

    filename = f"{login}_{token_prefix}.json"
    _write_json(result, output_dir, filename)
    logger.info(f"  Written: {filename} ({len(repos)} repos, {len(errors)} permission errors)")
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
    parser = argparse.ArgumentParser(description="Enumerate GitHub PATs: repos, permissions, secrets, branch protections.")
    parser.add_argument("tokens_file", help="Text file with one PAT per line (# for comments)")
    parser.add_argument("--org", required=True, help="GitHub organization to enumerate repos from")
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
    for i, token in enumerate(tokens, 1):
        logger.info(f"[{i}/{len(tokens)}]")
        try:
            result = enumerate_token(token, args.output_dir, args.org)
            results.append(result)
            if not result.get("user"):
                failed += 1
            elif find_existing_output(token[:12], args.output_dir):
                skipped += 1
        except Exception as exc:
            logger.error(f"Unexpected error on token {i}: {exc}")
            failed += 1

    merge_results(results, args.output_dir)
    fetched = len(tokens) - failed - skipped
    logger.info(f"Done. {fetched} fetched, {skipped} skipped (already done), {failed} failed. Output: {args.output_dir}/")


if __name__ == "__main__":
    main()
