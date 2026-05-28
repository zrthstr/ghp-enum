#!/usr/bin/env python3
"""Generate HTML reports from enumerate.py and scan_workflows.py output."""

import argparse
import html
import json
import os


def load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def load_merged(output_dir: str) -> dict:
    path = os.path.join(output_dir, "merged_all.json")
    if not os.path.exists(path):
        raise FileNotFoundError(f"No merged_all.json found in {output_dir}. Run enumerate.py first.")
    return load_json(path)


def load_merged_workflows(output_dir: str) -> dict:
    path = os.path.join(output_dir, "merged_workflows.json")
    if not os.path.exists(path):
        return {}
    data = load_json(path)
    index = {}
    for token_entry in data.get("tokens", []):
        prefix = token_entry.get("token_prefix", "")
        index[prefix] = {
            r["full_name"]: r.get("workflow_secrets", [])
            for r in token_entry.get("repos", [])
        }
    return index


def merge_secrets(api_names: list, api_status: str, wf_names: list | None):
    """
    Returns a list of (name, source) tuples where source is:
      'api'      — confirmed via secrets API
      'workflow' — referenced in workflow YAML only
    Names appearing in both are returned once as 'api'.
    wf_names=None means workflow scan not run yet.
    """
    api_set = set(api_names)
    wf_set = set(wf_names) if wf_names is not None else set()

    result = []
    if api_status == "ok":
        for name in sorted(api_set):
            result.append((name, "api"))
        for name in sorted(wf_set - api_set):
            result.append((name, "workflow"))
    else:
        # No API data — show workflow secrets only, or the error
        for name in sorted(wf_set):
            result.append((name, "workflow"))

    return result


def flatten_to_rows(data: dict, workflow_index: dict) -> list:
    rows = []
    for token_entry in data.get("tokens", []):
        token_prefix = token_entry.get("token_prefix", "?")
        username = token_entry.get("user", {}).get("login", "unknown")
        wf_by_repo = workflow_index.get(token_prefix, {})

        for repo in token_entry.get("repos", []):
            secrets = repo.get("secrets", [])
            variables = repo.get("variables", [])
            full_name = repo.get("full_name", "")

            if isinstance(secrets, str):
                secrets_status = secrets
                secret_names = []
            else:
                secrets_status = "ok"
                secret_names = [s.get("name", "") for s in secrets]

            variable_names = [] if isinstance(variables, str) else [v.get("name", "") for v in variables]

            wf_secrets = wf_by_repo.get(full_name, None)  # None = not scanned
            merged_secrets = merge_secrets(secret_names, secrets_status, wf_secrets)

            default_branch = repo.get("default_branch") or "main"
            branches = repo.get("branches", [])
            bp_parts = []
            for b in branches:
                bname = b.get("name", "")
                if bname != default_branch:
                    continue
                protected = b.get("protected", False)
                protection = b.get("protection")
                if not protected:
                    bp_parts.append(f"{bname}:✗")
                elif protection == "permission_denied":
                    bp_parts.append(f"{bname}:?")
                elif isinstance(protection, dict):
                    flags = []
                    if protection.get("required_pull_request_reviews"):
                        flags.append("PR")
                    if protection.get("required_status_checks"):
                        flags.append("CI")
                    if (protection.get("enforce_admins") or {}).get("enabled"):
                        flags.append("ADM")
                    if protection.get("restrictions"):
                        flags.append("RST")
                    summary = ",".join(flags) if flags else "on"
                    bp_parts.append(f"{bname}:✓({summary})")
                else:
                    bp_parts.append(f"{bname}:✓")

            rows.append({
                "token_prefix": token_prefix,
                "username": username,
                "repo_full_name": full_name,
                "private": repo.get("private", False),
                "permission_level": repo.get("permission_level", "none"),
                "merged_secrets": merged_secrets,
                "secrets_status": secrets_status,
                "wf_scanned": wf_secrets is not None,
                "variable_names": sorted(set(variable_names)),
                "branch_protections_summary": " | ".join(bp_parts) if bp_parts else "—",
            })
    return rows


def find_shared_write_repos(rows: list) -> set:
    write_levels = {"admin", "maintain", "push"}
    repo_tokens = {}
    for row in rows:
        if row["permission_level"] in write_levels:
            repo_tokens.setdefault(row["repo_full_name"], set()).add(row["token_prefix"])
    return {repo for repo, tokens in repo_tokens.items() if len(tokens) >= 2}


PERM_ORDER = {"admin": 0, "maintain": 1, "push": 2, "triage": 3, "pull": 4, "none": 5}


def _perm_sort_key(row):
    return (PERM_ORDER.get(row["permission_level"], 99), row["repo_full_name"])


def _render_secrets(merged_secrets: list, secrets_status: str, wf_scanned: bool) -> str:
    if not merged_secrets:
        if secrets_status != "ok":
            return f'<span class="s-err">{html.escape(secrets_status)}</span>'
        return "—"
    parts = []
    for name, source in merged_secrets:
        if source == "api":
            parts.append(f'<span class="s-api">{html.escape(name)}</span>')
        else:
            parts.append(f'<span class="s-wf">{html.escape(name)}</span>')
    return " ".join(parts)


def build_html_table(rows: list, shared_write_repos: set, include_secrets: bool) -> str:
    parts = ['<table id="main-table">']

    headers = ["Token Prefix", "Username", "Repo", "Private", "Permission"]
    if include_secrets:
        headers += ["Secrets", "Variables"]
    headers += ["Branch Protections"]

    parts.append("<thead><tr>")
    for h in headers:
        parts.append(f"<th>{html.escape(h)}</th>")
    parts.append("</tr></thead>")

    parts.append("<tbody>")
    for row in sorted(rows, key=_perm_sort_key):
        tr_class = ' class="shared-write"' if row["repo_full_name"] in shared_write_repos else ""
        perm = row["permission_level"]
        perm_class = ' class="high-perm"' if perm in ("admin", "push", "maintain") else ""
        private_str = "private" if row["private"] else "public"

        parts.append(f"<tr{tr_class}>")
        parts.append(f"<td>{html.escape(row['token_prefix'])}</td>")
        parts.append(f"<td>{html.escape(row['username'])}</td>")
        parts.append(f"<td>{html.escape(row['repo_full_name'])}</td>")
        parts.append(f"<td>{private_str}</td>")
        parts.append(f"<td{perm_class}>{html.escape(perm)}</td>")

        if include_secrets:
            secret_display = _render_secrets(row["merged_secrets"], row["secrets_status"], row["wf_scanned"])
            var_display = ", ".join(html.escape(v) for v in row["variable_names"]) or "—"
            parts.append(f"<td>{secret_display}</td>")
            parts.append(f"<td>{var_display}</td>")

        parts.append(f"<td>{html.escape(row['branch_protections_summary'])}</td>")
        parts.append("</tr>")

    parts.append("</tbody></table>")
    return "\n".join(parts)


def build_html_page(table_html: str, title: str, generated_at: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)}</title>
<style>
  body {{ font-family: monospace; font-size: 13px; margin: 0; padding: 16px; background: #f8f8f8; color: #222; }}
  h1 {{ font-size: 16px; margin-bottom: 4px; }}
  .meta {{ color: #888; font-size: 11px; margin-bottom: 12px; }}
  .legend {{ margin-bottom: 10px; font-size: 12px; }}
  .legend span {{ display: inline-block; padding: 2px 8px; margin-right: 8px; border-radius: 3px; }}
  .legend .l-shared {{ background: #fff3cd; border: 1px solid #ffc107; }}
  .legend .l-highperm {{ color: #c0392b; font-weight: bold; }}
  .legend .l-api {{ color: #222; font-weight: bold; }}
  .legend .l-wf {{ color: #e67e22; }}
  .table-wrap {{ overflow-x: auto; max-height: 90vh; border: 1px solid #ccc; border-radius: 4px; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff; }}
  th, td {{ border: 1px solid #ddd; padding: 5px 10px; vertical-align: top; white-space: nowrap; }}
  thead th {{ background: #2c3e50; color: #fff; position: sticky; top: 0; z-index: 1; }}
  tbody tr:hover {{ background: #eef2f7 !important; }}
  tr.shared-write {{ background: #fff3cd; }}
  .high-perm {{ color: #c0392b; font-weight: bold; }}
  .s-api {{ color: #222; font-weight: bold; }}
  .s-wf {{ color: #e67e22; }}
  .s-err {{ color: #aaa; font-style: italic; }}
  .filters {{ margin-bottom: 8px; display: flex; gap: 8px; }}
  .filters input {{ padding: 4px 8px; font-family: monospace; font-size: 13px; width: 300px; border: 1px solid #ccc; border-radius: 3px; }}
  .filters label {{ font-size: 11px; color: #888; display: block; margin-bottom: 2px; }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<div class="meta">Generated: {html.escape(generated_at)}</div>
<div class="legend">
  <span class="l-shared">&#9632; shared write access (2+ tokens)</span>
  <span class="l-highperm">&#9632; high permission</span>
  <span class="l-api">&#9632; secret confirmed via API</span>
  <span class="l-wf">&#9632; secret from workflow YAML only</span>
</div>
<div class="filters">
  <div><label>Filter rows</label><input id="filter-row" type="text" placeholder="repo, user, permission..." oninput="applyFilters()"></div>
  <div><label>Search secrets</label><input id="filter-secret" type="text" placeholder="SECRET_NAME..." oninput="applyFilters()"></div>
</div>
<div class="table-wrap">
{table_html}
</div>
<script>
function applyFilters() {{
  var q = document.getElementById('filter-row').value.toLowerCase();
  var s = document.getElementById('filter-secret').value.toLowerCase();
  document.querySelectorAll('#main-table tbody tr').forEach(function(row) {{
    var text = row.textContent.toLowerCase();
    row.style.display = (!q || text.includes(q)) && (!s || text.includes(s)) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""


def generate_reports(output_dir: str, report_output_dir: str = None) -> None:
    if report_output_dir is None:
        report_output_dir = output_dir

    data = load_merged(output_dir)
    workflow_index = load_merged_workflows(output_dir)
    generated_at = data.get("generated_at", "")

    if not workflow_index:
        print("Note: no merged_workflows.json found — run scan_workflows.py to add workflow-sourced secrets.")

    rows = flatten_to_rows(data, workflow_index)
    shared_write = find_shared_write_repos(rows)

    print(f"Loaded {len(data.get('tokens', []))} token(s), {len(rows)} repo entries, {len(shared_write)} shared-write repos")

    ts = str(int(__import__("time").time()))
    for include_secrets, suffix, label in [
        (True, f"report_with_secrets_{ts}.html", "GitHub PAT Report — With Secrets"),
        (False, f"report_without_secrets_{ts}.html", "GitHub PAT Report — Without Secrets"),
    ]:
        table = build_html_table(rows, shared_write, include_secrets)
        page = build_html_page(table, label, generated_at)
        out_path = os.path.join(report_output_dir, suffix)
        with open(out_path, "w") as f:
            f.write(page)
        print(f"Written: {os.path.abspath(out_path)}")


def main():
    parser = argparse.ArgumentParser(description="Generate HTML reports from enumerate.py output.")
    parser.add_argument("input_dir", help="Directory containing merged_all.json (output from enumerate.py)")
    parser.add_argument("--output-dir", default=None, help="Where to write HTML reports (default: same as input_dir)")
    args = parser.parse_args()

    generate_reports(args.input_dir, args.output_dir)


if __name__ == "__main__":
    main()
