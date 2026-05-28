#!/usr/bin/env python3
"""Generate HTML reports from merged GitHub PAT enumeration output."""

import argparse
import html
import json
import os
from datetime import datetime


def load_merged(output_dir: str) -> dict:
    path = os.path.join(output_dir, "merged_all.json")
    if not os.path.exists(path):
        raise FileNotFoundError(f"No merged_all.json found in {output_dir}. Run enumerate.py first.")
    with open(path) as f:
        return json.load(f)


def flatten_to_rows(data: dict) -> list:
    rows = []
    for token_entry in data.get("tokens", []):
        token_prefix = token_entry.get("token_prefix", "?")
        user = token_entry.get("user", {})
        username = user.get("login", "unknown")
        org_logins = ", ".join(o.get("login", "") for o in token_entry.get("orgs", []))

        for repo in token_entry.get("repos", []):
            secrets = repo.get("secrets", [])
            variables = repo.get("variables", [])

            if isinstance(secrets, str):
                secrets_status = secrets
                secret_names = []
            else:
                secrets_status = "ok"
                secret_names = [s.get("name", "") for s in secrets]

            if isinstance(variables, str):
                variable_names = []
            else:
                variable_names = [v.get("name", "") for v in variables]

            branches = repo.get("branches", [])
            bp_parts = []
            for b in branches:
                bname = b.get("name", "")
                protected = b.get("protected", False)
                protection = b.get("protection")
                if not protected:
                    bp_parts.append(f"{bname}:none")
                elif isinstance(protection, str):
                    bp_parts.append(f"{bname}:{protection}")
                elif isinstance(protection, dict):
                    bp_parts.append(f"{bname}:protected")
                else:
                    bp_parts.append(f"{bname}:unknown")
            branch_protections_summary = ", ".join(bp_parts) if bp_parts else "—"

            rows.append({
                "token_prefix": token_prefix,
                "username": username,
                "repo_full_name": repo.get("full_name", ""),
                "private": repo.get("private", False),
                "permission_level": repo.get("permission_level", "none"),
                "secret_names": secret_names,
                "variable_names": variable_names,
                "secrets_status": secrets_status,
                "branch_protections_summary": branch_protections_summary,
                "orgs": org_logins,
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


def build_html_table(rows: list, shared_write_repos: set, include_secrets: bool) -> str:
    parts = ['<table id="main-table">']

    headers = ["Token Prefix", "Username", "Repo", "Private", "Permission"]
    if include_secrets:
        headers += ["Secret Names", "Variable Names"]
    headers += ["Branch Protections", "Orgs"]

    parts.append("<thead><tr>")
    for h in headers:
        parts.append(f"<th>{html.escape(h)}</th>")
    parts.append("</tr></thead>")

    parts.append("<tbody>")
    for row in sorted(rows, key=_perm_sort_key):
        tr_class = ""
        if row["repo_full_name"] in shared_write_repos:
            tr_class = ' class="shared-write"'

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
            if row["secrets_status"] == "ok":
                secret_display = ", ".join(html.escape(s) for s in row["secret_names"]) or "—"
            else:
                secret_display = f'<span class="status-{html.escape(row["secrets_status"])}">{html.escape(row["secrets_status"])}</span>'

            var_display = ", ".join(html.escape(v) for v in row["variable_names"]) or "—"
            parts.append(f"<td>{secret_display}</td>")
            parts.append(f"<td>{var_display}</td>")

        parts.append(f"<td>{html.escape(row['branch_protections_summary'])}</td>")
        parts.append(f"<td>{html.escape(row['orgs']) if row['orgs'] else '—'}</td>")
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
  body {{
    font-family: monospace;
    font-size: 13px;
    margin: 0;
    padding: 16px;
    background: #f8f8f8;
    color: #222;
  }}
  h1 {{
    font-size: 16px;
    margin-bottom: 4px;
  }}
  .meta {{
    color: #888;
    font-size: 11px;
    margin-bottom: 12px;
  }}
  .legend {{
    margin-bottom: 10px;
    font-size: 12px;
  }}
  .legend span {{
    display: inline-block;
    padding: 2px 8px;
    margin-right: 8px;
    border-radius: 3px;
  }}
  .legend .l-shared {{ background: #fff3cd; border: 1px solid #ffc107; }}
  .legend .l-highperm {{ color: #c0392b; font-weight: bold; }}
  .table-wrap {{
    overflow-x: auto;
    max-height: 90vh;
    border: 1px solid #ccc;
    border-radius: 4px;
  }}
  table {{
    border-collapse: collapse;
    width: 100%;
    background: #fff;
  }}
  th, td {{
    border: 1px solid #ddd;
    padding: 5px 10px;
    vertical-align: top;
    white-space: nowrap;
  }}
  thead th {{
    background: #2c3e50;
    color: #fff;
    position: sticky;
    top: 0;
    z-index: 1;
  }}
  tbody tr:hover {{
    background: #eef2f7 !important;
  }}
  tr.shared-write {{
    background: #fff3cd;
  }}
  .high-perm {{
    color: #c0392b;
    font-weight: bold;
  }}
  .status-permission_denied {{
    color: #888;
    font-style: italic;
  }}
  .status-not_found {{
    color: #aaa;
    font-style: italic;
  }}
  #filter-input {{
    margin-bottom: 8px;
    padding: 4px 8px;
    font-family: monospace;
    font-size: 13px;
    width: 300px;
    border: 1px solid #ccc;
    border-radius: 3px;
  }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<div class="meta">Generated: {html.escape(generated_at)}</div>
<div class="legend">
  <span class="l-shared">&#9632; shared write access (2+ tokens)</span>
  <span class="l-highperm">&#9632; high permission (admin/maintain/push)</span>
</div>
<input id="filter-input" type="text" placeholder="Filter rows..." oninput="filterTable(this.value)">
<div class="table-wrap">
{table_html}
</div>
<script>
function filterTable(q) {{
  var rows = document.querySelectorAll('#main-table tbody tr');
  var lq = q.toLowerCase();
  rows.forEach(function(row) {{
    row.style.display = row.textContent.toLowerCase().includes(lq) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""


def generate_reports(output_dir: str, report_output_dir: str = None) -> None:
    if report_output_dir is None:
        report_output_dir = output_dir

    data = load_merged(output_dir)
    generated_at = data.get("generated_at", "")
    rows = flatten_to_rows(data)
    shared_write = find_shared_write_repos(rows)

    token_count = len(data.get("tokens", []))
    repo_count = len(rows)
    print(f"Loaded {token_count} token(s), {repo_count} repo entries, {len(shared_write)} shared-write repos")

    for include_secrets, suffix, label in [
        (True, "report_with_secrets.html", "GitHub PAT Report — With Secrets"),
        (False, "report_without_secrets.html", "GitHub PAT Report — Without Secrets"),
    ]:
        table = build_html_table(rows, shared_write, include_secrets)
        page = build_html_page(table, label, generated_at)
        out_path = os.path.join(report_output_dir, suffix)
        with open(out_path, "w") as f:
            f.write(page)
        print(f"Written: {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate HTML reports from enumerate.py output.")
    parser.add_argument("input_dir", help="Directory containing merged_all.json (output from enumerate.py)")
    parser.add_argument("--output-dir", default=None, help="Where to write HTML reports (default: same as input_dir)")
    args = parser.parse_args()

    generate_reports(args.input_dir, args.output_dir)


if __name__ == "__main__":
    main()
