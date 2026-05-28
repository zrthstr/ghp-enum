# ghp-enum

Enumerate GitHub Personal Access Tokens: repos, permissions, secrets, variables, and branch protections. Produces per-token JSON files and HTML reports.

## Install

```bash
git clone git@github.com:zrthstr/ghp-enum.git
cd ghp-enum
uv sync
```

## Usage

Create a `tokens.txt` with one PAT per line (`#` for comments):

```
# some account
ghp_xxxxxxxxxxxxxx
# other account
ghp_yyyyyyyyyyyyyy
```

**Enumerate:**
```bash
uv run python enumerate.py tokens.txt --output-dir ./output
```

Writes one JSON file per token (`{username}_{token_prefix}.json`) plus `merged_all.json` into `./output/`.

**Generate reports:**
```bash
uv run python report.py ./output
```

Writes two HTML files into `./output/`:
- `report_with_secrets.html` — full data including secret and variable names
- `report_without_secrets.html` — same but secrets/variables columns hidden

## Output

Each per-token JSON contains:
- Authenticated user info and token scopes
- All accessible repos with permission level (`admin` / `maintain` / `push` / `triage` / `pull`)
- Repo Actions secrets and variables (names only, not values)
- Branch protection rules per branch
- Org-level secrets and variables for each org the token belongs to

The HTML reports highlight repos where two or more tokens share write/admin access.

## Notes

- Secrets and variables endpoints require `admin` scope on the repo/org; 403s are recorded as `permission_denied` and do not abort the run
- Rate limits are handled automatically — the script sleeps until the reset window if the limit is nearly exhausted
- `tokens.txt` and `output/` are gitignored
