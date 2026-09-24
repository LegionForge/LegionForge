#!/usr/bin/env bash
# org_pr_triage.sh — org-wide PR/issue triage for the LegionForge GitHub org.
#
# Read-only by default: reports what Dependabot's auto-merge workflow (see
# .github/workflows/dependabot-automerge.yml) has already handled or flagged,
# plus any non-Dependabot PRs and any issues that look stale/unlabeled.
# Never merges anything itself — that's the workflow's job. This is the
# status dashboard Jp reads to see what needs an engineering decision.
#
# Usage: scripts/org_pr_triage.sh [org]   (default org: LegionForge)

set -euo pipefail
ORG="${1:-LegionForge}"

echo "# LegionForge org PR/issue triage — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo

echo "## Open PRs needing a decision (needs-review label, or non-Dependabot, or CI red)"
gh search prs --owner "$ORG" --state open --json repository,number,title,author,url --limit 100 |
  python3 -c '
import json, sys, subprocess

prs = json.load(sys.stdin)
flagged = []

for p in prs:
    repo = p["repository"]["nameWithOwner"]
    num = p["number"]
    author = p["author"]["login"] if p.get("author") else "unknown"
    detail = json.loads(subprocess.run(
        ["gh", "pr", "view", str(num), "-R", repo, "--json",
         "labels,mergeStateStatus,statusCheckRollup,title,url"],
        capture_output=True, text=True, check=True
    ).stdout)
    labels = [l["name"] for l in detail.get("labels", [])]
    checks = detail.get("statusCheckRollup", [])
    failed = [c["name"] for c in checks if (c.get("conclusion") or c.get("state")) == "FAILURE"]
    reasons = []
    if not author.startswith("dependabot"):
        reasons.append(f"author={author} (not Dependabot — needs human review)")
    if "dependabot-needs-review" in labels:
        reasons.append("labeled dependabot-needs-review (major/0.x bump)")
    if failed:
        failed_str = ", ".join(failed)
        reasons.append(f"CI failing: {failed_str}")
    if reasons:
        flagged.append((repo, num, detail["title"], detail["url"], reasons))

if not flagged:
    print("(none — everything is either merged or waiting on Dependabot auto-merge CI)")
else:
    for repo, num, title, url, reasons in flagged:
        print(f"- {repo}#{num}: {title}")
        for r in reasons:
            print(f"    - {r}")
        print(f"    {url}")
'

echo
echo "## Auto-merged in the last 7 days (informational — no action needed)"
gh search prs --owner "$ORG" --state closed --merged --author "app/dependabot" --json repository,number,title,closedAt --limit 100 |
  python3 -c '
import json, sys, datetime
prs = json.load(sys.stdin)
cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
recent = [p for p in prs if datetime.datetime.fromisoformat(p["closedAt"].replace("Z","+00:00")) > cutoff]
if not recent:
    print("(none in the last 7 days)")
for p in sorted(recent, key=lambda p: p["closedAt"], reverse=True):
    repo = p["repository"]["nameWithOwner"]
    date = p["closedAt"][:10]
    num = p["number"]
    title = p["title"]
    print(f"- {repo}#{num}: {title} ({date})")
'

echo
echo "## Repos without the dependabot-automerge.yml workflow"
for repo in $(gh repo list "$ORG" --limit 100 --json name -q '.[].name'); do
  gh api "repos/$ORG/$repo/contents/.github/workflows/dependabot-automerge.yml" >/dev/null 2>&1 || echo "- $repo"
done
