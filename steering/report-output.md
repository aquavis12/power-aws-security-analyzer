# Report Output — Consolidated JSON + HTML

Write BOTH files to the `outputDir` from `.kiro/security-analyzer.json` (default `./security-reports`).
Filenames: `security-report-<accountId>-<YYYYMMDD-HHMM>.json` and `.html`.

## JSON schema

```json
{
  "account": "123456789012",
  "generatedAt": "2026-07-07T10:30:00Z",
  "regions": ["us-east-1"],
  "trustedAdvisor": "available | unavailable",
  "summary": {
    "fail": 0, "warn": 0, "pass": 0, "accepted": 0,
    "riskScore": 0,
    "bySeverity": { "H": 0, "M": 0, "L": 0 }
  },
  "findings": [
    {
      "id": "EC2IMDSv2",
      "category": "EC2",
      "title": "IMDSv2 not enforced",
      "severity": "H",
      "status": "FAIL",              // PASS | WARN | FAIL | "PASS (accepted)"
      "region": "us-east-1",
      "resource": "i-0abc123...",
      "evidence": "HttpTokens=optional",
      "recommendation": "Set MetadataOptions.HttpTokens=required",
      "source": "EC2"
    }
  ],
  "trustedAdvisorFindings": []
}
```

- `riskScore` = sum of FAIL weights (H=3, M=2, L=1). Findings with status `PASS (accepted)` are EXCLUDED from the risk score.
- Findings suppressed via `security-context/exceptions.csv` carry `status: "PASS (accepted)"` plus `acceptedReason` and `acceptedOwner`. Add an `accepted` count to `summary`.
- One `findings[]` entry per resource per check.

## HTML report

Self-contained (inline CSS, no external assets) so it opens offline. Include:
1. **Header** — account, regions, timestamp, TA availability.
2. **Summary cards** — total FAIL / WARN / PASS and risk score; severity breakdown (H/M/L).
3. **Findings table** — grouped by category (IAM → EC2/Network → S3 → Trusted Advisor), sorted by severity then status. Columns: Check, Severity, Status, Region, Resource, Evidence, Recommendation. Color rows: FAIL red, WARN amber, PASS green, `PASS (accepted)` grey with the acceptance reason/owner shown in the Evidence column.
4. **Footer** — note the scan is read-only and lists the check catalog version.

## Writing the files
- Build the JSON object in memory, then write both files via a small local script (Python/Node) in the workspace.
- After writing, print the absolute paths of both files to the user and offer to open the HTML.
- Do NOT upload anywhere unless the user explicitly asks.
