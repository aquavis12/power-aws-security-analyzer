# Report Output — Consolidated Markdown + HTML

Write BOTH files to the `outputDir` from `.kiro/security-analyzer.json` (default `./security-reports`).
Filenames: `security-report-<accountId>-<YYYYMMDD-HHMM>.md` and `.html`.

---

## Markdown report (.md)

The `.md` file is the source of truth — version-controllable, readable in any editor or Git diff.

### Structure

```markdown
# AWS Security Posture Report

| Field | Value |
|-------|-------|
| Account | 123456789012 |
| Regions | us-east-1, ap-south-1 |
| Generated | 2026-08-14T10:30:00Z |
| Trusted Advisor | available / unavailable |
| Risk Score | 42 (H×3 + M×2 + L×1) |

## Executive Summary

| Metric | Count |
|--------|-------|
| FAIL | N |
| WARN | N |
| PASS | N |
| Accepted (suppressed) | N |
| By Severity | H: N, M: N, L: N |

## Findings — [Category Name]

| Check | ID | Sev | Status | Region | Resource ARN | Resource Name | Resource ID | Evidence | Recommendation | Compliance | WAF Mapping | Docs |
|-------|-----|-----|--------|--------|--------------|---------------|-------------|----------|----------------|------------|-------------|------|
```

### Resource identification columns
Every finding MUST include these three resource-identity columns:
- **Resource ARN**: Full Amazon Resource Name (e.g., `arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123`). For account-level findings use `arn:aws:iam::<accountId>:root`.
- **Resource Name**: Human-friendly name — Name tag, bucket name, function name, role name, cluster name, etc. Falls back to resource ID if no name exists.
- **Resource ID**: AWS-assigned unique identifier — `sg-0abc123`, `i-0def456`, `AKIAIOSFODNN7EXAMPLE`, etc. For account-level findings use the account ID.

When a single check flags multiple resources, either:
- List one row per resource (preferred for ≤5 resources), OR
- Combine in a single row with comma-separated values in each column (for >5 resources, truncate at 10 and note "… and N more").

### Compliance column
Each finding includes a `Compliance` field listing all frameworks violated (comma-separated):
- `CIS 1.5` — CIS AWS Foundations Benchmark v3.0 section
- `HIPAA §164.312(d)` — HIPAA safeguard reference
- `SOC2 CC6.1` — SOC 2 Trust Services Criteria
- `PCI 8.3` — PCI DSS v4.0 requirement
- `FSBP EC2.8` — AWS Foundational Security Best Practices control

Map each check ID to frameworks using `steering/checks-catalog.md` § "Compliance Framework Mappings".

### Category order
IAM → EC2/Network → S3 → RDS → KMS → Lambda → API Gateway → SNS/SQS → DynamoDB → CloudFront → ELB/ALB → Secrets Manager → WAF → VPC → OpenSearch → Containers → Detective Controls → Access Analyzer → Compute Optimizer → Trusted Advisor

### Sorting
Within each category: severity (H→M→L) then status (FAIL→WARN→PASS).

### Accepted risks section
Separate section listing all suppressed findings with owner, reason, review date, and expiry status.

### Footer
- Scan is read-only — no resources were modified.
- Check catalog version, power version, MCP servers used.

---

## HTML report (.html)

Self-contained (inline CSS, no external assets) so it opens offline in any browser. Include:

1. **Header** — account, regions, timestamp, TA availability, MCP servers used.
2. **Executive summary cards** — total FAIL / WARN / PASS and risk score; severity breakdown (H/M/L). Use colored cards (red/amber/green).
3. **Compliance posture summary** — per-framework pass rate:
   - CIS AWS Foundations Benchmark v3.0: X/Y controls passing (Z%)
   - HIPAA: X/Y safeguards passing (Z%)
   - SOC 2: X/Y criteria passing (Z%)
   - PCI DSS v4.0: X/Y requirements passing (Z%)
   - AWS FSBP: X/Y controls passing (Z%)
3. **Findings tables** — grouped by category (same order as Markdown), sorted by severity then status. Columns: Check, ID, Severity, Status, Region, Resource ARN, Resource Name, Resource ID, Evidence, Recommendation, Compliance (CIS/HIPAA/SOC2/PCI/FSBP tags), WAF Mapping, Docs Link. Row colors: FAIL=red, WARN=amber, PASS=green, `PASS (accepted)`=grey with acceptance reason/owner shown in Evidence column.
4. **Accepted risks table** — separate section for suppressed findings.
5. **Footer** — note the scan is read-only, check catalog version, power version.

---

## Scoring rules

- `riskScore` = sum of FAIL weights (H=3, M=2, L=1). Findings with status `PASS (accepted)` are EXCLUDED from the risk score.
- Findings suppressed via `security-context/exceptions.csv` carry `status: "PASS (accepted)"` plus `acceptedReason` and `acceptedOwner`.
- One finding entry per resource per check.

## Writing the files

1. Build findings data in memory during the scan.
2. Render the `.md` file (always — lightweight, version-controllable).
3. Render the `.html` file (always — self-contained, color-coded, opens offline).
4. Print the absolute paths of both files to the user and offer to open the HTML.
5. Do NOT upload anywhere unless the user explicitly asks.
