---
name: report
description: Generate or regenerate the consolidated security report (Markdown + HTML) from a previous scan's findings — with executive summary, per-service breakdown, severity scoring, Well-Architected mappings, and remediation recommendations enriched with AWS documentation links.
---

# Generate Security Report

## Step 1: Validate prerequisites
- Confirm that scan findings exist in run state (from a previous `scan` skill execution).
- If no findings in memory, ask the user to run the scan first or provide a path to a previous JSON report to re-render.

## Step 2: Load findings
- Load all findings from run state (or from a previous Markdown report file).
- Recompute summary: total FAIL/WARN/PASS/accepted, risk score, severity breakdown.

## Step 3: Apply exception list
- If `security-context/exceptions.csv` exists, apply accepted-risk suppression.
- Downgrade matching findings to `PASS (accepted)` with reason and owner attached.
- Flag expired exceptions (review_date before today) — keep as FAIL with note.

## Step 4: Enrich with Well-Architected mappings
- For each FAIL/WARN finding, map to the relevant Well-Architected Security Pillar best-practice ID (SEC##-BP##) using `well-architected-security-mcp-server`.
- Add WAF mapping as a field in the JSON output and as a column/badge in the HTML report.

## Step 5: Enrich with documentation links
- Use `aws-documentation-mcp-server` to search for remediation documentation for the top findings.
- Attach doc links to the `recommendation` field in each finding.

## Step 6: Produce the report files
Follow `steering/report-output.md`:

### Markdown report (.md)
- Structured with proper headings for each category section.
- Include `wafMapping` field per finding where available.
- Include `documentationUrl` per finding where available.
- Version-controllable, readable in any editor or Git diff.

### HTML report (.html)
Self-contained (inline CSS, no external assets), opens offline in any browser:
1. **Header** — account, regions, timestamp, TA availability, MCP servers used.
2. **Executive summary cards** — FAIL/WARN/PASS counts, risk score, severity breakdown with color-coded cards.
3. **Well-Architected coverage** — which SEC controls are covered vs. gaps.
4. **Findings tables** — grouped by category (IAM → EC2/Network → S3 → RDS → KMS → Lambda → API Gateway → SNS/SQS → DynamoDB → CloudFront → ELB/ALB → Secrets Manager → WAF → VPC → OpenSearch → Containers → Detective Controls → Access Analyzer → Compute Optimizer → Trusted Advisor), sorted by severity then status. Row colors: red=FAIL, amber=WARN, green=PASS, grey=accepted.
5. **Accepted risks table** — separate section for suppressed findings with owner/reason/review date.
6. **Footer** — scan metadata, check catalog version, power version.

## Step 7: Write and present
- Write both files to `outputDir` with naming: `security-report-<accountId>-<YYYYMMDD-HHMM>.md` and `.html`.
- Print absolute paths and offer to open the HTML.

## Guardrails
- Read-only. Report generation never modifies AWS resources.
- Never expose secrets or credentials in the report output.
- If enrichment MCP servers are unavailable, produce the report without enrichment and note the limitation.
