---
name: scan
description: Run the full end-to-end security posture scan — Trusted Advisor, IAM, EC2/network, S3, RDS, KMS, containers, detective controls, IAM Access Analyzer, Compute Optimizer — and produce the consolidated JSON + HTML report.
---

# Full Security Posture Scan

## Step 1: Validate AWS session
- Run `aws sts get-caller-identity` via `aws-mcp` to confirm credentials are valid.
- If expired, instruct the user to re-authenticate (`aws login` or `aws sso login`).
- Record the account ID and default region.

## Step 2: Confirm scan scope
- Load `.kiro/security-analyzer.json` if it exists. Otherwise ask the user for:
  - Target region(s)
  - Output directory (default `./security-reports`)
  - Whether to include Trusted Advisor (requires Business/Enterprise Support)
- Save scope to `.kiro/security-analyzer.json`.

## Step 3: Execute the scan
- Load `steering/scan-workflow.md` and execute all phases in order:
  1. Trusted Advisor (global, once)
  2. IAM & credentials (global)
  3. EC2 / network (per region)
  4. S3 (global + per bucket)
  5. RDS / data protection (per region)
  6. Detective controls — GuardDuty & CloudTrail (per region + global)
  7. KMS (per region)
  8. Container security — EKS / ECS / ECR (per region)
  9. IAM Access Analyzer external access (per region)
  10. Compute Optimizer (global)
  11. Consolidate & score

## Step 4: Enrich findings
- Use `well-architected-security-mcp-server` to cross-reference findings against the Well-Architected Security Pillar. Attach WAF best-practice IDs to relevant findings.
- Use `iam-mcp-server` (read-only) for deeper IAM analysis: simulate principal policies for over-permissive findings, retrieve inline policy documents.
- Use `aws-documentation-mcp-server` to attach relevant AWS documentation links to recommendations.

## Step 5: Produce the report
- Follow `steering/report-output.md` to write both Markdown and HTML files to `outputDir`.
- Print the absolute paths and offer to open the HTML.

## Step 6: Summary
- Present a brief summary to the user: total FAIL/WARN/PASS, risk score, top 5 critical findings, and the report file paths.

## Guardrails
- Read-only. Never create, modify, or delete any AWS resource.
- Page through ALL results before scoring.
- If any API is denied, note it in the report and continue.
- Never invent operation names — discover via `aws-mcp` tools first.
