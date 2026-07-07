---
name: "aws-security-analyzer"
displayName: "AWS Security Analyzer"
description: "Run a consolidated AWS security posture scan from your IDE — Trusted Advisor security findings plus a curated set of IAM, EC2/network, S3, RDS, KMS, container, and detective-control security best-practice checks — via the managed AWS MCP Server, and emit a consolidated JSON + HTML report to a local path."
keywords: ["security", "security audit", "trusted advisor", "iam audit", "ec2 security", "s3 public access", "imdsv2", "security group", "posture", "cspm", "container security", "guardduty", "cloudtrail"]
author: "Venkata Pavan Vishnu Rachapudi"
---

# AWS Security Analyzer Power

This power lets the Kiro agent run a **read-only AWS security posture scan** through the managed **AWS MCP Server** (`aws-mcp`). It pulls **Trusted Advisor** flagged security checks once, runs a curated set of **IAM / EC2 / network / S3 / RDS / KMS** best-practice checks, **EKS / ECS / ECR** container-security checks, plus **GuardDuty & CloudTrail** detective-control checks, and writes a **consolidated JSON + HTML report** to a local path.

## Ground rules (always apply)

1. **Read-only**: This power performs discovery only — `describe*`, `list*`, `get*`, `Support:DescribeTrustedAdvisorChecks/Results`. NEVER create, modify, or delete any resource. No remediation without a separate, explicit user instruction.
2. **One MCP server**: Use only `aws-mcp`. Do NOT add legacy `aws-api-mcp-server` or other MCP servers alongside it — avoids tool conflicts.
3. **Discover, don't assume**: Verify actual operation names via the `aws-mcp` tools before first use in a session. NEVER invent operation names.
4. **Trusted Advisor once**: Pull TA security-category results a single time per scan and cache them in the run state — do not re-poll per check.
5. **Region awareness**: Trusted Advisor Support API is global via `us-east-1`. Regional resource checks (EC2, SG, EBS) MUST be run per target region — ask the user which region(s) to scan; default to the caller's configured region.
6. **Checks are catalogued**: Every check has a stable ID and severity defined in `steering/checks-catalog.md`. Do not add ad-hoc checks without adding them to the catalog first.

# Onboarding

## Step 1: Validate tools work
- **AWS CLI ≥ 2.32.0**: verify with `aws --version`
- **uv/uvx installed**: verify with `uvx --version` (the MCP proxy launches via uvx)
- **Active AWS session**: authenticates via SigV4 through `mcp-proxy-for-aws`. Recommend `aws login` (or `aws sso login --profile <name>`). Verify with `aws sts get-caller-identity` and confirm the account ID with the user.
- **CRITICAL**: On `ExpiredTokenException`, STOP — instruct the user to re-authenticate and restart Kiro.

## Step 2: Confirm scan scope
Ask and record: target account(s), target region(s), and the local output directory for the report. Save to `.kiro/security-analyzer.json`:

```json
{
  "accountId": "AUTO_FROM_STS",
  "regions": ["us-east-1"],
  "outputDir": "./security-reports",
  "trustedAdvisor": true,
  "unusedRoleThresholdDays": 180
}
```

## Step 3: Run the scan
Load `steering/scan-workflow.md` and execute the phases in order (Trusted Advisor → IAM → EC2/network → S3 → RDS → GuardDuty/CloudTrail → KMS → EKS/ECS/ECR → consolidate).

## Step 4: Add a hook (optional)
Add `.kiro/hooks/run-security-scan.kiro.hook`:

```json
{
  "enabled": true,
  "name": "Run AWS Security Scan",
  "description": "Run the consolidated AWS security posture scan and write JSON + HTML to the local report directory",
  "version": "1",
  "when": { "type": "userTriggered" },
  "then": {
    "type": "askAgent",
    "prompt": "Follow steering/scan-workflow.md: pull Trusted Advisor security findings once, run the IAM/EC2/S3 checks in steering/checks-catalog.md against the regions in .kiro/security-analyzer.json, then write the consolidated report per steering/report-output.md. Report the JSON and HTML paths."
  }
}
```

# When to Load Steering Files
- Running the end-to-end scan (phases, TA pull, polling) → `steering/scan-workflow.md`
- The full check catalog with check IDs, severity, and how to evaluate each → `steering/checks-catalog.md`
- Building the consolidated JSON + HTML report and where to write it → `steering/report-output.md`

# Best Practices
- Pull Trusted Advisor security-category checks **once** and reuse; TA results are cached ~24h server-side anyway.
- Batch describe calls per region; page through results fully before scoring.
- Score every finding as PASS / WARN / FAIL and attach the source rule ID + severity from the catalog.
- Keep the report self-contained (inline CSS, no external assets) so it opens offline.

# Troubleshooting
- `ExpiredTokenException` / MCP tools not loading → SigV4 session expired. Re-authenticate and restart the MCP client.
- `AccessDeniedException` on Trusted Advisor → account lacks Business/Enterprise Support, or caller lacks `support:*`. Skip TA, note it in the report, continue with the direct checks.
- `AccessDenied` on IAM credential report → caller lacks `iam:GenerateCredentialReport`; fall back to per-user `list-access-keys` + `get-access-key-last-used`.
- Empty EC2/SG results → wrong region; confirm the region list in `.kiro/security-analyzer.json`.
- Unknown service/operation → verify names via the `aws-mcp` tools before calling.
