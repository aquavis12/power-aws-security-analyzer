---
name: "aws-security-analyzer"
displayName: "AWS Security Analyzer"
description: "Run a consolidated AWS security posture scan from your IDE — Trusted Advisor security findings plus a comprehensive set of IAM, EC2/network, S3, RDS, KMS, Lambda, API Gateway, SNS, SQS, DynamoDB, CloudFront, ELB/ALB/NLB, Secrets Manager, WAF, VPC, OpenSearch, container (EKS/ECS/ECR), detective-control (GuardDuty/CloudTrail), IAM Access Analyzer external-access, and Compute Optimizer best-practice checks — enriched with Well-Architected Security Pillar guidance, IAM deep-analysis, and AWS Documentation references — powered by four MCP servers, emitting a consolidated Markdown + HTML report."
keywords: ["security", "security audit", "trusted advisor", "iam audit", "iam analysis", "ec2 security", "s3 public access", "imdsv2", "security group", "posture", "cspm", "container security", "guardduty", "cloudtrail", "access analyzer", "external access", "compute optimizer", "cost optimization", "lambda", "api gateway", "sns", "sqs", "dynamodb", "cloudfront", "elb", "alb", "waf", "secrets manager", "opensearch", "vpc", "well-architected", "security pillar", "compliance", "cis benchmark", "hipaa", "soc2", "pci dss", "fsbp"]
author: "Venkata Pavan Vishnu Rachapudi"
---

# AWS Security Analyzer Power

This power lets the Kiro agent run a **read-only AWS security posture scan** through **four MCP servers**. It pulls **Trusted Advisor** flagged security checks once, then runs a comprehensive set of best-practice checks across **IAM / EC2 / network / S3 / RDS / KMS / Lambda / API Gateway / SNS / SQS / DynamoDB / CloudFront / ELB-ALB-NLB / Secrets Manager / WAF / VPC / OpenSearch**, **EKS / ECS / ECR** container-security checks, **IAM Access Analyzer** external-access findings, **Compute Optimizer** enrollment and over-provisioned resource detection, plus **GuardDuty & CloudTrail** detective-control checks — all enriched with **Well-Architected Security Pillar** guidance, deep **IAM policy analysis**, and **AWS Documentation** references — and writes a **consolidated Markdown + HTML report** to a local path.

## MCP Servers

| Server | Purpose | Package |
|--------|---------|---------|
| `aws-mcp` | All AWS API calls — Trusted Advisor, IAM, EC2, S3, RDS, KMS, Lambda, GuardDuty, CloudTrail, EKS/ECS/ECR, Access Analyzer, Compute Optimizer | `mcp-proxy-for-aws` |
| `iam-mcp-server` | Deep IAM analysis — policy simulation, inline policy audit, group/role enumeration (read-only mode) | `awslabs.iam-mcp-server` |
| `well-architected-security-mcp-server` | Well-Architected Security Pillar assessment — service status, findings, compliance, posture analysis | `awslabs.well-architected-security-mcp-server` |
| `aws-documentation-mcp-server` | AWS Documentation search & retrieval — remediation guidance, best-practice docs, service references | `awslabs.aws-documentation-mcp-server` |

## Skills

| Skill | Description |
|-------|-------------|
| `scan` | Full end-to-end security posture scan — all phases, all checks, consolidated report |
| `iam-deep-dive` | Deep IAM analysis — credential hygiene, policy simulation, inline audit, Access Analyzer findings |
| `well-architected-assessment` | Assess against Well-Architected Security Pillar — service coverage, compliance, prioritized recommendations |
| `report` | Generate or regenerate the consolidated JSON + HTML report from existing findings |

## Ground rules (always apply)

1. **Read-only**: This power performs discovery only — `describe*`, `list*`, `get*`, `Support:DescribeTrustedAdvisorChecks/Results`. NEVER create, modify, or delete any resource. No remediation without a separate, explicit user instruction.
2. **Four MCP servers**: Use `aws-mcp` for all AWS API calls, `iam-mcp-server` (read-only) for deep IAM analysis, `well-architected-security-mcp-server` for WAF Security Pillar assessment, and `aws-documentation-mcp-server` for documentation enrichment. Do NOT add other MCP servers alongside these.
3. **Discover, don't assume**: Verify actual operation names via the `aws-mcp` tools before first use in a session. NEVER invent operation names.
4. **Trusted Advisor once**: Pull TA security-category results a single time per scan and cache them in the run state — do not re-poll per check.
5. **Region awareness**: Trusted Advisor Support API is global via `us-east-1`. Regional resource checks (EC2, Lambda, RDS, etc.) MUST be run per target region — ask the user which region(s) to scan; default to the caller's configured region.
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
Load `steering/scan-workflow.md` and execute the phases in order (Trusted Advisor → IAM → EC2/network → S3 → RDS → GuardDuty/CloudTrail → KMS → EKS/ECS/ECR → Lambda → API Gateway → SNS/SQS → DynamoDB → CloudFront → ELB/ALB/NLB → Secrets Manager → WAF → VPC → OpenSearch → IAM Access Analyzer → Compute Optimizer → consolidate).

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
    "prompt": "Follow steering/scan-workflow.md: pull Trusted Advisor security findings once, run all checks in steering/checks-catalog.md against the regions in .kiro/security-analyzer.json, enrich with Well-Architected mappings and documentation links, then write the consolidated report per steering/report-output.md. Report the Markdown and HTML paths."
  }
}
```

# When to Load Steering Files
- Running the end-to-end scan (phases, TA pull, polling) → `steering/scan-workflow.md`
- The full check catalog with check IDs, severity, and how to evaluate each → `steering/checks-catalog.md`
- Building the consolidated Markdown + HTML report and where to write it → `steering/report-output.md`

# When to Use Skills
- Full scan → `skills/scan/SKILL.md`
- Deep IAM-only analysis → `skills/iam-deep-dive/SKILL.md`
- Well-Architected Security Pillar assessment → `skills/well-architected-assessment/SKILL.md`
- Report generation/regeneration → `skills/report/SKILL.md`

# Best Practices
- Pull Trusted Advisor security-category checks **once** and reuse; TA results are cached ~24h server-side anyway.
- Batch describe calls per region; page through results fully before scoring.
- Score every finding as PASS / WARN / FAIL and attach the source rule ID + severity from the catalog.
- Use `well-architected-security-mcp-server` to map findings to WAF Security Pillar best-practice IDs.
- Use `aws-documentation-mcp-server` to attach authoritative remediation docs to recommendations.
- Use `iam-mcp-server` for policy simulation when validating over-permissive findings.
- Keep the report self-contained (inline CSS, no external assets) so it opens offline.

# Troubleshooting
- `ExpiredTokenException` / MCP tools not loading → SigV4 session expired. Re-authenticate and restart the MCP client.
- `AccessDeniedException` on Trusted Advisor → account lacks Business/Enterprise Support, or caller lacks `support:*`. Skip TA, note it in the report, continue with the direct checks.
- `AccessDenied` on IAM credential report → caller lacks `iam:GenerateCredentialReport`; fall back to per-user `list-access-keys` + `get-access-key-last-used`.
- Empty EC2/SG results → wrong region; confirm the region list in `.kiro/security-analyzer.json`.
- Unknown service/operation → verify names via the `aws-mcp` tools before calling.
- IAM MCP server errors → confirm `--readonly` flag is set; the server blocks all write operations in this mode.
- Well-Architected Security server unavailable → skip WAF enrichment, note in report, continue with direct checks.
- Documentation server unavailable → skip doc links, note in report, continue.

## License and support

This power (**AWS Security Analyzer**) is licensed under **MIT** (SPDX: `MIT`). See [LICENSE](LICENSE).

It integrates with the **AWS MCP Server** via `mcp-proxy-for-aws` (SPDX: `Apache-2.0`), the **IAM MCP Server** (Apache-2.0), the **Well-Architected Security MCP Server** (Apache-2.0), and the **AWS Documentation MCP Server** (Apache-2.0).

- Privacy Policy: [AWS Privacy Notice](https://aws.amazon.com/privacy/)
- Support: [github.com/aquavis12/power-aws-security-analyzer/issues](https://github.com/aquavis12/power-aws-security-analyzer/issues) or rachapudivishnu9@gmail.com
