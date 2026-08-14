<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/hero-orbital-dark.png">
  <img src="assets/hero-orbital-light.png" alt="AWS Security Analyzer — Kiro Power" width="100%">
</picture>

<h1 align="center">AWS Security Analyzer</h1>

<p align="center">
  A <a href="https://kiro.dev/powers">Kiro Power</a> that runs a read-only AWS security posture scan from your IDE —<br>
  <b>104 checks</b> across every major service, mapped to <b>CIS, HIPAA, SOC 2, PCI DSS</b> and <b>AWS FSBP</b>.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/checks-104-ff9900?style=flat-square">
  <img src="https://img.shields.io/badge/frameworks-5-4dd0e1?style=flat-square">
  <img src="https://img.shields.io/badge/MCP%20servers-4-4dd0e1?style=flat-square">
  <img src="https://img.shields.io/badge/license-MIT-666?style=flat-square">
</p>

---

> **Read-only by design.** Every call is `describe` / `list` / `get`. Nothing is created, modified, or deleted. The report stays on your machine.

## Install

Kiro → **Powers** → **Add Custom Power** → **Import from GitHub**:

```
https://github.com/aquavis12/power-aws-security-analyzer
```

Kiro reads `plugin.json` + `mcp.json` and installs automatically. Activates on *security scan*, *iam audit*, *compliance*, *cis benchmark*, *hipaa*.

**Prerequisites:** AWS CLI ≥ 2.32.0 · `uvx` · a working `aws sts get-caller-identity`.

## Usage

```
run the AWS security scan against us-east-1
```

21 phases, 104 checks, compliance mapping — then two files land in your workspace:

```
security-report-<account>-<timestamp>.md
security-report-<account>-<timestamp>.html
```

## Coverage

**Identity & data** — IAM (key rotation, wildcard policies, MFA, root hygiene, boundaries), KMS, Secrets Manager, S3, RDS, DynamoDB.

**Network & edge** — EC2/VPC (IMDSv2, 0.0.0.0/0 ingress, flow logs), ELB/ALB/NLB, CloudFront, API Gateway, WAF.

**Compute & app** — Lambda (public access, deprecated runtimes, env secrets, function URL auth), EKS/ECS/ECR, OpenSearch, SNS/SQS.

**Detective & advisory** — GuardDuty, CloudTrail, Security Hub, IAM Access Analyzer, Compute Optimizer, Trusted Advisor.

Every finding is tagged with the controls it violates: **CIS AWS Foundations v3.0** (23+), **AWS FSBP** (28+), **HIPAA** (13+), **PCI DSS v4.0** (11+), **SOC 2 Type II** (10+). The report shows per-framework pass rates.

## Skills

| Skill | What it does |
|-------|--------------|
| `scan` | Full posture scan — 21 phases, 104 checks, consolidated report |
| `iam-deep-dive` | Policy simulation, inline policy audit, Access Analyzer findings |
| `well-architected-assessment` | WA Security Pillar — coverage, compliance, recommendations |
| `report` | Regenerate Markdown + HTML from existing findings |

## MCP servers

`aws-mcp` (all API calls) · `iam-mcp-server` (deep IAM, read-only) · `well-architected-security-mcp-server` · `aws-documentation-mcp-server` (remediation references)

## Layout

```
├── POWER.md · plugin.json · mcp.json
├── skills/          scan · iam-deep-dive · well-architected-assessment · report
├── steering/        scan-workflow.md · checks-catalog.md · report-output.md
└── context-templates/  scan-scope.json · exceptions.csv
```

---

[MIT](LICENSE) © 2026 Venkata Pavan Vishnu Rachapudi

---

## Privacy & Support

- **Privacy Policy**: [AWS Privacy Notice](https://aws.amazon.com/privacy/)
- **Support**: [GitHub Issues](https://github.com/aquavis12/power-aws-security-analyzer/issues) or rachapudivishnu9@gmail.com
