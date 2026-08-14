# AWS Security Analyzer — Kiro Power

A [Kiro Power](https://kiro.dev/powers) that runs a **read-only, compliance-mapped AWS security posture scan** from your IDE — **104 checks** across every major service, mapped to **CIS, HIPAA, SOC 2, PCI DSS, and AWS FSBP** — powered by four MCP servers.

> **Read-only by design.** Every operation is `describe` / `list` / `get`. Never creates, modifies, or deletes. Report stays local.

---

## Install

Kiro → Powers panel → Add Custom Power → Import from GitHub:

```
https://github.com/aquavis12/power-aws-security-analyzer
```

Kiro reads `plugin.json` + `mcp.json` and installs automatically. Activates on keywords like *security scan*, *iam audit*, *compliance*, *cis benchmark*, *hipaa*.

Prerequisites: AWS CLI ≥ 2.32.0 · `uvx` installed · active `aws sts get-caller-identity`.

---

## What it checks (104 checks)

| Domain | Key checks |
|--------|-----------|
| **IAM & credentials** | Key rotation, wildcard policies, unused roles/users, MFA, root hygiene, password policy, permissions boundaries |
| **EC2 / network** | IMDSv2, 0.0.0.0/0 ingress, SSH/RDP exposure, SSM-managed, termination protection |
| **S3** | Public access block (account + bucket), wildcard policy, encryption, TLS-only, versioning + lifecycle |
| **RDS** | Deletion protection, public access, encryption, backups, secret rotation |
| **KMS** | Key rotation, over-permissive key policies/grants |
| **Lambda** | Public access, deprecated runtimes, env secrets, function URL auth, code signing, tracing |
| **API Gateway** | No authorizer, no WAF, logging, throttling, mTLS |
| **SNS / SQS** | Public access, encryption, DLQ, delivery logging |
| **DynamoDB** | PITR, deletion protection, CMK encryption, auto-scaling |
| **CloudFront** | HTTPS-only, WAF, OAC, TLS version, logging |
| **ELB / ALB / NLB** | Access logs, WAF, deletion protection, TLS policy, HTTP redirect |
| **Secrets Manager** | Rotation, CMK encryption, stale secrets |
| **WAF** | Empty ACLs, logging, rate-based rules |
| **VPC** | Flow logs, default VPC usage, gateway endpoints |
| **OpenSearch** | Public access, encryption at rest, node-to-node, audit logs |
| **Containers (EKS/ECS/ECR)** | Public endpoint, secrets encryption, logging, privileged mode, scan-on-push |
| **Detective controls** | GuardDuty, CloudTrail, Security Hub integration |
| **IAM Access Analyzer** | External access findings, unused access findings |
| **Compute Optimizer** | Enrollment status, over-provisioned resources |
| **Trusted Advisor** | All flagged security-category checks |

---

## Compliance frameworks

Every finding maps to applicable compliance controls:

| Framework | Coverage |
|-----------|----------|
| **CIS AWS Foundations Benchmark v3.0** | 23+ controls mapped |
| **HIPAA** | 13+ safeguard references |
| **SOC 2 Type II** | 10+ Trust Services Criteria |
| **PCI DSS v4.0** | 11+ requirements mapped |
| **AWS Foundational Security Best Practices** | 28+ controls mapped |

The report shows per-framework pass rates and tags each finding with violated controls.

---

## MCP Servers

| Server | Role |
|--------|------|
| `aws-mcp` | All AWS API calls via managed proxy |
| `iam-mcp-server` | Deep IAM analysis (read-only mode) |
| `well-architected-security-mcp-server` | WA Security Pillar posture analysis |
| `aws-documentation-mcp-server` | Remediation docs and best-practice references |

---

## Skills

| Skill | What it does |
|-------|-------------|
| `scan` | Full end-to-end posture scan — all 21 phases, all 104 checks, consolidated report |
| `iam-deep-dive` | Deep IAM analysis — policy simulation, inline audit, Access Analyzer |
| `well-architected-assessment` | WA Security Pillar — service coverage, compliance, recommendations |
| `report` | Generate/regenerate Markdown + HTML report from existing findings |

---

## Usage

1. Say *"run the AWS security scan against us-east-1"*
2. The power executes 21 phases, scores 104 checks, maps compliance frameworks
3. Outputs:
   - `security-report-<account>-<timestamp>.md`
   - `security-report-<account>-<timestamp>.html`

---

## Repository layout

```
power-aws-security-analyzer/
├── POWER.md                    # Power definition + onboarding
├── plugin.json                 # Kiro plugin manifest
├── mcp.json                    # 4 MCP server configs
├── LICENSE                     # MIT
├── README.md
├── skills/
│   ├── scan/SKILL.md           # Full scan skill
│   ├── iam-deep-dive/SKILL.md  # IAM deep-dive skill
│   ├── well-architected-assessment/SKILL.md
│   └── report/SKILL.md         # Report generation skill
├── steering/
│   ├── scan-workflow.md        # 21-phase scan orchestration
│   ├── checks-catalog.md       # 104 checks + compliance mappings
│   └── report-output.md        # Markdown + HTML report schema
└── context-templates/
    ├── scan-scope.json
    └── exceptions.csv
```

---

## License

[MIT](LICENSE) © 2026 Venkata Pavan Vishnu Rachapudi

---

## Privacy & Support

- **Privacy Policy**: [AWS Privacy Notice](https://aws.amazon.com/privacy/)
- **Support**: [GitHub Issues](https://github.com/aquavis12/power-aws-security-analyzer/issues) or rachapudivishnu9@gmail.com
