# AWS Security Analyzer — Kiro Power

A [Kiro Power](https://kiro.dev/powers) that runs a **consolidated, read-only AWS security posture scan** from your IDE and emits a **JSON + HTML report** to a local path.

It pulls **Trusted Advisor** flagged security findings once, then runs a curated catalog of **49 security checks** across IAM, EC2/network, S3, RDS, KMS, containers (EKS/ECS/ECR), and detective controls (GuardDuty/CloudTrail) — all through the managed **AWS MCP Server** (`aws-mcp`).

> **Read-only by design.** Every operation is a `describe` / `list` / `get`. The power never creates, modifies, or deletes a resource, and writes its report only to your local machine.

---

## What it checks

| Domain | Coverage |
|---|---|
| **IAM & credentials** | Unused key pairs, key rotation (30/90d), wildcard/full-admin policies, permissions boundaries, unused roles (180d+), inactive users, MFA (users + root) |
| **Account foundations** | Root access keys, root usage, password policy, inline policies, AWS Config enabled, alternate contacts, IAM Access Analyzer |
| **EC2 / network** | IMDSv2 enforcement, `0.0.0.0/0` ingress, SSH-22/RDP-3389 exposure, SSM-managed, termination protection |
| **S3** | Account + bucket public access block, wildcard bucket policy, encryption, TLS-only, versioning (+ lifecycle when versioning is on) |
| **RDS** | Deletion protection (instance + cluster), public accessibility, storage encryption, backups/cross-region, secret rotation |
| **KMS** | Key rotation, over-permissive key policy/grants |
| **Containers** | EKS (endpoint, secrets encryption, logging, IRSA, SG/EOL), ECR (scan-on-push, tag immutability, wildcard policy, lifecycle), ECS (privileged, plaintext secrets, host mode, logging) |
| **Detective controls** | GuardDuty enabled + findings, CloudTrail enabled/multi-region/validation/bucket hardening |
| **Trusted Advisor** | All flagged security-category checks (pulled once per scan) |

Full catalog with check IDs, severity, and evaluation logic: [`steering/checks-catalog.md`](steering/checks-catalog.md).

---

## Prerequisites

- **AWS CLI ≥ 2.32.0** — `aws --version`
- **uv / uvx** — `uvx --version` (launches the MCP proxy)
- **An active AWS session** — `aws login` or `aws sso login --profile <name>`, verified with `aws sts get-caller-identity`
- Recommended IAM: the AWS managed **`SecurityAudit`** policy (read-only across security configs). Trusted Advisor checks additionally require Business/Enterprise Support.

---

## Install

**From a local folder**
1. Clone this repo.
2. Open Kiro → **Powers** panel → **Add Custom Power**.
3. Choose **Import power from a folder** and select this directory.

**From GitHub**
- Kiro → **Add Custom Power** → **Import power from GitHub**, then paste the repo URL.

Activate by using keywords like *security scan*, *trusted advisor*, *iam audit*, or *s3 public access* in a conversation.

---

## Usage

1. Confirm scope — the power records target account, region(s), and output directory in `.kiro/security-analyzer.json`.
2. Say something like *"run the AWS security scan against us-east-1 and ap-south-1."*
3. The power executes the phases in [`steering/scan-workflow.md`](steering/scan-workflow.md) and writes:
   - `security-report-<account>-<timestamp>.json`
   - `security-report-<account>-<timestamp>.html`

Optional context tuning (accepted-risk exceptions, severity overrides, scope) lives in [`context-templates/`](context-templates/).

---

## Repository layout

```
power-aws-security-analyzer/
├── POWER.md                    # Root skill: frontmatter, onboarding, steering map
├── mcp.json                    # aws-mcp server config + scoped autoApprove
├── LICENSE                     # MIT
├── README.md
├── steering/
│   ├── scan-workflow.md        # 10-phase scan orchestration
│   ├── checks-catalog.md       # 49 checks with IDs, severity, evaluation
│   └── report-output.md        # JSON + HTML report schema
└── context-templates/
    ├── README.md
    ├── scan-scope.json
    └── exceptions.csv
```

---

## Auto-approve & safety

`mcp.json` auto-approves only the AWS MCP server's read/discovery tools
(`aws___call_aws`, `aws___run_script`, `aws___get_tasks`, region/documentation
tools). `aws___get_presigned_url` is **intentionally excluded** so the power
cannot upload/download objects — keeping the scan read-only and the report
local.

---

## License

[MIT](LICENSE) © 2026 Venkata Pavan Vishnu Rachapudi
