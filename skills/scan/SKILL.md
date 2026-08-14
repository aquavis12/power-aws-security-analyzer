---
name: scan
description: Run the full end-to-end security posture scan — Trusted Advisor, IAM, EC2/network, S3, RDS, KMS, containers, detective controls, IAM Access Analyzer, Compute Optimizer — and produce the consolidated JSON + HTML report with full resource identification (ARN, Name, ID).
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

## Step 3: Resource identification requirements
For EVERY finding, capture the following resource identifiers wherever the AWS API provides them:
- **resourceArn**: The full ARN (e.g., `arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123`). Construct it from API responses if not returned directly.
- **resourceName**: The human-readable name (e.g., Name tag value, bucket name, function name, role name, cluster name).
- **resourceId**: The AWS-assigned unique ID (e.g., `sg-0abc123`, `i-0def456`, `vol-789`, `AKIAIOSFODNN7EXAMPLE`).

If an API does not return all three, populate what is available:
- Security Groups: ARN (construct from region+account+sg-id), Name tag or GroupName, GroupId.
- EC2 instances: ARN (construct), Name tag, InstanceId.
- S3 buckets: ARN (`arn:aws:s3:::bucket-name`), bucket name, bucket name (same).
- IAM users/roles: ARN (from API), UserName/RoleName, UserId/RoleId.
- RDS instances: DBInstanceArn, DBInstanceIdentifier, DbiResourceId.
- Lambda functions: FunctionArn, FunctionName, RevisionId.
- KMS keys: KeyArn (from metadata), alias if any, KeyId.
- EKS clusters: cluster ARN, cluster name, cluster name.
- VPCs: ARN (construct), Name tag, VpcId.
- For account-level findings: use `arn:aws:iam::<accountId>:root` as ARN, "Account" as name, accountId as ID.

## Step 4: Execute the scan
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

## Step 5: Enrich findings
- Use `well-architected-security-mcp-server` to cross-reference findings against the Well-Architected Security Pillar. Attach WAF best-practice IDs to relevant findings.
- Use `iam-mcp-server` (read-only) for deeper IAM analysis: simulate principal policies for over-permissive findings, retrieve inline policy documents.
- Use `aws-documentation-mcp-server` to attach relevant AWS documentation links to recommendations.

## Step 6: Produce the report
- Follow `steering/report-output.md` to write both Markdown and HTML files to `outputDir`.
- Print the absolute paths and offer to open the HTML.

## Step 7: Summary
- Present a brief summary to the user: total FAIL/WARN/PASS, risk score, top 5 critical findings, and the report file paths.

## Guardrails
- Read-only. Never create, modify, or delete any AWS resource.
- Page through ALL results before scoring.
- If any API is denied, note it in the report and continue.
- Never invent operation names — discover via `aws-mcp` tools first.
