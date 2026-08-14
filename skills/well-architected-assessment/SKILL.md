---
name: well-architected-assessment
description: Assess the AWS account's security posture against the Well-Architected Security Pillar — check security service status, retrieve findings, analyze compliance, and provide prioritized recommendations with documentation references.
---

# Well-Architected Security Assessment

## Step 1: Validate AWS session
- Run `aws sts get-caller-identity` to confirm credentials.
- Record account ID and region.

## Step 2: Check security services status
- Use `well-architected-security-mcp-server` → `CheckSecurityServices` to verify operational status of:
  - Amazon GuardDuty
  - AWS Security Hub
  - Amazon Inspector
  - IAM Access Analyzer
- Record which services are active, partially configured, or missing per region.

## Step 3: Retrieve security findings
- Use `GetSecurityFindings` to collect active findings from Security Hub, GuardDuty, and Inspector.
- Filter by severity (CRITICAL, HIGH first) and resource type.
- Cross-reference against findings already captured in the scan workflow to avoid duplicates.

## Step 4: Compliance status check
- Use `GetResourceComplianceStatus` to identify resources non-compliant against active security standards (CIS, AWS Foundational Security Best Practices, PCI DSS if enabled).
- Map compliance failures to the power's check catalog where possible.

## Step 5: Explore resources
- Use `ExploreAwsResources` to discover resources across services and regions for complete coverage.
- Identify resources not covered by existing security checks.

## Step 6: Analyze security posture
- Use `AnalyzeSecurityPosture` for a comprehensive evaluation against the Well-Architected Security Pillar.
- Extract prioritized recommendations and map to:
  - SEC01 (Secure account) — root hygiene, alternate contacts, Config
  - SEC02 (Identity management) — MFA, password policy, federation
  - SEC03 (Permissions management) — least privilege, boundaries, conditions
  - SEC04 (Detect) — GuardDuty, CloudTrail, Security Hub
  - SEC05 (Network protection) — SGs, NACLs, VPC endpoints
  - SEC06 (Compute protection) — IMDSv2, SSM, patching
  - SEC07 (Data classification) — encryption, access controls
  - SEC08 (Data protection at rest) — KMS, S3 encryption
  - SEC09 (Data protection in transit) — TLS enforcement
  - SEC10 (Incident response) — runbooks, forensics readiness

## Step 7: Enrich with documentation
- Use `aws-documentation-mcp-server` to pull relevant Security Pillar documentation for each recommendation.
- Search for implementation guides, service-specific security chapters, and IAM best practices.

## Step 8: Produce output
- Attach Well-Architected best-practice IDs (SEC##-BP##) to findings in the main report.
- Add a dedicated "Well-Architected Security Pillar" section to the HTML report showing:
  - Service coverage status (GuardDuty, Security Hub, Inspector, Access Analyzer)
  - Compliance posture summary
  - Top recommendations mapped to WAF controls
  - Links to relevant AWS documentation

## Guardrails
- Read-only. The WA Security server only reads — no modifications.
- If Security Hub or Inspector is not enabled, note the gap and continue.
- Never invent WAF best-practice IDs — only use those returned by the tool.
- Reference AWS docs via `aws-documentation-mcp-server`, not hardcoded URLs.
