---
name: iam-deep-dive
description: Perform a deep IAM security analysis — credential hygiene, policy simulation, inline policy audit, unused roles/users, MFA enforcement, Access Analyzer findings, and permissions boundary coverage — using both aws-mcp and the dedicated IAM MCP server.
---

# IAM Deep-Dive Analysis

## Step 1: Validate AWS session
- Run `aws sts get-caller-identity` to confirm credentials.
- Record account ID and region.

## Step 2: Credential report analysis
- Generate and retrieve the IAM credential report via `aws-mcp`.
- Parse for: root access keys, root MFA, user MFA status, password age, access key rotation, last activity dates.
- Run checks 1–6, 42–48 from `steering/checks-catalog.md`.

## Step 3: Policy analysis via IAM MCP server
- Use `iam-mcp-server` (read-only mode) to:
  - `list_users` and `get_user` for each user — enumerate attached policies, inline policies, group memberships.
  - `list_roles` — identify roles with long session durations, unused roles, over-privileged cluster/service roles.
  - `list_policies` (scope=Local) — find customer-managed policies with wildcard actions.
  - `list_user_policies` / `list_role_policies` + `get_user_policy` / `get_role_policy` — audit all inline policies for full-admin or wildcard statements.
  - `simulate_principal_policy` — for any flagged over-permissive principal, simulate specific sensitive actions (s3:*, iam:*, ec2:*) to confirm actual effective permissions.

## Step 4: IAM Access Analyzer findings
- Via `aws-mcp`: `accessanalyzer:ListAnalyzers` per region.
- For each active analyzer: `accessanalyzer:ListFindings` (status=ACTIVE).
- Categorize: external access findings (FAIL/H) vs. unused access findings (WARN/M).
- For each external access finding, record: resource ARN, external principal, condition, and finding type.

## Step 5: Permissions boundary audit
- Identify all roles and users WITHOUT a permissions boundary attached.
- Flag roles used by compute services (Lambda execution roles, EC2 instance profiles, ECS task roles) that lack boundaries — these are highest risk.

## Step 6: Enrich with documentation
- Use `aws-documentation-mcp-server` to attach relevant IAM best-practice documentation links to each recommendation (MFA setup, key rotation, permissions boundaries, Access Analyzer).

## Step 7: Produce findings
- Score all findings per `steering/checks-catalog.md`.
- Output a focused IAM section in the standard report format (JSON + HTML) or as a standalone summary to the user.

## Guardrails
- Read-only. The IAM MCP server runs with `--readonly` flag. Never create, modify, or delete IAM resources.
- Never expose access key values, secrets, or session tokens in output.
- If credential report generation is denied, fall back to per-user enumeration.
