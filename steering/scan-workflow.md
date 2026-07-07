# Scan Workflow

Load scope from `.kiro/security-analyzer.json`. All calls go through the `aws-mcp` server tools (read-only). Discover exact operation names before first use in a session.

## Phase 0 — Identity & scope
1. `aws sts get-caller-identity` → confirm account ID with the user.
2. Read `regions`, `outputDir`, `unusedRoleThresholdDays` from state. If missing, ask.
3. If `security-context/exceptions.csv` exists in the workspace, load it into run state as the accepted-risk list (columns: `resource_arn,check_id,reason,owner,review_date`). If absent, proceed with an empty list.

## Phase 1 — Trusted Advisor (once)
1. `Support:DescribeTrustedAdvisorChecks` (en) → filter category = security.
2. For each security check, `DescribeTrustedAdvisorCheckResult`; keep flagged (`warning`/`error`).
3. Store the full flagged set in run state. If Support API denied → mark `trustedAdvisor: "unavailable"` and continue.

## Phase 2 — IAM (global)
1. Generate/read the IAM credential report (`GenerateCredentialReport` → `GetCredentialReport`); fall back to per-user `list-access-keys` + `get-access-key-last-used` if denied.
2. Run catalog checks 1–6: unused key pairs, key rotation (30/90d), wildcard/full-admin policies + permissions boundaries, unused roles (≥180d), inactive users (90/365d), MFA (users + root).
3. Run account-foundation checks 42-48: root access keys / root usage, password policy, inline policies, AWS Config enabled, alternate contacts, IAM Access Analyzer.

## Phase 3 — EC2 / network (per region)
For EACH region in scope:
1. `describe-instances`, `describe-security-groups`, `describe-network-acls`.
2. SSM `describe-instance-information`; `describe-instance-attribute` for termination protection.
3. Run catalog checks 7–11: IMDSv2, 0.0.0.0/0 ingress, SSH-22/RDP-3389 exposure, SSM-managed, termination protection.

## Phase 4 — S3 (global + per bucket)
1. Account-level `get-public-access-block`.
2. `list-buckets`; per bucket: public access block, policy status, encryption, bucket policy (wildcard + TLS), versioning/MFA-delete.
3. Run catalog checks 12–17.

## Phase 5 - RDS / data protection (per region)
For EACH region in scope:
1. `describe-db-instances`, `describe-db-clusters`, `describe-db-snapshots`.
2. Run catalog checks 18-22: deletion protection (instance + cluster), public accessibility, storage encryption, backups/cross-region, secret rotation.

## Phase 6 - Detective controls (per region + global)
1. GuardDuty `list-detectors` / `get-detector` per region; surface open high/critical findings.
2. CloudTrail `describe-trails` + `get-trail-status`; inspect multi-region, log-file validation, and the trail's S3 bucket hardening.
3. Run catalog checks 23-28.

## Phase 7 - KMS (per region)
1. `list-keys` -> `describe-key` (customer-managed only), `get-key-rotation-status`, `get-key-policy`.
2. Run catalog checks 29-30: rotation, over-permissive policy/grants.

## Phase 8 - Container security (per region)
1. EKS: `list-clusters` -> `describe-cluster` (endpoint access, secrets encryption, logging, cluster role, version). Run catalog checks 31-35.
2. ECR: `describe-repositories` + `get-repository-policy` (scan-on-push, tag immutability, wildcard policy). Run catalog checks 36-38.
3. ECS: `list-task-definitions` -> `describe-task-definition` and `describe-services` (privileged/host mode, plaintext secrets, public IP). Run catalog checks 39-41.

## Phase 9 - Consolidate
1. Score every finding PASS/WARN/FAIL with check ID + severity.
2. **Apply accepted-risk exceptions**: for each FAIL, if a row in the exceptions list matches on BOTH `check_id` AND `resource_arn` (exact, or the resource identifier is contained in the ARN), downgrade its status to `PASS (accepted)` and attach the row's `reason` + `owner`. An expired `review_date` (before today) does NOT auto-suppress — keep it as FAIL and add an `exceptionExpired` note so stale acceptances resurface.
3. Recompute the summary so `PASS (accepted)` findings are excluded from the risk score (see `steering/report-output.md`).
4. Hand off to `steering/report-output.md` to write JSON + HTML to `outputDir`.

## Hygiene
- Page through ALL results before scoring (don't stop at the first page).
- Surface a one-line progress note per phase to the user.
- Never mutate anything — this is a read-only posture scan.
