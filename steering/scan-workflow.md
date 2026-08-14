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

## Phase 9 — Lambda (per region)
For EACH region in scope:
1. `lambda:ListFunctions` (page through all); for each function: `get-function`, `get-policy` (resource-based policy), `list-function-url-configs`.
2. Inspect runtime, VPC config, environment variables, tracing, code-signing config, reserved concurrency.
3. Run catalog checks 53–60: public access, deprecated runtime, no VPC, env secrets, reserved concurrency, function URL auth, code signing, tracing.

## Phase 10 — API Gateway (per region)
For EACH region in scope:
1. REST APIs: `get-rest-apis` → `get-resources` → `get-method`; inspect authorizer, stage settings.
2. HTTP APIs: `get-apis` → `get-routes` → `get-stages`; inspect authorization, logging.
3. `wafv2:GetWebACLForResource` on stage ARNs.
4. Run catalog checks 61–67: no authorizer, no WAF, logging disabled, no throttling, mutual TLS, client cert, edge endpoint.

## Phase 11 — SNS / SQS (per region)
For EACH region in scope:
1. SNS: `list-topics` → `get-topic-attributes` (policy, encryption, delivery logging).
2. SQS: `list-queues` → `get-queue-attributes` (policy, encryption, DLQ).
3. Run catalog checks 68–73: public access, encryption, delivery logging, DLQ.

## Phase 12 — DynamoDB (per region)
For EACH region in scope:
1. `list-tables` → `describe-table`, `describe-continuous-backups`.
2. Check encryption type, PITR, deletion protection, auto-scaling policies.
3. Run catalog checks 74–77.

## Phase 13 — CloudFront (global)
1. `list-distributions` → `get-distribution` per distribution.
2. Inspect viewer protocol, WAF, certificate, logging, origin access, TLS version, geo-restriction.
3. Run catalog checks 78–84.

## Phase 14 — ELB / ALB / NLB (per region)
For EACH region in scope:
1. `describe-load-balancers` (v2: ALB/NLB), `describe-load-balancers` (classic).
2. `describe-load-balancer-attributes`, `describe-listeners`, `describe-ssl-policies`.
3. `wafv2:GetWebACLForResource` on ALB ARNs.
4. Run catalog checks 85–91: access logs, WAF, deletion protection, TLS policy, HTTP redirect, classic LB, cross-zone.

## Phase 15 — Secrets Manager (per region)
For EACH region in scope:
1. `list-secrets` (page through all); inspect rotation config, KMS key, last accessed date.
2. Run catalog checks 92–94: no rotation, no CMK, stale secrets.

## Phase 16 — WAF (per region + global CloudFront scope)
1. `wafv2:ListWebACLs` (REGIONAL scope per region, CLOUDFRONT scope in us-east-1).
2. Per ACL: `get-web-acl` (rules count, rate-based rules), `get-logging-configuration`.
3. Run catalog checks 95–97: no rules, no logging, no rate-limit.

## Phase 17 — VPC & Networking (per region)
For EACH region in scope:
1. `describe-vpcs`, `describe-flow-logs`, `describe-vpc-endpoints`.
2. Check for flow logs per VPC, default VPC usage (ENIs attached), gateway endpoints.
3. Run catalog checks 98–100.

## Phase 18 — OpenSearch (per region)
For EACH region in scope:
1. `es:ListDomainNames` → `es:DescribeDomain` per domain.
2. Inspect VPC config, access policy, encryption at rest, node-to-node encryption, audit logs.
3. Run catalog checks 101–104.

## Phase 19 — IAM Access Analyzer External Access (per region)
For EACH region in scope:
1. `accessanalyzer:ListAnalyzers` — identify ACCOUNT and ORGANIZATION-level analyzers; also check for UNUSED_ACCESS type analyzers.
2. For each active analyzer, `accessanalyzer:ListFindings` with filter `status=ACTIVE`.
3. Run catalog checks 49–50: external-access findings (FAIL per active finding), unused-access findings (WARN per active finding).
4. If no analyzer exists, check 48 already flags it — skip findings retrieval for that region.

## Phase 20 — Compute Optimizer (global)
1. `compute-optimizer:GetEnrollmentStatus` — confirm whether Compute Optimizer is active for the account. If denied, mark `computeOptimizer: "unavailable"` and continue.
2. If enrolled (`status=Active`), call `compute-optimizer:GetEC2InstanceRecommendations` (page through results); optionally `GetAutoScalingGroupRecommendations`.
3. Run catalog checks 51–52: enrollment status (FAIL if not active), over-provisioned resources (WARN per resource with `OVER_PROVISIONED` finding).

## Phase 21 - Consolidate
1. Score every finding PASS/WARN/FAIL with check ID + severity.
2. **Validate resource identifiers**: For every finding, ensure `resourceArn`, `resourceName`, and `resourceId` are populated. Construct ARNs where APIs only return IDs (e.g., `arn:aws:ec2:<region>:<accountId>:security-group/<sg-id>`). Resolve Name tags where available.
3. **Map compliance frameworks**: for each finding, look up the check ID in `steering/checks-catalog.md` § "Compliance Framework Mappings" and attach all matching framework references (CIS, HIPAA, SOC2, PCI DSS, FSBP).
4. **Compute compliance posture**: calculate per-framework pass rates (total mapped controls that are PASS / total mapped controls).
5. **Apply accepted-risk exceptions**: for each FAIL, if a row in the exceptions list matches on BOTH `check_id` AND `resource_arn` (exact, or the resource identifier is contained in the ARN), downgrade its status to `PASS (accepted)` and attach the row's `reason` + `owner`. An expired `review_date` (before today) does NOT auto-suppress — keep it as FAIL and add an `exceptionExpired` note so stale acceptances resurface.
6. Recompute the summary so `PASS (accepted)` findings are excluded from the risk score (see `steering/report-output.md`).
7. Hand off to `steering/report-output.md` to write Markdown + HTML to `outputDir`.

## Hygiene
- Page through ALL results before scoring (don't stop at the first page).
- Surface a one-line progress note per phase to the user.
- Never mutate anything — this is a read-only posture scan.
