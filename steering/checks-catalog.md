# Security Checks Catalog

Every check below has a stable check ID owned by this power
(grouped by AWS service domain). Severity: **H**=High, **M**=Medium, **L**=Low.
Evaluate each finding as **PASS / WARN / FAIL** and carry the rule ID + severity into the report.

All discovery calls go through the `aws-mcp` server tools (read-only: `describe*`, `list*`, `get*`).

---

## Trusted Advisor (pull once)

- Use `Support:DescribeTrustedAdvisorChecks` (language=en, global via `us-east-1`), filter to **category = security**.
- `Support:DescribeTrustedAdvisorCheckResult` per security check ID; keep only `status in {warning, error}` (flagged).
- Cache the full result set in run state — do NOT re-poll per finding.
- If Support API is denied (no Business/Enterprise Support), skip and note "TA unavailable" in the report; the direct checks below still cover the same ground.

---

## IAM & credential checks

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 1 | Unused key pairs | `EC2KeyPairNotInUse` | L | List key pairs, cross-ref against running/stopped instances; FAIL any key pair referenced by 0 instances. |
| 2 | Un-rotated access / secret keys | `hasAccessKeyNoRotate30days` (M), `hasAccessKeyNoRotate90days` (H) | M/H | From credential report / `list-access-keys` + `get-access-key-last-used`: WARN >30d since rotation, FAIL >90d. |
| 3 | Over-permissive permissions | `wildcardActionsDetection` (H), `InlinePolicyFullAdminAccess` (H), `ManagedPolicyFullAccessOneServ` (H), `missingPermissionsBoundaries` (M), `missingPolicyConditions` (H) | H | FAIL policies with `Action:"*"` / `Resource:"*"` / full admin; WARN roles/users without permissions boundary. |
| 4 | IAM roles unaccessed 180+ days | `unusedRole` (L), `roleLongSession` (L) | L | `get-role` → `RoleLastUsed.LastUsedDate`; FAIL if null or older than `unusedRoleThresholdDays` (default 180). Also flag `MaxSessionDuration` > 12h. |
| 5 | Inactive IAM users | `userNoActivity90days` (H), `consoleLastAccess365` (H) | H | Credential report: FAIL users with no console/key activity in 90d; escalate at 365d. |
| 6 | MFA not enabled | `mfaActive` (H), `rootMfaActive` (H) | H | FAIL any console-enabled user without MFA; FAIL root without MFA (highest priority). |

---

## EC2 / network checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 7 | IMDSv2 not enforced | `EC2IMDSv2` (H), `ASGIMDSv2` (L) | H | `describe-instances` → `MetadataOptions.HttpTokens`; FAIL if not `required`. Also check launch templates behind ASGs. |
| 8 | Inbound open to 0.0.0.0/0 | `SGAllPortOpenToAll` (H), `SGAllPortOpen` (H) | H | `describe-security-groups`; FAIL any ingress rule with `0.0.0.0/0` or `::/0` on all ports / wide ranges. |
| 9 | SSH port 22 open to world | `SGSensitivePortOpenToAll` (H), `NACLSensitivePort` (H) | H | FAIL ingress allowing tcp/22 (and RDP 3389) from `0.0.0.0/0`; also inspect NACLs. |
| 10 | SSM not enabled | `EC2SSMNotManaged` (M) | M | Cross-ref `describe-instances` against SSM `describe-instance-information`; FAIL instances not registered as managed. |
| 11 | Termination protection off | `EC2NoTerminationProtection` (M) | M | `describe-instance-attribute` `disableApiTermination`; FAIL if `false`. Apply to all in-scope instances. |

---

## S3 checks (global + per bucket)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 12 | Account-level public access block | `S3AccountPublicAccessBlock` (H) | H | `get-public-access-block` at account level; FAIL if all four flags not enabled. |
| 13 | Bucket public access | `PublicAccessBlock` (H), `PublicReadAccessBlock` (H), `PublicWriteAccessBlock` (H) | H | Per bucket public access block + `get-bucket-policy-status`; FAIL any public read/write. |
| 14 | Wildcard bucket policy | `WildcardPrincipalsActions` (H) | H | FAIL bucket policies with `Principal:"*"` + broad actions and no condition. |
| 15 | Encryption at rest | `ServerSideEncrypted` (M), `SSEWithKMS` (M) | M | `get-bucket-encryption`; WARN if unencrypted; note SSE-S3 vs SSE-KMS. |
| 16 | TLS-only enforced | `TlsEnforced` (M) | M | FAIL if no `aws:SecureTransport=false` deny in bucket policy. |
| 17 | Versioning / MFA delete | `BucketVersioning` (L), `MFADelete` (M) | L/M | WARN if versioning suspended; note MFA-delete status. |
| 17a | Versioning enabled requires lifecycle | `BucketVersioning` + `BucketLifecycle` (M) | M | If `get-bucket-versioning` = Enabled, then `get-bucket-lifecycle-configuration` MUST return a rule that expires noncurrent versions (e.g. `NoncurrentVersionExpiration`). FAIL a versioning-enabled bucket with no lifecycle rule managing old versions. |

---


## RDS / data-protection checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 18 | RDS deletion protection off | `DeleteProtection` (H), `DeleteProtectionCluster` (H) | H | `describe-db-instances` / `describe-db-clusters` `DeletionProtection`; FAIL if `false`. Cluster-level applies to Aurora. |
| 19 | RDS publicly accessible | `PubliclyAccessible` (H), `SnapshotRDSIsPublic` (H) | H | FAIL instances with `PubliclyAccessible=true`; FAIL any public DB snapshot. |
| 20 | RDS storage not encrypted | `StorageEncrypted` (M) | M | `describe-db-instances` `StorageEncrypted`; FAIL if `false`. |
| 21 | RDS backups / cross-region | `Backup` (H), `BackupTooLow` (H), `CrossRegionBackupNotEnabled` (H) | H | FAIL if automated backups disabled or retention too low; WARN if no cross-region backup. |
| 22 | RDS secret rotation | `Secret__NoRotation` (M), `DBwithoutSecretManager` (M) | M | WARN DBs whose Secrets Manager secret has no rotation, or not using Secrets Manager at all. |

---

## Detective controls - GuardDuty & CloudTrail

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 23 | GuardDuty enabled + active findings | `Findings` (H), `Settings` (L), `FailMeetingCompliances` (H) | H | `list-detectors` per region; FAIL if no active detector. If enabled, surface open high/critical findings. |
| 24 | CloudTrail enabled | `NeedToEnableCloudTrail` (H), `EnableCloudTrailLogging` (H) | H | `describe-trails` + `get-trail-status`; FAIL if no trail or logging stopped. |
| 25 | Multi-region trail | `HasOneMultiRegionTrail` (H), `OrganizationTrailEnabled` (H) | H | FAIL if no multi-region trail; note org-trail status. |
| 26 | Log file validation | `LogFileValidationEnabled` (L) | L | WARN if `LogFileValidationEnabled=false`. |
| 27 | Trail S3 bucket hardening | `EnableTrailS3BucketLogging` (H), `EnableTrailS3BucketVersioning` (H), `EnableS3PublicAccessBlock` (H) | H | FAIL if the trail's S3 bucket lacks logging/versioning/public-access-block. |
| 28 | GuardDuty / Security Hub integration | `GuardDutyIntegration` (H), `SecurityHubIntegration` (H) | H | Note whether findings flow to Security Hub / GuardDuty. |

---

## KMS checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 29 | Key rotation disabled | `KeyRotationEnabled` (M) | M | `get-key-rotation-status` per CMK; FAIL customer-managed keys with rotation off. |
| 30 | Over-permissive key policy | `KeyPolicyWildcardPrincipal` (H), `KeyPolicyWildcardAction` (H), `GrantWildcardPrincipal` (H), `KeyPolicySensitiveActionsNotRestricted` (H) | H | FAIL key policies/grants with `Principal:"*"` or unrestricted sensitive actions and no conditions. |

---


## Container security - EKS / ECS / ECR (per region)

Container coverage for EKS, ECR, and ECS. These are this power's own checks.

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 31 | EKS public endpoint exposure | `eksEndpointPublicAccess`, `eksPublicEndpointNoCidrRestriction` | H | `describe-cluster`; FAIL if API endpoint is public with no CIDR restriction. |
| 32 | EKS secrets not encrypted (KMS) | `eksSecretsEncryption`, `eksSecretsEncryptionNoKMS` | H | FAIL if envelope encryption of secrets with a KMS key is not configured. |
| 33 | EKS control-plane logging off | `eksClusterLogging`, `eksClusterLoggingIncomplete` | L/H | FAIL/WARN if audit + authenticator control-plane logs are not all enabled. |
| 34 | EKS cluster role least-privilege / IRSA | `eksClusterRoleLeastPrivilege`, `eksNoIRSAConfigured` | H | FAIL over-privileged cluster role; FAIL if IRSA (IAM Roles for Service Accounts) not configured. |
| 35 | EKS SG restriction + version EOL | `eksClusterSGRestriction`, `eksClusterVersionEol` | H | FAIL wide cluster SG; FAIL clusters on end-of-life Kubernetes versions. |
| 36 | ECR image scan on push | `EcrScanOnPush` | H | `describe-repositories`; FAIL repos with `imageScanningConfiguration.scanOnPush=false`. |
| 37 | ECR tag immutability | `EcrTagImmutability` | M | FAIL repos with `imageTagMutability=MUTABLE`. |
| 38 | ECR no wildcard repo policy + lifecycle | `EcrWildcardRepoPolicy`, `EcrLifecyclePolicy`, `EcrEncryptionKms` | H | `get-repository-policy`; FAIL wildcard principal without conditions. WARN missing lifecycle policy / non-KMS encryption. |
| 39 | ECS task def no privileged / hardening | `EcsTaskPrivileged`, `EcsReadonlyRootFilesystem`, `EcsHostNetworkMode` | H | `describe-task-definition`; FAIL privileged containers or host networking; WARN writable root filesystem. |
| 40 | ECS no secrets in env vars | `EcsSecretsInEnv` | H | FAIL task defs passing secrets via plaintext `environment` instead of `secrets` (Secrets Manager/SSM). |
| 41 | ECS container logging | `EcsTaskDefLogging` | L | WARN containers with no `logConfiguration`. |

---


## Account-level foundations & governance

Account-level identity and governance foundations aligned to the AWS Well-Architected Security Pillar and the AWS security-review checklist (root hygiene, password policy, detective services).

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 42 | Root account has access keys | `rootHasAccessKey` | H | Credential report: FAIL if the root user has ANY access key (active or inactive). CRITICAL priority. |
| 43 | Root recent usage / console login | `rootConsoleLogin30days`, `rootConsoleLoginFail3x` | H | FAIL if root was used for daily ops in the last 30d; flag repeated root login failures. |
| 44 | Weak IAM password policy | `passwordPolicy`, `passwordPolicyWeak`, `passwordPolicyReuse`, `passwordPolicyLength` | L | `get-account-password-policy`; FAIL if missing/weak (length < 14, reuse allowed, no complexity). |
| 45 | Inline policies on users | `InlinePolicy`, `InlinePolicyFullAccessOneServ` | L/H | FAIL users/roles with inline policies (prefer managed); escalate if inline grants full service access. |
| 46 | AWS Config not enabled | `EnableConfigService`, `PartialEnableConfigService` | H | FAIL if AWS Config recording is off (or partial) in scanned regions. |
| 47 | Alternate contacts missing | `hasAlternateContact` | H | FAIL if billing/operations/security alternate contacts are not configured. |
| 48 | IAM Access Analyzer disabled | `IamAccessAnalyzerEnabled` | M | `access-analyzer list-analyzers`; WARN if no account/org analyzer active. |

---

## Scoring

- **FAIL** = misconfiguration present (counts toward the risk total, weighted by severity: H=3, M=2, L=1).
- **WARN** = deviation from best practice but lower risk.
- **PASS** = compliant.
- Roll up per-service and overall counts for the report summary (see `steering/report-output.md`).
