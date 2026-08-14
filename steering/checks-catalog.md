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

## Lambda checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 53 | Lambda function public access | `LambdaPublicAccess` | H | `get-policy` per function; FAIL if resource-based policy grants invoke to `Principal:"*"` without conditions. |
| 54 | Lambda using deprecated runtime | `LambdaDeprecatedRuntime` | H | `list-functions` → `Runtime`; FAIL functions on EOL/deprecated runtimes (e.g. python3.7, nodejs14.x, dotnetcore3.1). |
| 55 | Lambda no VPC configured | `LambdaNoVpc` | L | WARN functions with no VPC configuration (acceptable for many use cases; flag for data-processing functions). |
| 56 | Lambda env vars with secrets | `LambdaEnvSecrets` | H | Inspect `Environment.Variables` keys/values for patterns like `PASSWORD`, `SECRET`, `API_KEY`, `TOKEN`; FAIL if plaintext secrets detected (should use Secrets Manager / SSM Parameter Store). |
| 57 | Lambda reserved concurrency not set | `LambdaNoReservedConcurrency` | L | WARN functions without `ReservedConcurrentExecutions` set — risk of noisy-neighbor throttling. |
| 58 | Lambda function URL auth | `LambdaFunctionUrlNoAuth` | H | `list-function-url-configs`; FAIL if `AuthType=NONE` (unauthenticated public endpoint). |
| 59 | Lambda code signing not configured | `LambdaNoCodeSigning` | M | WARN functions without a code-signing configuration (allows unsigned deployments). |
| 60 | Lambda tracing disabled | `LambdaTracingDisabled` | L | WARN if `TracingConfig.Mode` ≠ `Active` (X-Ray tracing not enabled). |

---

## API Gateway checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 61 | API Gateway no authorization | `ApiGwNoAuthorizer` | H | REST APIs: `get-resources` + `get-method`; FAIL methods with `authorizationType=NONE` on non-OPTIONS methods. HTTP APIs: `get-routes`; FAIL routes with no authorizer. |
| 62 | API Gateway no WAF association | `ApiGwNoWaf` | M | `wafv2:GetWebACLForResource` on stage ARN; WARN if no Web ACL attached. |
| 63 | API Gateway logging disabled | `ApiGwLoggingDisabled` | M | `get-stage`; FAIL if `accessLogSettings` is absent or `methodSettings` lack `loggingLevel` data/error. |
| 64 | API Gateway no throttling | `ApiGwNoThrottling` | M | WARN if stage/method default throttle limits are not explicitly configured (uses account-level defaults). |
| 65 | API Gateway mutual TLS disabled | `ApiGwNoMtls` | L | For custom domains; WARN if `mutualTlsAuthentication` is not configured. |
| 66 | API Gateway no client certificate | `ApiGwNoClientCert` | L | REST API stages; WARN if no `clientCertificateId` for backend TLS verification. |
| 67 | API Gateway REST API endpoint type | `ApiGwEdgeEndpoint` | L | WARN if REST API uses EDGE endpoint (prefer REGIONAL/PRIVATE for lower attack surface). |

---

## SNS checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 68 | SNS topic public access | `SnsTopicPublicAccess` | H | `get-topic-attributes`; FAIL if policy allows `Principal:"*"` publish/subscribe without conditions. |
| 69 | SNS topic not encrypted | `SnsTopicNotEncrypted` | M | WARN if `KmsMasterKeyId` is absent (server-side encryption disabled). |
| 70 | SNS no delivery logging | `SnsNoDeliveryLogging` | L | WARN if no delivery status logging configured for any protocol. |

---

## SQS checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 71 | SQS queue public access | `SqsQueuePublicAccess` | H | `get-queue-attributes`; FAIL if policy allows `Principal:"*"` send/receive without conditions. |
| 72 | SQS queue not encrypted | `SqsQueueNotEncrypted` | M | FAIL if neither `SqsManagedSseEnabled` nor `KmsMasterKeyId` is set. |
| 73 | SQS dead-letter queue not configured | `SqsNoDlq` | L | WARN if `RedrivePolicy` is absent (messages can be lost on failure). |

---

## DynamoDB checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 74 | DynamoDB table not encrypted with CMK | `DynamoDbNoCmkEncryption` | L | `describe-table`; WARN if `SSEDescription.SSEType` ≠ `KMS` (DEFAULT uses AWS-owned key — acceptable but less control). |
| 75 | DynamoDB PITR not enabled | `DynamoDbNoPitr` | M | `describe-continuous-backups`; FAIL if `PointInTimeRecoveryStatus` ≠ `ENABLED`. |
| 76 | DynamoDB deletion protection off | `DynamoDbNoDeletionProtection` | M | `describe-table`; FAIL if `DeletionProtectionEnabled` = `false`. |
| 77 | DynamoDB table no auto-scaling | `DynamoDbNoAutoScaling` | L | For provisioned tables, WARN if no auto-scaling policies registered (risk of throttling or over-provisioning). |

---

## CloudFront checks (global)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 78 | CloudFront no HTTPS-only | `CloudFrontNoHttpsOnly` | H | `list-distributions` + `get-distribution`; FAIL if `ViewerProtocolPolicy` = `allow-all` on any cache behavior. |
| 79 | CloudFront no WAF | `CloudFrontNoWaf` | M | FAIL if `WebACLId` / `WebACLArn` is empty. |
| 80 | CloudFront default certificate | `CloudFrontDefaultCert` | M | WARN if using the default `*.cloudfront.net` certificate instead of a custom SSL cert. |
| 81 | CloudFront access logging disabled | `CloudFrontNoLogging` | L | WARN if `Logging.Enabled` = `false`. |
| 82 | CloudFront origin not using OAC/OAI | `CloudFrontNoOac` | H | For S3 origins, FAIL if no Origin Access Control (OAC) or legacy OAI is configured (bucket is directly accessible). |
| 83 | CloudFront TLS minimum version | `CloudFrontOldTls` | M | WARN if `MinimumProtocolVersion` < `TLSv1.2_2021`. |
| 84 | CloudFront geo-restriction not set | `CloudFrontNoGeoRestriction` | L | WARN if `GeoRestriction.RestrictionType` = `none` (informational). |

---

## ELB / ALB / NLB checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 85 | ALB/NLB access logging disabled | `ElbNoAccessLogs` | M | `describe-load-balancer-attributes`; FAIL if `access_logs.s3.enabled` = `false`. |
| 86 | ALB no WAF associated | `AlbNoWaf` | M | `wafv2:GetWebACLForResource` on ALB ARN; WARN if no Web ACL. |
| 87 | ALB/NLB deletion protection off | `ElbNoDeletionProtection` | M | FAIL if `deletion_protection.enabled` = `false`. |
| 88 | ALB using insecure cipher/TLS | `AlbInsecureTls` | H | `describe-listeners` + `describe-ssl-policies`; FAIL listeners on policies older than `ELBSecurityPolicy-TLS13-1-2-2021-06` or equivalent. |
| 89 | ALB HTTP listener without redirect | `AlbHttpNoRedirect` | M | FAIL HTTP (port 80) listeners that don't have a redirect action to HTTPS. |
| 90 | Classic LB in use | `ClassicLbInUse` | L | WARN any classic ELB (recommend migration to ALB/NLB). |
| 91 | NLB cross-zone disabled | `NlbNoCrossZone` | L | WARN if cross-zone load balancing is not enabled. |

---

## Secrets Manager checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 92 | Secret not rotated | `SecretsManagerNoRotation` | M | `list-secrets` → `RotationEnabled`; FAIL if rotation not configured or `LastRotatedDate` > 90d. |
| 93 | Secret not encrypted with CMK | `SecretsManagerNoCmk` | L | WARN if `KmsKeyId` is absent or uses default `aws/secretsmanager` key (less control). |
| 94 | Secret unused / stale | `SecretsManagerStaleSecret` | L | WARN if `LastAccessedDate` > 90d (potential orphaned secret). |

---

## WAF checks (per region + global)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 95 | WAF Web ACL no rules | `WafNoRules` | H | `get-web-acl`; FAIL if `Rules` array is empty (ACL exists but blocks nothing). |
| 96 | WAF logging disabled | `WafNoLogging` | M | `get-logging-configuration`; FAIL if no logging destination configured. |
| 97 | WAF no rate-based rules | `WafNoRateLimit` | M | WARN if no rate-based rule present in the Web ACL (no DDoS/brute-force mitigation). |

---

## VPC & Networking checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 98 | VPC flow logs disabled | `VpcNoFlowLogs` | M | `describe-flow-logs` per VPC; FAIL if no flow log configured. |
| 99 | Default VPC in use | `DefaultVpcInUse` | L | WARN if the default VPC has any running resources (ENIs attached). |
| 100 | VPC endpoint not used for S3/DynamoDB | `VpcNoGatewayEndpoint` | L | WARN VPCs without gateway endpoints for S3/DynamoDB (traffic traverses internet). |

---

## Elasticsearch / OpenSearch checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 101 | OpenSearch domain publicly accessible | `OpenSearchPublicAccess` | H | `describe-domain`; FAIL if no VPC endpoint configured or access policy allows `Principal:"*"`. |
| 102 | OpenSearch encryption at rest | `OpenSearchNoEncryption` | M | FAIL if `EncryptionAtRestOptions.Enabled` = `false`. |
| 103 | OpenSearch node-to-node encryption | `OpenSearchNoNodeEncryption` | M | FAIL if `NodeToNodeEncryptionOptions.Enabled` = `false`. |
| 104 | OpenSearch audit logging | `OpenSearchNoAuditLogs` | L | WARN if audit logs not published to CloudWatch. |

---

## IAM Access Analyzer — External Access (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 49 | External access findings present | `IamAccessAnalyzerExternalFindings` | H | `accessanalyzer:ListFindings` (filter `analyzerArn` for ACCOUNT/ORG type, `status=ACTIVE`, `resourceType` not filtered). FAIL if any active external-access findings exist — each finding becomes a separate FAIL entry with the resource ARN and principal. |
| 50 | Unused access findings present | `IamAccessAnalyzerUnusedAccess` | M | If an UNUSED_ACCESS analyzer exists, `ListFindings` with `status=ACTIVE`. WARN for each active unused-access finding (unused role, unused permission, unused access key). |

---

## Compute Optimizer (global)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 51 | Compute Optimizer not enabled | `ComputeOptimizerNotEnabled` | M | `compute-optimizer:GetEnrollmentStatus`; FAIL if `status` ≠ `Active`. Note: requires `compute-optimizer:GetEnrollmentStatus` permission. If denied, mark as "unavailable" and continue. |
| 52 | Compute Optimizer over-provisioned resources | `ComputeOptimizerOverProvisioned` | L | If enrolled, call `GetEC2InstanceRecommendations` (and optionally `GetAutoScalingGroupRecommendations`). WARN for any resource with finding = `OVER_PROVISIONED`. Report the instance ID and recommended instance type. |

---

## Scoring

- **FAIL** = misconfiguration present (counts toward the risk total, weighted by severity: H=3, M=2, L=1).
- **WARN** = deviation from best practice but lower risk.
- **PASS** = compliant.
- Roll up per-service and overall counts for the report summary (see `steering/report-output.md`).
