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

## Compliance Framework Mappings

Every check in this catalog maps to one or more industry compliance benchmarks. The mapping allows the report to show which frameworks a finding violates. Use the compliance tags in the report output alongside the check ID and severity.

### CIS AWS Foundations Benchmark v3.0

| Check ID(s) | CIS Control | CIS Section |
|-------------|-------------|-------------|
| `rootMfaActive` | Ensure MFA is enabled for the root account | 1.5 |
| `mfaActive` | Ensure MFA is enabled for all IAM users with console access | 1.10 |
| `rootHasAccessKey` | Ensure no root account access key exists | 1.4 |
| `hasAccessKeyNoRotate90days` | Ensure access keys are rotated every 90 days or less | 1.14 |
| `userNoActivity90days` | Ensure credentials unused for 90 days are disabled | 1.12 |
| `passwordPolicy`, `passwordPolicyLength` | Ensure IAM password policy requires minimum length of 14 | 1.8 |
| `passwordPolicyReuse` | Ensure IAM password policy prevents password reuse | 1.9 |
| `wildcardActionsDetection` | Ensure IAM policies that allow full "*:*" administrative privileges are not attached | 1.16 |
| `NeedToEnableCloudTrail`, `EnableCloudTrailLogging` | Ensure CloudTrail is enabled in all regions | 3.1 |
| `HasOneMultiRegionTrail` | Ensure CloudTrail trails are integrated with CloudWatch Logs | 3.4 |
| `LogFileValidationEnabled` | Ensure CloudTrail log file validation is enabled | 3.2 |
| `EnableTrailS3BucketLogging` | Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket | 3.6 |
| `VpcNoFlowLogs` | Ensure VPC Flow Logging is enabled in all VPCs | 3.9 |
| `SGAllPortOpenToAll`, `SGSensitivePortOpenToAll` | Ensure no security groups allow ingress from 0.0.0.0/0 to remote admin ports | 5.2, 5.3 |
| `S3AccountPublicAccessBlock` | Ensure S3 buckets are configured with Block Public Access | 2.1.4 |
| `ServerSideEncrypted` | Ensure S3 bucket server-side encryption is enabled | 2.1.1 |
| `KeyRotationEnabled` | Ensure rotation for customer-managed CMKs is enabled | 3.8 |
| `IamAccessAnalyzerEnabled` | Ensure IAM Access Analyzer is enabled for all regions | 1.20 |
| `DefaultVpcInUse` | Ensure the default security group of every VPC restricts all traffic | 5.4 |
| `EnableConfigService` | Ensure AWS Config is enabled in all regions | 3.5 |
| `rootConsoleLogin30days` | Ensure use of root account is monitored/minimized | 1.7 |
| `EC2IMDSv2` | Ensure EC2 instances use IMDSv2 | 5.6 |
| `StorageEncrypted` | Ensure RDS instances have encryption at rest enabled | 2.3.1 |

### HIPAA (Health Insurance Portability and Accountability Act)

| Check ID(s) | HIPAA Safeguard | Reference |
|-------------|-----------------|-----------|
| `mfaActive`, `rootMfaActive` | Access Control — Unique User Identification + MFA | §164.312(d) |
| `hasAccessKeyNoRotate90days` | Access Control — Automatic Logoff / credential management | §164.312(a)(2)(iii) |
| `userNoActivity90days` | Workforce Security — Termination procedures | §164.308(a)(3)(ii)(C) |
| `ServerSideEncrypted`, `SSEWithKMS`, `StorageEncrypted` | Encryption at rest — ePHI protection | §164.312(a)(2)(iv) |
| `TlsEnforced`, `AlbInsecureTls`, `CloudFrontNoHttpsOnly` | Encryption in transit — ePHI transmission security | §164.312(e)(1) |
| `NeedToEnableCloudTrail`, `EnableCloudTrailLogging` | Audit Controls — information system activity review | §164.312(b) |
| `Findings`, `Settings` | Integrity Controls — mechanism to detect unauthorized alteration | §164.312(c)(2) |
| `PubliclyAccessible`, `SnsTopicPublicAccess`, `SqsQueuePublicAccess` | Access Control — minimum necessary access to ePHI | §164.502(b) |
| `DeleteProtection`, `Backup`, `DynamoDbNoPitr` | Contingency Plan — data backup and disaster recovery | §164.308(a)(7) |
| `VpcNoFlowLogs`, `ElbNoAccessLogs` | Audit Controls — activity logging and monitoring | §164.312(b) |
| `SecretsManagerNoRotation` | Access Control — credential management | §164.312(a)(1) |
| `WafNoRules`, `ApiGwNoAuthorizer` | Access Control — prevent unauthorized access | §164.312(a)(1) |
| `LambdaPublicAccess`, `LambdaFunctionUrlNoAuth` | Access Control — restrict public access to compute | §164.312(a)(1) |

### SOC 2 Type II (Trust Services Criteria)

| Check ID(s) | SOC 2 Criteria | Category |
|-------------|----------------|----------|
| `mfaActive`, `rootMfaActive` | CC6.1 — Logical and physical access controls | Security |
| `hasAccessKeyNoRotate90days` | CC6.2 — Credentials are managed prior to access | Security |
| `userNoActivity90days`, `unusedRole` | CC6.3 — Access is removed when no longer needed | Security |
| `NeedToEnableCloudTrail`, `VpcNoFlowLogs` | CC7.1 — Detection of unauthorized activities | Security |
| `Findings` | CC7.2 — Monitoring of anomalies for incident response | Security |
| `ServerSideEncrypted`, `StorageEncrypted`, `SqsQueueNotEncrypted` | CC6.7 — Restrict access to information assets in transit/rest | Confidentiality |
| `DeleteProtection`, `Backup`, `DynamoDbNoPitr` | A1.2 — Recovery of infrastructure/data | Availability |
| `SGAllPortOpenToAll`, `LambdaPublicAccess` | CC6.6 — Restrict external access | Security |
| `wildcardActionsDetection` | CC6.3 — Least privilege access | Security |
| `CloudFrontNoHttpsOnly`, `TlsEnforced` | CC6.7 — Protection of data in transit | Confidentiality |

### PCI DSS v4.0

| Check ID(s) | PCI DSS Requirement | Section |
|-------------|---------------------|---------|
| `SGAllPortOpenToAll`, `SGSensitivePortOpenToAll` | Restrict inbound/outbound traffic to that which is necessary | 1.3 |
| `CloudFrontNoHttpsOnly`, `TlsEnforced`, `AlbInsecureTls` | Encrypt transmission of cardholder data across open networks | 4.1 |
| `ServerSideEncrypted`, `StorageEncrypted`, `DynamoDbNoCmkEncryption` | Protect stored cardholder data with encryption | 3.5 |
| `mfaActive`, `rootMfaActive` | Multi-factor authentication for access to CDE | 8.3 |
| `hasAccessKeyNoRotate90days` | Passwords/passphrases changed at least once every 90 days | 8.3.9 |
| `NeedToEnableCloudTrail`, `VpcNoFlowLogs`, `ElbNoAccessLogs` | Audit trail — record all access to system components | 10.1, 10.2 |
| `Findings`, `Settings` | Regularly test security systems and processes | 11.4 |
| `WafNoRules`, `ApiGwNoAuthorizer` | Protect web-facing applications | 6.4 |
| `LambdaPublicAccess`, `PubliclyAccessible` | Restrict public access to system components | 1.4 |
| `SecretsManagerNoRotation`, `LambdaEnvSecrets`, `EcsSecretsInEnv` | Do not store sensitive authentication data after authorization | 3.2 |
| `KeyRotationEnabled` | Cryptographic key management procedures | 3.6 |

### AWS Foundational Security Best Practices (FSBP)

| Check ID(s) | FSBP Control | AWS Service |
|-------------|--------------|-------------|
| `EC2IMDSv2` | EC2.8 — IMDSv2 should be configured | EC2 |
| `SGAllPortOpenToAll` | EC2.19 — Security groups should not allow unrestricted ingress | EC2 |
| `S3AccountPublicAccessBlock` | S3.1 — S3 Block Public Access setting should be enabled | S3 |
| `ServerSideEncrypted` | S3.4 — S3 buckets should have server-side encryption enabled | S3 |
| `StorageEncrypted` | RDS.3 — RDS DB instances should have encryption at rest enabled | RDS |
| `DeleteProtection` | RDS.8 — RDS DB instances should have deletion protection enabled | RDS |
| `PubliclyAccessible` | RDS.2 — RDS DB instances should prohibit public access | RDS |
| `KeyRotationEnabled` | KMS.4 — AWS KMS key rotation should be enabled | KMS |
| `NeedToEnableCloudTrail` | CloudTrail.1 — CloudTrail should be enabled | CloudTrail |
| `HasOneMultiRegionTrail` | CloudTrail.5 — CloudTrail trails should be multi-region | CloudTrail |
| `Findings` | GuardDuty.1 — GuardDuty should be enabled | GuardDuty |
| `LambdaPublicAccess` | Lambda.1 — Lambda function policies should prohibit public access | Lambda |
| `LambdaDeprecatedRuntime` | Lambda.2 — Lambda functions should use supported runtimes | Lambda |
| `EcrScanOnPush` | ECR.1 — ECR repositories should have image scanning enabled | ECR |
| `eksEndpointPublicAccess` | EKS.1 — EKS cluster endpoints should not be publicly accessible | EKS |
| `eksSecretsEncryption` | EKS.2 — EKS clusters should use encrypted secrets | EKS |
| `CloudFrontNoHttpsOnly` | CloudFront.3 — CloudFront distributions should require HTTPS | CloudFront |
| `ElbNoAccessLogs` | ELB.5 — Application and Classic LBs logging should be enabled | ELB |
| `AlbInsecureTls` | ELB.8 — Classic LBs with SSL listeners should use a predefined security policy with strong TLS | ELB |
| `OpenSearchPublicAccess` | ES.2 — OpenSearch domains should not be publicly accessible | OpenSearch |
| `OpenSearchNoEncryption` | ES.1 — OpenSearch domains should have encryption at rest enabled | OpenSearch |
| `SqsQueueNotEncrypted` | SQS.1 — SQS queues should be encrypted at rest | SQS |
| `SnsTopicNotEncrypted` | SNS.1 — SNS topics should be encrypted at rest | SNS |
| `DynamoDbNoPitr` | DynamoDB.2 — DynamoDB tables should have PITR enabled | DynamoDB |
| `WafNoLogging` | WAF.1 — AWS WAF Classic global web ACL logging should be enabled | WAF |
| `SecretsManagerNoRotation` | SecretsManager.1 — Secrets Manager secrets should have rotation enabled | Secrets Manager |
| `VpcNoFlowLogs` | EC2.6 — VPC flow logging should be enabled in all VPCs | VPC |
| `IamAccessAnalyzerEnabled` | IAM.8 — IAM Access Analyzer should be enabled | IAM |
| `ComputeOptimizerNotEnabled` | Account.1 — AWS Compute Optimizer should be enabled | Account |

---

## EBS checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 105 | EBS volume not encrypted | `EbsVolumeNotEncrypted` | M | `ec2:DescribeVolumes`; FAIL volumes with `Encrypted=false`. |
| 106 | EBS default encryption disabled | `EbsDefaultEncryptionDisabled` | M | `ec2:GetEbsEncryptionByDefault`; FAIL if account-level default EBS encryption is not enabled in the region. |
| 107 | EBS public snapshot | `EbsSnapshotPublic` | H | `ec2:DescribeSnapshotAttribute` (createVolumePermission); FAIL snapshots shared with `all` (public). |
| 108 | EBS volume not attached (orphaned) | `EbsVolumeOrphaned` | L | `ec2:DescribeVolumes`; WARN volumes with `State=available` (not attached to any instance — potential waste + data exposure). |

---

## EFS checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 109 | EFS not encrypted at rest | `EfsNotEncrypted` | M | `efs:DescribeFileSystems`; FAIL if `Encrypted=false`. |
| 110 | EFS public mount target | `EfsPublicMountTarget` | H | `efs:DescribeMountTargets` → inspect associated security groups; FAIL if SG allows 0.0.0.0/0 on port 2049 (NFS). |
| 111 | EFS no backup policy | `EfsNoBackupPolicy` | L | `efs:DescribeBackupPolicy`; WARN if `Status` ≠ `ENABLED`. |
| 112 | EFS file system policy public access | `EfsPublicPolicy` | H | `efs:DescribeFileSystemPolicy`; FAIL if policy allows `Principal:"*"` without conditions. |

---

## ElastiCache checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 113 | ElastiCache cluster no encryption in transit | `ElastiCacheNoTransitEncryption` | H | `elasticache:DescribeReplicationGroups` / `DescribeCacheClusters`; FAIL if `TransitEncryptionEnabled=false`. |
| 114 | ElastiCache cluster no encryption at rest | `ElastiCacheNoAtRestEncryption` | M | FAIL if `AtRestEncryptionEnabled=false`. |
| 115 | ElastiCache no auth token | `ElastiCacheNoAuth` | H | FAIL Redis replication groups with `AuthTokenEnabled=false` (unauthenticated access). |
| 116 | ElastiCache cluster not in VPC | `ElastiCacheNoVpc` | M | WARN if cache cluster is not associated with a VPC subnet group (legacy EC2-Classic or default placement). |

---

## Redshift checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 117 | Redshift cluster publicly accessible | `RedshiftPublicAccess` | H | `redshift:DescribeClusters`; FAIL if `PubliclyAccessible=true`. |
| 118 | Redshift cluster not encrypted | `RedshiftNotEncrypted` | M | FAIL if `Encrypted=false`. |
| 119 | Redshift audit logging disabled | `RedshiftNoAuditLogging` | M | `redshift:DescribeLoggingStatus`; FAIL if `LoggingEnabled=false`. |
| 120 | Redshift no automated snapshots | `RedshiftNoSnapshots` | M | FAIL if `AutomatedSnapshotRetentionPeriod=0`. |
| 121 | Redshift parameter require SSL | `RedshiftNoRequireSsl` | H | Inspect cluster parameter group for `require_ssl=true`; FAIL if SSL not required. |

---

## SageMaker checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 122 | SageMaker notebook publicly accessible | `SageMakerNotebookPublic` | H | `sagemaker:ListNotebookInstances` → `DescribeNotebookInstance`; FAIL if `DirectInternetAccess=Enabled`. |
| 123 | SageMaker notebook not encrypted | `SageMakerNotebookNotEncrypted` | M | FAIL if `KmsKeyId` is absent (no CMK encryption for notebook storage). |
| 124 | SageMaker notebook root access | `SageMakerNotebookRootAccess` | M | WARN if `RootAccess=Enabled` (elevated privileges in the notebook container). |
| 125 | SageMaker endpoint no VPC | `SageMakerEndpointNoVpc` | M | `sagemaker:DescribeEndpointConfig`; WARN if no VPC config (endpoints accessible only via public API). |

---

## AMI checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 126 | AMI shared publicly | `AmiPublicSharing` | H | `ec2:DescribeImageAttribute` (launchPermission); FAIL any owned AMI shared with `all` (public). Potential data/IP leakage. |
| 127 | AMI not encrypted | `AmiNotEncrypted` | M | `ec2:DescribeImages` (owner=self); WARN AMIs with unencrypted EBS snapshots as block devices. |

---

## Inspector checks (per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 128 | Inspector not enabled | `InspectorNotEnabled` | M | `inspector2:BatchGetAccountStatus`; FAIL if Inspector is not activated for EC2/ECR/Lambda scanning. |
| 129 | Inspector active critical/high findings | `InspectorCriticalFindings` | H | `inspector2:ListFindings` (filter severity=CRITICAL/HIGH, state=ACTIVE); FAIL if active critical/high vulnerability findings exist — report count and top affected resources. |
| 130 | Inspector ECR scan coverage gap | `InspectorEcrCoverageGap` | M | `inspector2:ListCoverageStatistics`; WARN if ECR repository scan coverage < 100% of active repos. |

---

## Security Hub checks (global + per region)

| # | Requirement | Check ID(s) | Sev | How to evaluate |
|---|---|---|---|---|
| 131 | Security Hub not enabled | `SecurityHubNotEnabled` | H | `securityhub:DescribeHub`; FAIL if Security Hub is not enabled in the region. |
| 132 | Security Hub no standards enabled | `SecurityHubNoStandards` | M | `securityhub:GetEnabledStandards`; WARN if no security standards subscriptions (CIS, FSBP, PCI). |
| 133 | Security Hub critical findings unresolved | `SecurityHubCriticalFindings` | H | `securityhub:GetFindings` (filter SeverityLabel=CRITICAL, WorkflowStatus=NEW/NOTIFIED); FAIL if unresolved critical findings exist. |

---

## Compliance Framework Mappings — New Checks

### CIS AWS Foundations Benchmark v3.0

| Check ID(s) | CIS Control | CIS Section |
|-------------|-------------|-------------|
| `EbsVolumeNotEncrypted` | Ensure EBS volume encryption is enabled | 2.2.1 |
| `EbsDefaultEncryptionDisabled` | Ensure EBS default encryption is enabled | 2.2.1 |
| `EbsSnapshotPublic` | Ensure EBS snapshots are not publicly restorable | 2.2.2 |
| `RedshiftPublicAccess` | Ensure Redshift clusters are not publicly accessible | 2.3.2 |

### HIPAA

| Check ID(s) | HIPAA Safeguard | Reference |
|-------------|-----------------|-----------|
| `EbsVolumeNotEncrypted`, `EfsNotEncrypted`, `ElastiCacheNoAtRestEncryption`, `RedshiftNotEncrypted` | Encryption at rest — ePHI protection | §164.312(a)(2)(iv) |
| `ElastiCacheNoTransitEncryption`, `RedshiftNoRequireSsl` | Encryption in transit — ePHI transmission security | §164.312(e)(1) |
| `SageMakerNotebookPublic`, `RedshiftPublicAccess` | Access Control — minimum necessary access | §164.502(b) |
| `InspectorNotEnabled` | Security Management — vulnerability management | §164.308(a)(1) |

### SOC 2

| Check ID(s) | SOC 2 Criteria | Category |
|-------------|----------------|----------|
| `EbsSnapshotPublic`, `AmiPublicSharing`, `EfsPublicPolicy` | CC6.6 — Restrict external access | Security |
| `EbsVolumeNotEncrypted`, `EfsNotEncrypted`, `RedshiftNotEncrypted` | CC6.7 — Restrict access to information assets at rest | Confidentiality |
| `InspectorCriticalFindings` | CC7.1 — Detection of vulnerabilities | Security |
| `SecurityHubNotEnabled` | CC7.2 — Monitoring for incident response | Security |

### PCI DSS v4.0

| Check ID(s) | PCI DSS Requirement | Section |
|-------------|---------------------|---------|
| `EbsVolumeNotEncrypted`, `EfsNotEncrypted`, `RedshiftNotEncrypted`, `ElastiCacheNoAtRestEncryption` | Protect stored cardholder data with encryption | 3.5 |
| `ElastiCacheNoTransitEncryption`, `RedshiftNoRequireSsl` | Encrypt transmission of cardholder data | 4.1 |
| `InspectorNotEnabled`, `InspectorCriticalFindings` | Regularly test security systems | 11.3 |
| `SecurityHubNotEnabled` | Centralized security monitoring | 10.7 |

### AWS FSBP

| Check ID(s) | FSBP Control | AWS Service |
|-------------|--------------|-------------|
| `EbsVolumeNotEncrypted` | EC2.3 — EBS volumes should be encrypted | EC2/EBS |
| `EbsSnapshotPublic` | EC2.1 — EBS snapshots should not be public | EC2/EBS |
| `EbsDefaultEncryptionDisabled` | EC2.7 — EBS default encryption should be enabled | EC2/EBS |
| `EfsNotEncrypted` | EFS.1 — EFS should be configured to encrypt data at rest | EFS |
| `ElastiCacheNoTransitEncryption` | ElastiCache.1 — ElastiCache clusters should have encryption in transit | ElastiCache |
| `ElastiCacheNoAtRestEncryption` | ElastiCache.2 — ElastiCache clusters should have encryption at rest | ElastiCache |
| `RedshiftPublicAccess` | Redshift.1 — Redshift clusters should prohibit public access | Redshift |
| `RedshiftNotEncrypted` | Redshift.10 — Redshift clusters should be encrypted at rest | Redshift |
| `RedshiftNoAuditLogging` | Redshift.4 — Redshift clusters should have audit logging enabled | Redshift |
| `SageMakerNotebookPublic` | SageMaker.1 — SageMaker notebook instances should not have direct internet access | SageMaker |
| `SageMakerNotebookNotEncrypted` | SageMaker.2 — SageMaker notebook instances should be encrypted | SageMaker |
| `InspectorNotEnabled` | Inspector.1 — Amazon Inspector should be enabled | Inspector |
| `SecurityHubNotEnabled` | SecurityHub.1 — Security Hub should be enabled | Security Hub |
| `AmiPublicSharing` | EC2.2 — AMIs should not be publicly shared | EC2 |

---

## Scoring

- **FAIL** = misconfiguration present (counts toward the risk total, weighted by severity: H=3, M=2, L=1).
- **WARN** = deviation from best practice but lower risk.
- **PASS** = compliant.
- Roll up per-service and overall counts for the report summary (see `steering/report-output.md`).
