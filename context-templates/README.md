# Context Templates — AWS Security Analyzer

Optional files that tune the scan. Copy into your workspace as `security-context/` and fill in.

- **scan-scope.json** — target accounts, regions, output directory, and thresholds (e.g. `unusedRoleThresholdDays`). Mirrors `.kiro/security-analyzer.json`.
- **exceptions.csv** — resources you've accepted as risk (bucket/SG/role ARN + reason + owner + review date). Findings matching these are marked `PASS (accepted)` in the report instead of FAIL.
- **severity-overrides.md** — org-specific severity bumps (e.g. treat any public S3 bucket as CRITICAL regardless of the catalog default).

All checks are defined in this power's own catalog (see `../steering/checks-catalog.md`). The scan is strictly read-only.
