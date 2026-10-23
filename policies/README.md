# Starter plan policies (WP-1.9)

Run `opa test policies -v` and `opa test policies --coverage --format=json` with
OPA 1.21.3 (Rego v1); evaluate `data.forge.plan.decision`. Input is a native
OpenTofu/Terraform `show -json` plan with format version 1.x, planned_values object
and optional resource_changes array. Each change needs address, mode, type,
actions, object/null after and optional object after_unknown. Supported actions:
create, update, delete, replacements, no-op and read. Invalid shape/format denies.
`make tools` installs the pinned CLI and verifies the release checksum;
`make lint test` enforces strict compilation and at least 70% Rego coverage.

| ID | Rule | Outcome |
| --- | --- | --- |
| FORGE-001 | World IPv4/IPv6 on aws_vpc_security_group_ingress_rule | Deny |
| FORGE-002 | aws_ebs_volume must set encrypted=true | Deny |
| FORGE-003 | aws_db_instance must set publicly_accessible=false | Deny |
| FORGE-004 | aws_db_instance must set storage_encrypted=true | Deny |
| FORGE-005 | aws_s3_bucket_acl must use a listed non-public canned ACL | Deny |
| FORGE-006 | aws_instance metadata_options must require IMDSv2 | Deny |
| FORGE-007 | aws_db_instance backup_retention_period must be at least 1 | Deny |
| FORGE-008 | Managed resource deletion/replacement | Human approval |
| FORGE-009 | Create/update of aws_iam_* | Human approval |
| FORGE-010 | Missing/empty/unknown tags on volume, DB, instance, bucket | Warn |

After-value controls inspect changed managed resources; data, no-op and pure
delete changes skip them. Missing or unknown security fields deny; unrelated
computed fields do not. Deny overrides approval/warnings. Results contain sorted
IDs only; passing policy never authorizes apply. IAM deletion requires approval
through FORGE-008. The run workflow must enforce the human approval gate.
CIDRs are checked semantically, including expanded IPv6 forms; malformed nested
unknown masks deny the plan instead of treating security fields as known.

Coverage is deliberately scoped to the listed resource schemas. It does not
normalize inline security groups, JSON IAM documents, S3 bucket policies, every
cloud/provider or unchanged existing resources. These controls cannot establish
complete infrastructure security. Saved-plan binding and embedded Go evaluation
with failure/resource-limit handling are subsequent integration work, required
before WP-1.9 is complete. See ADR0012 and OPA's
[Terraform integration](https://www.openpolicyagent.org/docs/terraform) and
[policy testing](https://www.openpolicyagent.org/docs/policy-testing) references.
