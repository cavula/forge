package forge.plan_test

import data.forge.plan
import rego.v1

base := {
	"cidr_ipv4": "10.0.0.0/8", "cidr_ipv6": null, "encrypted": true,
	"publicly_accessible": false, "storage_encrypted": true, "acl": "private",
	"metadata_options": [{"http_tokens": "required"}], "backup_retention_period": 7,
	"tags": {"owner": "fixture"},
}

cases := [
	["FORGE-001", "aws_vpc_security_group_ingress_rule", "cidr_ipv4", "0.0.0.0/0"],
	["FORGE-002", "aws_ebs_volume", "encrypted", false],
	["FORGE-003", "aws_db_instance", "publicly_accessible", true],
	["FORGE-004", "aws_db_instance", "storage_encrypted", false],
	["FORGE-005", "aws_s3_bucket_acl", "acl", "public-read"],
	["FORGE-006", "aws_instance", "metadata_options", [{"http_tokens": "optional"}]],
	["FORGE-007", "aws_db_instance", "backup_retention_period", 0],
]

resource(kind, after, unknown, actions) := {
	"address": "fixture.example", "mode": "managed",
	"type": kind, "change": {"actions": actions, "after": after, "after_unknown": unknown},
}

document(r) := {"format_version": "1.2", "planned_values": {}, "resource_changes": [r]}
result(kind, after, unknown, actions) := value if {
	value := plan.decision with input as document(resource(kind, after, unknown, actions))
}

test_security_controls[tc[0]] if {
	some tc in cases
	bad := result(tc[1], object.union(base, {tc[2]: tc[3]}), {}, ["create"])
	tc[0] in bad.deny
	not bad.allowed
	good := result(tc[1], base, {}, ["update"])
	good.allowed
}

test_missing_security_fields[tc[0]] if {
	some tc in cases
	actual := result(tc[1], object.remove(base, [tc[2]]), {}, ["create"])
	tc[0] in actual.deny
}

test_unknown_security_fields[tc[0]] if {
	some tc in cases
	actual := result(tc[1], base, {tc[2]: true}, ["create"])
	tc[0] in actual.deny
}

test_wrong_security_field_types[tc[0]] if {
	some tc in cases
	actual := result(tc[1], object.union(base, {tc[2]: {"invalid": true}}), {}, ["create"])
	tc[0] in actual.deny
}

test_nested_unknown_and_unrelated_unknown if {
	a := result("aws_instance", base, {"metadata_options": [{"http_tokens": true}]}, ["create"])
	"FORGE-006" in a.deny
	b := result("aws_instance", base, {"id": true}, ["create"])
	b.allowed
}

test_ipv6_ingress if {
	a := result("aws_vpc_security_group_ingress_rule", object.union(base, {"cidr_ipv6": "::/0"}), {}, ["create"])
	a.deny == ["FORGE-001"]
}

test_invalid_or_world_cidrs[tc] if {
	some tc in [
		["cidr_ipv6", "0:0:0:0:0:0:0:0/0"], ["cidr_ipv6", "2001:db8::1/0"],
		["cidr_ipv4", "192.0.2.1/0"], ["cidr_ipv4", "invalid"],
		["cidr_ipv4", "10.0.0.0/99"], ["cidr_ipv6", "::/129"],
		["cidr_ipv4", "2001:db8::/32"], ["cidr_ipv6", "10.0.0.0/8"],
	]
	a := result("aws_vpc_security_group_ingress_rule", object.union(base, {tc[0]: tc[1]}), {}, ["create"])
	a.deny == ["FORGE-001"]
}

test_malformed_unknown_masks[mask] if {
	some mask in [
		{"encrypted": "unknown"}, {"encrypted": null}, {"encrypted": 1},
		{"metadata_options": [{"http_tokens": "unknown"}]},
	]
	a := result("aws_ebs_volume", base, mask, ["create"])
	a.deny == ["FORGE-PLAN-INVALID"]
	not a.allowed
}

test_replacements_require_approval_and_security if {
	every actions in [["delete", "create"], ["create", "delete"]] {
		a := result("aws_ebs_volume", {"encrypted": false}, {}, actions)
		"FORGE-002" in a.deny
		a.approval == ["FORGE-008"]
		a.requires_approval
	}
}

test_delete_approval_without_after_checks if {
	a := result("aws_ebs_volume", null, {}, ["delete"])
	a.allowed
	a.approval == ["FORGE-008"]
}

test_iam_change_and_noop if {
	a := result("aws_iam_role", {}, {}, ["update"])
	a.allowed
	a.approval == ["FORGE-009"]
	b := result("aws_iam_role", {}, {}, ["no-op"])
	b.approval == []
	not b.requires_approval
}

test_missing_tags_warn_only if {
	a := result("aws_s3_bucket", {}, {}, ["create"])
	a.allowed
	a.warn == ["FORGE-010"]
	b := result("aws_s3_bucket", base, {}, ["create"])
	b.warn == []
}

test_data_read_ignored if {
	r := object.union(resource("aws_db_instance", {}, {}, ["read"]), {"mode": "data"})
	a := plan.decision with input as document(r)
	a == {"allowed": true, "requires_approval": false, "deny": [], "approval": [], "warn": []}
}

test_empty_plan if {
	a := plan.decision with input as {"format_version": "1.0", "planned_values": {}}
	a.allowed
}

test_malformed_plans[input_case] if {
	some input_case in [
		null, [], {}, {"format_version": "2.0", "planned_values": {}},
		{"format_version": "1.0", "resource_changes": []},
		{"format_version": "1.0", "planned_values": {}, "resource_changes": {}},
		document({}), document(resource("aws_instance", [], {}, ["create"])),
		document(resource("aws_instance", {}, true, ["create"])),
		document(resource("aws_instance", {}, {}, ["forget"])),
	]
	a := plan.decision with input as input_case
	a.deny == ["FORGE-PLAN-INVALID"]
	not a.allowed
}

test_result_never_contains_resource_values if {
	secret := "fixture-sensitive-value"
	a := result("aws_iam_role", {"name": secret}, {}, ["delete", "create"])
	not contains(json.marshal(a), secret)
	not contains(json.marshal(a), "fixture.example")
}
