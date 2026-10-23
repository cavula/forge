package forge.plan

import rego.v1

actions := {["no-op"], ["read"], ["create"], ["update"], ["delete"], ["delete", "create"], ["create", "delete"]}

valid_plan if {
	is_object(input)
	regex.match(`^1\.[0-9]+$`, input.format_version)
	is_object(input.planned_values)
	is_array(object.get(input, "resource_changes", []))
	every r in object.get(input, "resource_changes", []) { valid_change(r) }
}

valid_change(r) if {
	is_object(r)
	is_string(r.address)
	r.address != ""
	r.mode in {"managed", "data"}
	is_string(r.type)
	r.type != ""
	is_object(r.change)
	r.change.actions in actions
	is_object(object.get(r.change, "after_unknown", {}))
	not invalid_unknown(object.get(r.change, "after_unknown", {}))
	valid_after(r)
}

invalid_unknown(mask) if {
	walk(mask, [_, value])
	not is_boolean(value)
	not is_object(value)
	not is_array(value)
}

valid_after(r) if is_object(object.get(r.change, "after", null))

valid_after(r) if {
	object.get(r.change, "after", null) == null
	not active(r)
}

active(r) if {
	r.mode == "managed"
	some a in r.change.actions
	a in {"create", "update"}
}

unknown(r, key) if {
	walk(object.get(object.get(r.change, "after_unknown", {}), key, false), [_, true])
}

known(r, key) := value if {
	not unknown(r, key)
	value := r.change.after[key]
}

safe(r, "FORGE-001") if {
	safe_cidr(known(r, "cidr_ipv4"), "0.0.0.0/0")
	safe_cidr(known(r, "cidr_ipv6"), "::/0")
}

safe_cidr(value, _) if value == null

safe_cidr(value, blocked) if {
	is_string(value)
	net.cidr_is_valid(value)
	net.cidr_contains(blocked, value)
	not net.cidr_contains(value, blocked)
}

safe(r, "FORGE-002") if known(r, "encrypted") == true
safe(r, "FORGE-003") if known(r, "publicly_accessible") == false
safe(r, "FORGE-004") if known(r, "storage_encrypted") == true
safe(r, "FORGE-005") if known(r, "acl") in {"private", "log-delivery-write", "bucket-owner-read", "bucket-owner-full-control"}

safe(r, "FORGE-006") if {
	options := known(r, "metadata_options")
	is_array(options)
	count(options) == 1
	options[0].http_tokens == "required"
}

safe(r, "FORGE-007") if {
	days := known(r, "backup_retention_period")
	is_number(days)
	days >= 1
}

controls := {
	"FORGE-001": "aws_vpc_security_group_ingress_rule",
	"FORGE-002": "aws_ebs_volume", "FORGE-003": "aws_db_instance",
	"FORGE-004": "aws_db_instance", "FORGE-005": "aws_s3_bucket_acl",
	"FORGE-006": "aws_instance", "FORGE-007": "aws_db_instance",
}

deny contains "FORGE-PLAN-INVALID" if not valid_plan

deny contains id if {
	valid_plan
	some r in object.get(input, "resource_changes", [])
	active(r)
	some id, resource_type in controls
	r.type == resource_type
	not safe(r, id)
}

approval contains "FORGE-008" if {
	valid_plan
	some r in object.get(input, "resource_changes", [])
	r.mode == "managed"
	"delete" in r.change.actions
}

approval contains "FORGE-009" if {
	valid_plan
	some r in object.get(input, "resource_changes", [])
	active(r)
	startswith(r.type, "aws_iam_")
}

warn contains "FORGE-010" if {
	valid_plan
	some r in object.get(input, "resource_changes", [])
	active(r)
	r.type in {"aws_ebs_volume", "aws_db_instance", "aws_instance", "aws_s3_bucket"}
	not tagged(r)
}

tagged(r) if {
	tags := known(r, "tags")
	is_object(tags)
	count(tags) > 0
}

decision := {
	"deny": sort(deny), "warn": sort(warn), "approval": sort(approval),
	"allowed": count(deny) == 0, "requires_approval": count(approval) > 0,
}
