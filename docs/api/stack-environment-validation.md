# Stack environment validation

The private `internal/stacks.normalizeEnvironment` helper implements ADR0018's
non-secret environment rules against generated `forge.v1.StackEnvironmentVariable`
messages. It accepts at most 64 entries, rejects nil entries, and returns newly
allocated messages sorted by exact case-sensitive name. Input slices and messages
are never mutated, including when validation fails. Empty collections clear the
list; empty values are valid. Protobuf unknown fields have no environment meaning
and are not copied into the current-schema result.

Names must match `[A-Za-z_][A-Za-z0-9_]{0,63}` and be unique case-sensitively.
Values must be valid UTF-8, contain no Unicode control characters, and fit in
4096 UTF-8 bytes each. Names and values together must fit in 16 KiB. ADR0018's
global surrounding-whitespace rule applies to values: reject surrounding Unicode
whitespace without trimming or rewriting it. Interior spaces and non-control
Unicode whitespace remain valid. Limits count bytes, not characters.

Reserved runner/process/tool prefixes, exact names, cloud prefixes with their
eight explicit exceptions, and secret suffixes follow ADR0018 case-insensitively.
This includes lowercase proxy aliases and tool-loader names. `TF_LOG` reserves
the entire prefix; cloud exceptions allow only the exact exception name.
Ordinary custom names and `TF_VAR_` names remain valid unless another rule rejects
them. See [the approved policy](../adr/0018-stack-crud-contracts.md#validation-and-non-secret-boundary)
for the complete list.

Every rejection returns only `invalid environment_variables`, with no supplied
names, values, indices or protobuf diagnostics. The helper performs no logging,
network, filesystem, shell or credential access. These values are visible to
organization readers; name checks cannot prove arbitrary text contains no
secrets. Secret variables require WP-1.8's separate write-only interface.
Configuration values must never enter logs, audit payloads or AI requests.

Tests cover protected aliases and case variants, every cloud exception, secret
suffixes, name/value byte limits, aggregate size, duplicates, ordering, copied
inputs, unknown-field handling and fixed diagnostics. This validation slice adds
no RPC handler, persistence, runner environment construction or execution path;
WP-1.2 still requires authenticated CRUD acceptance and hosted CI.
