# Stack name, branch and engine-version validation

ADR0018's private metadata validators accept bounded configuration text before
later stack CRUD storage. Every failure returns only `invalid name`,
`invalid branch` or `invalid engine_version`. They do not log or echo input,
invoke Git or other commands, access files, resolve hosts or fetch repositories.

Names require 1–100 UTF-8 bytes. Invalid UTF-8, control characters (including NUL
and DEL) and surrounding Unicode whitespace are rejected. Interior spaces,
Unicode and case are retained. Exact case-sensitive organization name uniqueness,
including archived names, remains a storage constraint.

Branches require 1–255 UTF-8 bytes and an unqualified Git branch spelling.
Whitespace anywhere, controls, invalid UTF-8, leading `-` or `refs/`, exact `HEAD`,
lone `@`, `@{`, `..`, trailing `.`, and `~^:?*[\` are rejected. Slash components
must be nonempty, cannot start with `.`, and cannot end with `.lock`. Valid
Unicode and case are preserved; validation performs no checkout expansion.

Engine versions require a complete canonical SemVer 2.0 spelling of at most 64
ASCII bytes: three decimal components without leading zeroes, optional prerelease,
then optional build metadata. Identifiers are nonempty ASCII letters, digits or
hyphens separated by dots. Numeric prerelease identifiers cannot have leading
zeroes; numeric build identifiers may. The validators do not parse integers, so
valid large numeric components remain acceptable within the total byte limit.
Prefixes, aliases, ranges, URLs, paths, arguments and whitespace are rejected.
Availability and engine compatibility remain later execution prerequisites.

These helpers expose no RPC, storage or execution path. Full authenticated CRUD,
security review and hosted CI acceptance remain gates for WP-1.2 completion.
