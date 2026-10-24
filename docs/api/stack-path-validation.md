# Stack repository and working-directory validation

ADR0018's private helpers validate repository URLs and working directories before
later stack CRUD storage. Errors contain only the fixed field category; neither
helper logs input, resolves DNS, fetches repositories or accesses the filesystem.

Repository URLs are at most 2048 ASCII bytes and use HTTPS with a nonempty path.
Hosts must be lowercase DNS labels (including ASCII punycode A-label spelling)
or canonical IPv4/IPv6 text. IPv6 requires brackets; scoped addresses are rejected.
DNS labels are 1–63 bytes, with at most 253 host bytes and no boundary hyphens.
All-digit/dot hosts require canonical IP parsing; reserved double-hyphen labels such as `ab--cd` are rejected.
Explicit ports contain digits and represent 1–65535; leading zeroes are retained.
HTTPS scheme case is immaterial. An explicit nontransitional IDNA lookup profile
with Bidi and DNS-length validation must convert the host to exactly the same
ASCII spelling; malformed or noncanonical punycode is rejected without fallback.
Repository path components contain only ASCII letters, digits and `._~-`.
Userinfo, query/fragment delimiters including empty ones, percent signs, backslash,
empty/dot/dot-dot path components and trailing slashes are rejected.

Working directories accept `.` or a canonical POSIX relative path of at most 512
UTF-8 bytes. Empty/dot/dot-dot components, leading slash/tilde, backslash, colon,
percent signs, invalid UTF-8, controls and surrounding whitespace are rejected.
Interior spaces and Unicode directory names are retained without expansion.

Acceptance of a URL or path grants no runtime network or filesystem permission.
Later VCS authentication, runner egress/SSRF review and post-checkout symlink/path
containment remain separate gates. These helpers expose no RPC or storage path.
