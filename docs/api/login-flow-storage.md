# Browser login flow storage

Owner: CORE-BACKEND; WP-1.1, dependent on accepted ADR0016 and migration 00003.
This schema slice exposes no route or persistence helper. QA-SECURITY review and
hosted CI remain gates; sessions, cleanup and atomic consumption are later slices.

`login_flows` contains a server UUID, unique 32-byte state digest, 32-byte browser
binding digest and opaque envelope metadata. It contains no org or principal.
Both digests must match transaction-local `forge.login_state_hash` and
`forge.login_binding_hash`. Comparison with lowercase hex encoding rejects absent,
partial, uppercase and malformed context without decoding untrusted SQL values.
Org and verified-principal settings grant no flow access. Future helpers must
clear inherited contexts, use explicit digest/expiry predicates and reset context
on pooled connections; those helpers are not implemented or tested here.

The runtime can SELECT/DELETE matching flows and INSERT only envelope/digest/UUID
columns. Database defaults set creation time and exactly ten-minute expiry;
timestamps cannot be supplied by the runtime. Nonempty ciphertext, wrapped DEK
and key ID, 12-byte nonce and 32-byte digest constraints reject invalid metadata.
The expiry/UUID index supports the separately reviewed bounded cleanup slice.

ARCHITECT approved initial event actions `login_flow.created` and
`login_flow.consumed`, with the sole outcome `success`. Success means a committed
storage mutation, never successful authentication. Future helpers must insert the
corresponding event atomically with creation/consumption. This slice provides only
the table/grants, without claiming atomic lifecycle behavior. Failure/session
actions require a later allowlist migration. Events contain only UUID, database
timestamp, action and outcome: no flow reference, identity, credential or details.
Runtime INSERT is limited to UUID/action/outcome; SELECT/UPDATE/DELETE/TRUNCATE are
denied, and the existing append-only trigger also protects privileged mutations.

Real PostgreSQL tests require `TEST_DATABASE_URL` for the non-owner, NOBYPASSRLS
runtime role. They cover forced RLS, digest boundaries, flow-only denial of seeded
tenant resources, timestamp/metadata constraints and event privileges. Migration
up/down/up is a separate acceptance check. Full browser-login and WP-1.1 acceptance
remain outstanding.
