# Embedded plan evaluation

Owner: POLICY; WP-1.9; dependencies: ADR0012/0014 and OPA SDK v1.21.3.
Status: bounded evaluator implemented and independently reviewed; no endpoint.

Construct the embedded evaluator once. Evaluate exact saved-plan JSON bytes with
their SHA-256 from trusted artifact storage. Never derive the expected digest
from request input at the authorization boundary. The evaluator copies bytes,
checks the digest, bounds parsing/evaluation and returns stable rule IDs only.
Malformed input, unknown decisions and resource/cancellation failures deny.

Race tests cover deny/warn/approval decisions, tamper/context failures, duplicate
keys, malformed UTF-8, depth/numeric/byte limits, cancellation and concurrency.
Business coverage is 97.8%; QA-SECURITY and ARCHITECT approved the bounded slice.

Workflow integration must bind this JSON to the immutable binary plan, enforce
current authorization and required human approval, and prove the full MVP flow
in CI. A passing policy result alone never grants apply permission.
