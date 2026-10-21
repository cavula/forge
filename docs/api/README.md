# API contracts

`proto/forge/v1` is the source of truth. ADR0001 approves the initial nine entities
and public FoundationService.GetInfo. All future proto changes need a newly
approved ARCHITECT ADR. Run `make generate`; commit Go, Connect and TypeScript
outputs. Remote generators are version-pinned in buf.gen.yaml.

`m0.binpb` is the initial descriptor baseline. First-commit CI uses this because
there is no prior API. Later CI compares the real PR base/previous push SHA.
Never update the baseline merely to silence a breaking-change report.

Secret and StateVersion messages are metadata-only; state contents, plaintext,
ciphertext and key material are absent. Organization fields identify resources
and never establish authorization. GetInfo is the only exposed RPC in M0.
