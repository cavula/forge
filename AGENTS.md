# Forge repository instructions

Read docs/BRIEF.md before changes. Stop at the current milestone gate.
Track owner, dependencies, acceptance evidence and blockers in docs/STATUS.md.
Record ambiguity and reversible choices in docs/OPEN_QUESTIONS.md.

Changes to proto/ require a new ADR explicitly approved by ARCHITECT before
implementation. Regenerate Go/Connect/TypeScript clients and run buf lint and
breaking checks. ADR0001 authorizes only the initial M0 contracts.

QA-SECURITY review is mandatory for authentication, state, secrets, runners and AI.
Use non-owner PostgreSQL roles, WithOrg transaction-local tenant context derived
from authorization, and explicit org predicates. Do not log payloads or credentials.

Keep each proposed PR below 500 changed lines, with tests/docs. The user approved
a one-time exception for web/pnpm-lock.yaml only; count every other file, including
generated clients, toward the limit. Do not publish an oversized bootstrap PR. Use the review slicing plan in docs/STATUS.md;
regenerate clients in each contract slice. A WP is DONE only after its CI AC pass.
