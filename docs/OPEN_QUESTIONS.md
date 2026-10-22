# Open questions and reversible decisions

| Question | M0 decision | Remaining work |
| --- | --- | --- |
| Repository and license? | User selected cavula/forge; preserve its Apache-2.0 license. | Namespace ADR accompanies the contract slices. |
| Who approves API contracts? | Assign the roadmap ARCHITECT role to the contract agent, with root architecture review. | Maintainers select human approval identities before collaboration. |
| How is the bootstrap reviewed? | Publish small PRs and keep the complete implementation on a separate validation branch. | Split generated contracts through an approved ADR. The user approved a one-time size exception for web/pnpm-lock.yaml; every other file still counts toward the 500-line limit. |
| Does M0 implement authentication or encryption services? | M0 establishes contracts, schema and security decisions. | M1 adds authenticated operations and tested encryption before state/secret writes. |
| Can local checks satisfy hosted CI acceptance? | No. Local results are recorded separately. | Hosted checks must pass before any WP is DONE. |

The complete validation branch records implementation-specific choices for users,
key providers, version pins and the initial breaking-check baseline. Those choices
will accompany their respective review slices. No M1 work is included here.
