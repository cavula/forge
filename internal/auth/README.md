# auth

M1 begins with the role/action policy approved in ADR0009. Callers must resolve
an authenticated, current organization membership before evaluating `Allows`.
There are no login, membership administration or API-token endpoints yet.
Ordinary metadata/resource permissions do not grant state, secret, credential
or run-approval access. Unknown roles and actions deny, including for admins.
