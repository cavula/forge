// Package policies contains the reviewed, built-in Forge plan policy.
package policies

import _ "embed"

//go:embed starter.rego
var starter string

// Starter returns the policy compiled into this binary; no runtime loading occurs.
func Starter() string { return starter }
