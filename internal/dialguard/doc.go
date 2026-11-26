// Package dialguard holds the derived inventory of the points in this panel that
// can open a network connection to a managed server, and the checks that keep the
// provider-absence refusal at the boundary every one of them passes through.
//
// The inventory is derived from the source tree rather than written from memory:
// a duck-typed list of callers is what let two rounds of this work miss an
// unrelated worker and an automatic poll. The only production code in this
// package is this comment; the checks are in dialguard_test.go, so a new dialing
// path fails a test instead of shipping quietly.
package dialguard
