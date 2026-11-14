package policy

import (
	"errors"
	"sync"
)

// This file owns the write-ownership boundary for policy generations.
//
// One service can have several syncers over its lifetime: the runtime that is
// live, and a replacement created by the operator's save. They share the durable
// store and the matcher, so "who may write" cannot be a property of a single
// syncer. Without a boundary, an on-demand sync that is already blocked in a slow
// HTTPS fetch commits and publishes its old generation *after* the replacement has
// been accepted, leaving settings and status naming the new source while both the
// live and the durable generation are the old one (#678 F678-04).
//
// Atomic renames and atomic pointer publication prevent torn writes, not an
// obsolete last writer, so the boundary has to be evaluated at the write itself:
// the durable commit and the live publication are one critical section, and a
// writer whose runtime has been superseded is refused inside it.

// ErrSyncSuperseded reports an update whose runtime no longer owns the live
// policy: a newer runtime has published, or the runtime was retired by an
// explicit disable or shutdown. Committing or publishing would overwrite a policy
// the operator has already replaced.
var ErrSyncSuperseded = errors.New("policy sync superseded: this runtime no longer owns the live policy")

// WriteOwner is the write-ownership boundary of one policy service.
//
// Each syncer is given a ticket when it is attached. A write from the ticket that
// currently owns the service proceeds; a write from an older ticket is refused. A
// newer ticket takes ownership as part of its own successful write, so a
// replacement cannot strand the incumbent when its candidate is refused: the
// hand-over happens only when the replacement actually commits and publishes.
type WriteOwner struct {
	mu      sync.Mutex
	next    uint64
	current uint64
	retired bool
}

// NewWriteOwner returns an owner that has issued no tickets.
func NewWriteOwner() *WriteOwner { return &WriteOwner{} }

// Ticket issues the next writer ticket. Tickets are monotonic for the life of the
// owner, so "older" and "newer" are well defined.
func (o *WriteOwner) Ticket() uint64 {
	if o == nil {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.next++
	return o.next
}

// Retire permanently refuses every write through this owner, including the
// current owner's. It blocks until an in-flight commit-and-publish section
// finishes, so a caller that retires before tearing the data path down knows no
// further write can land afterwards.
//
// A nil owner is a no-op, which is what an unattached syncer (unit tests, or a
// store-only helper) uses.
func (o *WriteOwner) Retire() {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.retired = true
	o.mu.Unlock()
}

// Write runs fn inside the ownership boundary.
//
//   - retired owner: refused.
//   - older ticket than the current owner: refused, without running fn, so a
//     superseded runtime cannot commit or publish.
//   - the current owner's ticket: runs fn.
//   - a newer ticket: fn runs and the ticket becomes the owner only if it
//     succeeds, so a refused replacement leaves the incumbent in charge.
//
// fn must contain both the durable commit and the live publication; that is what
// makes the boundary span the two and not just the fetch or the scheduler.
func (o *WriteOwner) Write(ticket uint64, fn func() error) error {
	if o == nil {
		return fn()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.retired {
		return ErrSyncSuperseded
	}
	switch {
	case ticket < o.current:
		return ErrSyncSuperseded
	case ticket == o.current:
		return fn()
	}
	if err := fn(); err != nil {
		return err
	}
	o.current = ticket
	return nil
}
