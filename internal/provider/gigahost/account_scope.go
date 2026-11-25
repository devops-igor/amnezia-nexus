package gigahost

// The credential's own scope, as the documented permissions object states it.
//
// It lives beside the account decode rather than in the type file, which is close to
// the repository's size ceiling, and because it is the one input that may certify an
// inventory listing as the account's whole enumeration.

import "encoding/json"

// AccountPermissions is the documented permissions object: one entry per permission
// category, each with a mode and - for the resource categories dns, servers and
// webhosting - an all flag and an optional id list.
type AccountPermissions struct {
	Servers *PermissionScope `json:"servers,omitempty"`
}

// PermissionScope is one category's documented scope.
type PermissionScope struct {
	Mode string `json:"mode"`
	// All defaults to true when a permission object omits it, so a nil pointer is
	// resolved by the caller rather than assumed here.
	All *bool `json:"all"`
	// IDs restricts the category to specific resource ids when all is false.
	IDs []json.RawMessage `json:"ids,omitempty"`
}

// EnumeratesWholeAccount reports whether this payload states that the credential may
// enumerate every server on the account.
//
// stated is false when the payload says nothing about the credential's visibility: no
// permissions object, no servers entry, or no all flag. A stated scope carrying ids or
// all:false is a restriction, and a contradictory payload (all:true beside ids) is
// read as restricted - the fail-visible direction.
func (a *AccountInfo) EnumeratesWholeAccount() (accountWide, stated bool) {
	if a == nil || a.Permissions == nil || a.Permissions.Servers == nil {
		return false, false
	}
	scope := a.Permissions.Servers
	if len(scope.IDs) > 0 {
		return false, true
	}
	if scope.All == nil {
		return false, false
	}
	return *scope.All, true
}
