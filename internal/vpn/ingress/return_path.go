package ingress

import "github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"

// NewRouterWithReturnPath also fences the memo, fallback registration and
// packet submission to the engine that owns the peer's return path.
func NewRouterWithReturnPath(resolver *Resolver, admission Admission, fwd *forwarder.Forwarder, liveness Liveness, path *forwarder.ReturnPath) *Router {
	if path == nil {
		panic("ingress: return path is required")
	}
	router := NewRouter(resolver, admission, fwd, liveness)
	router.forwarder = ownedRoutes{fwd: fwd, path: path}
	return router
}

type ownedRoutes struct {
	fwd  *forwarder.Forwarder
	path *forwarder.ReturnPath
}

func (o ownedRoutes) HasSessionRoute(peerKey, sessionID, connectionID, assignedIP string, backendID int64) bool {
	return o.fwd.HasSessionRouteWithReturnPath(peerKey, sessionID, connectionID, assignedIP, backendID, o.path)
}
func (o ownedRoutes) TryRegisterSessionWithLimit(sessionID, connectionID, peerKey, assignedIP string, backendID, _, _ int64) (forwarder.Retirement, error) {
	// Admission owns session creation under service serialization. If another
	// generation won afterward, never recreate the stale session's route here.
	if !o.HasSessionRoute(peerKey, sessionID, connectionID, assignedIP, backendID) {
		return forwarder.Retirement{}, forwarder.ErrReturnRouteMismatch
	}
	return forwarder.Retirement{}, nil
}
func (o ownedRoutes) RouteClientToBackend(peerKey string, packet []byte) error {
	return o.fwd.RouteClientToBackendWithReturnPath(peerKey, packet, o.path)
}
