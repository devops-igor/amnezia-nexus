package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/cps"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ipam"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

var (
	mimicryPacketsMu       sync.RWMutex
	generateMimicryPackets = cps.GenerateMimicryPackets

	preAssignmentHookMu          sync.RWMutex
	preAssignmentLockHookForTest func()
)

func setGenerateMimicryPacketsForTest(fn func(ctx context.Context, mimicry string, domain string, sshClient ssh.SSHClient) (map[string]string, error)) func() {
	mimicryPacketsMu.Lock()
	orig := generateMimicryPackets
	generateMimicryPackets = fn
	mimicryPacketsMu.Unlock()
	return func() {
		mimicryPacketsMu.Lock()
		generateMimicryPackets = orig
		mimicryPacketsMu.Unlock()
	}
}

// SetPreAssignmentLockHookForTest installs a test hook called after client keypair
// generation and immediately before acquiring assignmentMu in renderClientConfigForConnection.
func SetPreAssignmentLockHookForTest(fn func()) func() {
	preAssignmentHookMu.Lock()
	orig := preAssignmentLockHookForTest
	preAssignmentLockHookForTest = fn
	preAssignmentHookMu.Unlock()
	return func() {
		preAssignmentHookMu.Lock()
		preAssignmentLockHookForTest = orig
		preAssignmentHookMu.Unlock()
	}
}

// SetPreAssignmentLockHookForTest installs a test hook on Service.
func (s *Service) SetPreAssignmentLockHookForTest(fn func()) func() {
	return SetPreAssignmentLockHookForTest(fn)
}

var (
	// ErrConnectionCreatedConcurrently is returned when client config generation raced
	// with a concurrent creation of the user's connection while awgConn was nil.
	ErrConnectionCreatedConcurrently = errors.New("connection was created concurrently; retry")

	// ErrUserNotFound is returned when the target user does not exist in the database.
	ErrUserNotFound = errors.New("user not found")

	// ErrBadRequest indicates an invalid or unsupported client configuration request.
	ErrBadRequest = errors.New("invalid client configuration request")

	// ErrInvalidParameter indicates an invalid client configuration parameter.
	ErrInvalidParameter = errors.New("invalid client configuration parameter")

	// ErrAccessDenied indicates forbidden access to the client configuration.
	ErrAccessDenied = errors.New("access denied")
)

// GenerateUserClientConfig is an alias for GenerateClientConfig for API clarity.
func (s *Service) GenerateUserClientConfig(ctx context.Context, userID string) (string, string, error) {
	return s.GenerateClientConfig(ctx, userID)
}

func resolveHeaderProtectionKey(ctx context.Context, db *database.DB, cfg *models.VPNConfig, awgParams *awg.AWGParams) {
	if awgParams.HeaderProtectionKey == "" {
		if cfg != nil && cfg.HeaderProtectionKey != "" {
			awgParams.HeaderProtectionKey = cfg.HeaderProtectionKey
		} else if db != nil {
			if vpnCfg, err := db.GetVPNConfig(ctx); err == nil && vpnCfg != nil && vpnCfg.HeaderProtectionKey != "" {
				awgParams.HeaderProtectionKey = vpnCfg.HeaderProtectionKey
			}
		}
	}
	if awgParams.HeaderProtectionKey != "" {
		ensureMinJunk := func(valStr *string, minVal int) {
			num, err := strconv.Atoi(*valStr)
			if err != nil || num < minVal {
				*valStr = strconv.Itoa(minVal)
			}
		}
		ensureMinJunk(&awgParams.InitPacketJunkSize, 12)
		ensureMinJunk(&awgParams.ResponsePacketJunkSize, 12)
		ensureMinJunk(&awgParams.CookieReplyPacketJunkSize, 12)
		ensureMinJunk(&awgParams.TransportPacketJunkSize, 12)
	}
}

func resolveContentPadding(ctx context.Context, db *database.DB, cfg *models.VPNConfig) (bool, string) {
	if cfg != nil && cfg.ContentPaddingAddition != "" && cfg.ContentPaddingAddition != "false" && cfg.ContentPaddingAddition != "0" {
		val := cfg.ContentPaddingAddition
		if val == "true" || val == "yes" || val == "1" {
			val = "16-64"
		}
		return true, val
	}
	if db == nil {
		return false, ""
	}
	srvs, err := db.GetAllServers(ctx)
	if err != nil {
		return false, ""
	}
	for _, srv := range srvs {
		if srv.Protocols == nil {
			continue
		}
		awgInfo, ok := srv.Protocols["awg"].(map[string]any)
		if !ok {
			continue
		}
		params, ok := awgInfo["awg_params"].(map[string]any)
		if !ok {
			continue
		}
		if cp, ok := params["awg_content_padding"]; ok {
			if b, _ := strconv.ParseBool(fmt.Sprint(cp)); b {
				return true, "16-64"
			}
		}
		if cp, ok := params["content_padding_addition"].(string); ok && cp != "" && cp != "false" {
			return true, cp
		}
	}
	return false, ""
}

type clientConfigParameters struct {
	clientPub  string
	clientPriv string
	rat        *awg.TimingRange
	rt         *awg.TimingRange
	rej        *awg.TimingRange
	kt         *awg.TimingRange
	mha        *awg.TimingRange
	pk         *awg.TimingRange
	cpAdd      *string
}

func resolveClientConfigParameters(awgConn *models.UserConnection, cpEnabled bool, cpVal string) (*clientConfigParameters, error) {
	res := &clientConfigParameters{}
	if awgConn != nil && len(awgConn.ClientParams) > 0 {
		res.rat = getTimingParam(awgConn.ClientParams, "rekey_after_time")
		res.rt = getTimingParam(awgConn.ClientParams, "rekey_timeout")
		res.rej = getTimingParam(awgConn.ClientParams, "reject_after_time")
		res.kt = getTimingParam(awgConn.ClientParams, "keepalive_timeout")
		res.mha = getTimingParam(awgConn.ClientParams, "max_handshake_attempts")
		res.pk = getTimingParam(awgConn.ClientParams, "persistent_keepalive")
		res.clientPriv = getStringParam(awgConn.ClientParams, "client_private_key")
		if res.clientPriv != "" && awgConn.ClientID != "" {
			res.clientPub = awgConn.ClientID
		}
		if s := getStringParam(awgConn.ClientParams, "content_padding_addition"); s != "" {
			res.cpAdd = &s
		}
	}

	rtBackfilled := (res.rt == nil)
	ratBackfilled := (res.rat == nil)

	if res.rat == nil {
		res.rat = awg.GenerateRekeyAfterTime()
	}
	if res.rt == nil {
		res.rt = awg.GenerateRekeyTimeout()
	}
	if res.rej == nil {
		res.rej = awg.GenerateRejectAfterTime()
	}
	if res.kt == nil {
		res.kt = awg.GenerateKeepaliveTimeout()
	}
	if res.mha == nil {
		res.mha = awg.GenerateMaxHandshakeAttempts()
	}
	if res.pk == nil {
		res.pk = awg.GeneratePersistentKeepalive()
	}

	if rtBackfilled && !ratBackfilled {
		if res.rt.Hi >= res.rat.Lo {
			res.rt.Hi = max(1, res.rat.Lo-1)
			if res.rt.Lo > res.rt.Hi {
				res.rt.Lo = res.rt.Hi
			}
		}
		// Clamp below any stored reject_after_time too: the regenerated rat may
		// extend past a stored rej (e.g. stored rt=110, rej=125, generated
		// rat=111-128). EnforceTimingOrdering is not called here because stored
		// values must not be mutated, so clamp the regenerated ranges instead.
		awg.EnforceTimingOrdering(nil, res.rat, res.rej)
	} else if ratBackfilled && !rtBackfilled {
		if res.rat.Lo <= res.rt.Hi {
			res.rat.Lo = res.rt.Hi + 1
			if res.rat.Hi < res.rat.Lo {
				res.rat.Hi = res.rat.Lo
			}
		}
		// Same: regenerated rat raised above stored rt.Hi may now collide with
		// a stored rej; re-check invariant 2 without touching stored values.
		awg.EnforceTimingOrdering(nil, res.rat, res.rej)
	} else {
		awg.EnforceTimingOrdering(res.rt, res.rat, res.rej)
	}

	if res.cpAdd == nil && cpEnabled {
		res.cpAdd = &cpVal
	}

	if res.clientPub == "" || res.clientPriv == "" {
		pub, priv, err := tunnel.GenerateCurve25519KeyPair()
		if err != nil {
			return nil, err
		}
		res.clientPub = pub
		res.clientPriv = priv
	}

	return res, nil
}

// GenerateClientConfigForConnection generates or retrieves client configuration for a specific connection ID.
func (s *Service) GenerateClientConfigForConnection(ctx context.Context, userID string, connectionID string) (string, string, error) {
	s.mu.RLock()
	db := s.db
	cfg := s.cfg
	portalPub := s.portalPubKey
	s.mu.RUnlock()

	if db == nil {
		return "", "", errors.New("database not available")
	}

	user, err := db.GetUser(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return "", "", ErrUserNotFound
	}

	conn, err := db.GetConnection(ctx, connectionID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get connection: %w", err)
	}
	if conn == nil {
		return "", "", errors.New("connection not found")
	}
	if conn.UserID != userID {
		return "", "", errors.New("unauthorized: connection does not belong to user")
	}
	if conn.ServerID != 0 {
		return "", "", fmt.Errorf("connection %s is not a load balancer connection (server_id=%d)", connectionID, conn.ServerID)
	}
	if conn.Protocol != "" && models.NormalizeProtocol(conn.Protocol) != "awg" {
		return "", "", fmt.Errorf("unsupported protocol %q for load balancer connection", conn.Protocol)
	}

	return s.renderClientConfigForConnection(ctx, db, cfg, portalPub, user, conn, true)
}

// GenerateClientConfig builds an AWG client configuration for connecting to this portal VPN endpoint.
func (s *Service) GenerateClientConfig(ctx context.Context, userID string) (string, string, error) {
	s.mu.RLock()
	db := s.db
	cfg := s.cfg
	portalPub := s.portalPubKey
	s.mu.RUnlock()

	if db == nil {
		return "", "", errors.New("database not available")
	}

	user, err := db.GetUser(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return "", "", ErrUserNotFound
	}

	awgConn := findAWGConnection(ctx, db, user)
	return s.renderClientConfigForConnection(ctx, db, cfg, portalPub, user, awgConn, false)
}

func (s *Service) renderClientConfigForConnection(
	ctx context.Context,
	db *database.DB,
	cfg *models.VPNConfig,
	portalPub string,
	user *models.User,
	awgConn *models.UserConnection,
	isExplicit bool,
) (string, string, error) {
	listenPort := 51820
	if cfg != nil && cfg.ListenPort > 0 {
		listenPort = cfg.ListenPort
	}

	endpointStr := s.resolveClientEndpoint(ctx, cfg, listenPort)
	awgParams := awg.AWGParamsFromVPNConfig(cfg)
	resolveHeaderProtectionKey(ctx, db, cfg, awgParams)
	cpEnabled, cpVal := resolveContentPadding(ctx, db, cfg)

	p, err := resolveClientConfigParameters(awgConn, cpEnabled, cpVal)
	if err != nil {
		return "", "", err
	}

	preAssignmentHookMu.RLock()
	hook := preAssignmentLockHookForTest
	preAssignmentHookMu.RUnlock()
	if hook != nil {
		hook()
	}

	s.assignmentMu.Lock()
	defer s.assignmentMu.Unlock()
	if err := reservePersistedClientIPs(ctx, db, s.ipam); err != nil {
		return "", "", fmt.Errorf("restore client IP assignments: %w", err)
	}

	refreshedConn, keysAlreadyPersisted, err := refreshAndAdoptPersistedConnection(ctx, db, user, awgConn, isExplicit, p)
	if err != nil {
		return "", "", err
	}
	awgConn = refreshedConn

	clientParams := buildClientParams(awgConn, p)
	i1, err := resolvePortalI1(ctx, cfg, clientParams)
	if err != nil {
		return "", "", err
	}
	awgParams.I1 = i1
	_, hadLease := s.ipam.GetAssignedIP(p.clientPub)
	assignedIP, err := s.resolveAssignedIP(clientParams, cfg, p.clientPub)
	if err != nil {
		return "", "", err
	}
	delete(clientParams, "config_regeneration_required")
	delete(clientParams, "quarantined_ip_collision")
	clientParams["assigned_ip"] = assignedIP

	if connectionNeedsUpdate(awgConn, keysAlreadyPersisted, assignedIP, i1) {
		if err := s.persistRenderedConnection(ctx, db, user, awgConn, isExplicit, p.clientPub, clientParams, hadLease); err != nil {
			return "", "", err
		}
	} else if awgConn != nil {
		awgConn.ClientID = p.clientPub
		awgConn.ClientParams = clientParams
	}

	ud := &awg.AWGClientUserData{
		ClientName:             user.Username,
		ClientPrivateKey:       p.clientPriv,
		ClientIP:               assignedIP,
		Enabled:                true,
		RekeyAfterTime:         p.rat,
		RekeyTimeout:           p.rt,
		RejectAfterTime:        p.rej,
		KeepaliveTimeout:       p.kt,
		MaxHandshakeAttempts:   p.mha,
		PersistentKeepalive:    p.pk,
		ContentPaddingAddition: p.cpAdd,
	}

	clientMTU := resolveClientMTU(awgConn, awgParams)

	configStr := awg.RenderClientConfig(
		p.clientPriv,
		assignedIP,
		portalPub,
		"", // psk
		endpointStr,
		awg.AWGDefaults["dns1"],
		awg.AWGDefaults["dns2"],
		clientMTU,
		awgParams,
		ud,
	)

	filename := fmt.Sprintf("amnezia-portal-%s.conf", user.Username)
	if isExplicit && awgConn != nil && awgConn.Name != "" {
		filename = fmt.Sprintf("%s.conf", awgConn.Name)
	}
	return configStr, filename, nil
}

func refreshAndAdoptPersistedConnection(
	ctx context.Context,
	db *database.DB,
	user *models.User,
	awgConn *models.UserConnection,
	isExplicit bool,
	p *clientConfigParameters,
) (*models.UserConnection, bool, error) {
	if awgConn != nil && awgConn.ID != "" {
		freshConn, err := db.GetConnection(ctx, awgConn.ID)
		if err != nil {
			return nil, false, fmt.Errorf("failed to get connection: %w", err)
		}
		if freshConn == nil {
			return nil, false, errors.New("connection was removed")
		}
		keysAlreadyPersisted := false
		if freshConn.ClientID != "" {
			if priv := getStringParam(freshConn.ClientParams, "client_private_key"); priv != "" {
				keysAlreadyPersisted = true
				if awgConn.ClientID == "" || getStringParam(awgConn.ClientParams, "client_private_key") == "" {
					p.clientPub = freshConn.ClientID
					p.clientPriv = priv
					adoptTimingParams(p, freshConn.ClientParams)
				}
			}
		}
		return freshConn, keysAlreadyPersisted, nil
	}
	if awgConn == nil && !isExplicit {
		if found := findAWGConnection(ctx, db, user); found != nil {
			return nil, false, ErrConnectionCreatedConcurrently
		}
	}
	return awgConn, false, nil
}

func adoptTimingParams(p *clientConfigParameters, params map[string]any) {
	if tr := getTimingParam(params, "rekey_after_time"); tr != nil {
		p.rat = tr
	}
	if tr := getTimingParam(params, "rekey_timeout"); tr != nil {
		p.rt = tr
	}
	if tr := getTimingParam(params, "reject_after_time"); tr != nil {
		p.rej = tr
	}
	if tr := getTimingParam(params, "keepalive_timeout"); tr != nil {
		p.kt = tr
	}
	if tr := getTimingParam(params, "max_handshake_attempts"); tr != nil {
		p.mha = tr
	}
	if tr := getTimingParam(params, "persistent_keepalive"); tr != nil {
		p.pk = tr
	}
	if s := getStringParam(params, "content_padding_addition"); s != "" {
		p.cpAdd = &s
	}
}

func connectionNeedsUpdate(awgConn *models.UserConnection, keysAlreadyPersisted bool, assignedIP, i1 string) bool {
	if !keysAlreadyPersisted {
		return true
	}
	if awgConn == nil || awgConn.ClientParams == nil {
		return true
	}
	if getStringParam(awgConn.ClientParams, "assigned_ip") != assignedIP ||
		getStringParam(awgConn.ClientParams, "portal_i1") != i1 {
		return true
	}
	if req, ok := awgConn.ClientParams["config_regeneration_required"].(bool); ok && req {
		return true
	}
	if q, ok := awgConn.ClientParams["quarantined_ip_collision"]; ok && q != nil && q != "" {
		return true
	}
	return false
}

func (s *Service) persistRenderedConnection(
	ctx context.Context,
	db *database.DB,
	user *models.User,
	awgConn *models.UserConnection,
	isExplicit bool,
	clientPub string,
	clientParams map[string]any,
	hadLease bool,
) error {
	if isExplicit && awgConn != nil {
		updates := map[string]any{
			"client_id":     clientPub,
			"client_params": clientParams,
		}
		updated, err := db.UpdateConnection(ctx, awgConn.ID, updates)
		if err != nil || !updated {
			if !hadLease {
				_ = s.ipam.Release(clientPub)
			}
			if err == nil {
				err = errors.New("connection was removed")
			}
			return fmt.Errorf("failed to update connection: %w", err)
		}
		awgConn.ClientID = clientPub
		awgConn.ClientParams = clientParams
		return nil
	}

	if err := saveOrUpdateAWGConnection(ctx, db, user, awgConn, clientPub, clientParams); err != nil {
		if !hadLease {
			_ = s.ipam.Release(clientPub)
		}
		return fmt.Errorf("failed to persist client configuration: %w", err)
	}
	if awgConn != nil {
		awgConn.ClientID = clientPub
		awgConn.ClientParams = clientParams
	}
	return nil
}

func resolveClientMTU(awgConn *models.UserConnection, awgParams *awg.AWGParams) string {
	if awgConn != nil && len(awgConn.ClientParams) > 0 {
		if m := getStringParam(awgConn.ClientParams, "mtu"); m != "" {
			return m
		}
	}
	if awgParams != nil && awgParams.MTU != "" {
		return awgParams.MTU
	}
	return "1280"
}

func resolvePortalI1(ctx context.Context, cfg *models.VPNConfig, clientParams map[string]any) (string, error) {
	if err := cfg.ValidateDataPlaneI1Protocol(); err != nil {
		return "", err
	}
	i1, exists := clientParams["portal_i1"]
	if !exists {
		if err := ctx.Err(); err != nil {
			return "", fmt.Errorf("generate portal I1: %w", err)
		}
		mimicryPacketsMu.RLock()
		genFn := generateMimicryPackets
		mimicryPacketsMu.RUnlock()
		packets, err := genFn(ctx, cfg.DataPlaneI1Protocol(), "", nil)
		if err != nil {
			return "", fmt.Errorf("generate portal I1: %w", err)
		}
		genI1, ok := packets["i1"]
		if !ok || genI1 == "" {
			return "", errors.New("empty generator result for portal I1")
		}
		clientParams["portal_i1"] = genI1
		return genI1, nil
	}
	value, ok := i1.(string)
	if !ok || value == "" {
		return "", errors.New("malformed persisted portal I1")
	}
	return value, nil
}

func buildClientParams(awgConn *models.UserConnection, p *clientConfigParameters) map[string]any {
	clientParams := make(map[string]any)
	if awgConn != nil && awgConn.ClientParams != nil {
		for k, v := range awgConn.ClientParams {
			clientParams[k] = v
		}
	}
	updateTimingParam := func(key string, tr *awg.TimingRange) {
		if tr == nil {
			return
		}
		existingVal, exists := clientParams[key]
		if !exists || existingVal == nil {
			clientParams[key] = tr.String()
			return
		}
		parsedExisting, err := awg.ParseTimingRange(existingVal)
		if err != nil || parsedExisting == nil || parsedExisting.Lo != tr.Lo || parsedExisting.Hi != tr.Hi {
			clientParams[key] = tr.String()
		}
	}

	updateTimingParam("rekey_after_time", p.rat)
	updateTimingParam("rekey_timeout", p.rt)
	updateTimingParam("reject_after_time", p.rej)
	updateTimingParam("keepalive_timeout", p.kt)
	updateTimingParam("max_handshake_attempts", p.mha)
	updateTimingParam("persistent_keepalive", p.pk)
	clientParams["client_private_key"] = p.clientPriv
	if p.cpAdd != nil {
		clientParams["content_padding_addition"] = *p.cpAdd
	}
	return clientParams
}

func (s *Service) resolveAssignedIP(clientParams map[string]any, cfg *models.VPNConfig, clientPub string) (string, error) {
	regenerationRequired := false
	if req, ok := clientParams["config_regeneration_required"].(bool); ok && req {
		regenerationRequired = true
	}
	if q, ok := clientParams["quarantined_ip_collision"]; ok && q != nil && q != "" {
		regenerationRequired = true
	}

	if !regenerationRequired {
		if existingVal, ok := clientParams["assigned_ip"]; ok && existingVal != nil {
			if existingStr, ok := existingVal.(string); ok && existingStr != "" {
				parsedIP := net.ParseIP(existingStr)
				if parsedIP != nil && parsedIP.To4() != nil {
					valid := true
					if cfg != nil && cfg.SubnetCIDR != "" {
						if _, cidrNet, err := net.ParseCIDR(cfg.SubnetCIDR); err == nil {
							if !cidrNet.Contains(parsedIP) {
								valid = false
							}
						}
					}
					if valid {
						if s.ipam != nil {
							err := s.ipam.Reserve(parsedIP, clientPub)
							if err == nil {
								return existingStr, nil
							}
							if errors.Is(err, ipam.ErrIPAlreadyAllocated) {
								return "", fmt.Errorf("client %s persisted IP %s conflicts with another client: %w", clientPub, existingStr, err)
							}
						} else {
							return existingStr, nil
						}
					}
				}
			}
		}
	}

	if s.ipam != nil {
		if regenerationRequired {
			_ = s.ipam.Release(clientPub)
		}
		ip, err := s.ipam.Allocate(clientPub)
		if err != nil {
			return "", fmt.Errorf("allocate client IP: %w", err)
		}
		delete(clientParams, "config_regeneration_required")
		delete(clientParams, "quarantined_ip_collision")
		return ip.String(), nil
	}
	return "", errors.New("IP address manager is unavailable")
}

func findAWGConnection(ctx context.Context, db *database.DB, user *models.User) *models.UserConnection {
	conns, err := db.GetConnectionsByUserID(ctx, user.ID)
	if err != nil || len(conns) == 0 {
		return nil
	}

	// Priority 1: Match pending connection created with empty ClientID
	for i := range conns {
		if conns[i].ServerID == 0 && (conns[i].Protocol == "" || models.NormalizeProtocol(conns[i].Protocol) == "awg") && conns[i].ClientID == "" {
			return &conns[i]
		}
	}
	// Priority 2: Match default portal connection
	for i := range conns {
		if conns[i].ServerID == 0 && conns[i].Name == fmt.Sprintf("%s-awg", user.Username) {
			return &conns[i]
		}
	}
	// Priority 3: Pick the most recently created load balancer connection
	var latestLB *models.UserConnection
	for i := range conns {
		if conns[i].ServerID == 0 && (conns[i].Protocol == "" || models.NormalizeProtocol(conns[i].Protocol) == "awg") {
			if latestLB == nil || conns[i].CreatedAt.After(latestLB.CreatedAt) {
				latestLB = &conns[i]
			}
		}
	}
	if latestLB != nil {
		return latestLB
	}

	return nil
}

func saveOrUpdateAWGConnection(ctx context.Context, db *database.DB, user *models.User, awgConn *models.UserConnection, clientPub string, clientParams map[string]any) error {
	if awgConn != nil {
		updates := map[string]any{
			"client_id": clientPub,
		}
		if clientParams != nil {
			updates["client_params"] = clientParams
		}
		updated, err := db.UpdateConnection(ctx, awgConn.ID, updates)
		if err != nil {
			return err
		}
		if !updated {
			return errors.New("connection was removed")
		}
		return nil
	}

	conns, err := db.GetConnectionsByUserID(ctx, user.ID)
	if err != nil {
		return err
	}
	if len(conns) > 0 {
		// User already has connections; do not silently auto-create phantom <username>-awg connection.
		return errors.New("no load balancer connection exists for user with existing connections")
	}

	newConn := &models.UserConnection{
		UserID:       user.ID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     clientPub,
		Name:         fmt.Sprintf("%s-awg", user.Username),
		AWGMimicry:   models.AWGMimicryAuto,
		ClientParams: clientParams,
	}
	_, err = db.CreateConnection(ctx, newConn)
	return err
}

func getTimingParam(m map[string]any, key string) *awg.TimingRange {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	tr, err := awg.ParseTimingRange(v)
	if err != nil || tr == nil {
		return nil
	}
	if tr.Lo <= 0 || tr.Hi <= 0 {
		return nil
	}
	return tr
}

func getStringParam(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}
