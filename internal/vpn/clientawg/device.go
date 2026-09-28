package clientawg

import (
	"encoding/hex"
	"errors"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

var (
	ErrPacketTooLarge = errors.New("clientawg: packet exceeds configured MTU")
	ErrClosed         = errors.New("clientawg: device is closed")
	ErrPeerExists     = errors.New("clientawg: peer already exists")
	ErrPeerNotFound   = errors.New("clientawg: peer does not exist")
)

// ClientAWGDevice owns exactly one upstream engine and VirtualTUN. Its lock
// serializes peer mutations, status and shutdown, never blocking plaintext reads.
// Protocol sessions, replay state, timers and roaming remain upstream-owned.
type ClientAWGDevice struct {
	mu        sync.Mutex
	dev       *device.Device
	tun       *virtualtun.VirtualTUN
	publicKey string
	mtu       int
	peers     map[string]Peer
	closed    bool
}

// NewDevice validates the whole snapshot, configures identity, obfuscation and
// peers while the engine is down, then opens its listener. Failure closes all
// owned resources. Upstream errors are intentionally sanitized: IPC errors can
// contain secret configuration values.
func NewDevice(cfg Config) (*ClientAWGDevice, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	vtun, err := virtualtun.New(cfg.TUN)
	if err != nil {
		return nil, errors.New("clientawg: cannot create virtual TUN")
	}
	dev := device.NewDevice(vtun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet(cfg.ipc()); err != nil {
		dev.Close()
		return nil, errors.New("clientawg: upstream configuration failed")
	}
	d := &ClientAWGDevice{dev: dev, tun: vtun, publicKey: cfg.PublicKey, mtu: cfg.TUN.MTU, peers: make(map[string]Peer, len(cfg.Peers))}
	for _, peer := range cfg.Peers {
		d.peers[peer.PublicKey] = peer
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, errors.New("clientawg: upstream listener startup failed")
	}
	return d, nil
}

// AddPeer authorizes a new identity; neither existing keys nor assigned IPs can
// be reassigned implicitly. Callers remain responsible for policy eligibility.
func (d *ClientAWGDevice) AddPeer(peer Peer) error { return d.setPeer(peer, false) }

// UpdatePeer replaces the assigned IP of an existing identity. It cannot steal
// another peer's address. Upstream retains ownership of the peer's protocol state.
func (d *ClientAWGDevice) UpdatePeer(peer Peer) error { return d.setPeer(peer, true) }

func (d *ClientAWGDevice) setPeer(peer Peer, update bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}
	if err := validatePeer(peer, d.publicKey); err != nil {
		return err
	}
	_, exists := d.peers[peer.PublicKey]
	if update && !exists {
		return ErrPeerNotFound
	}
	if !update && exists {
		return ErrPeerExists
	}
	for key, p := range d.peers {
		if key != peer.PublicKey && p.AllowedIP == peer.AllowedIP {
			return errors.New("clientawg: assigned IP already belongs to another peer")
		}
	}
	if err := d.dev.IpcSet(peerIPC(peer)); err != nil {
		return errors.New("clientawg: upstream peer update failed")
	}
	d.peers[peer.PublicKey] = peer
	return nil
}

// RemovePeer removes protocol state and the allowed address. Repeated removal
// returns ErrPeerNotFound; malformed keys never reach the upstream IPC parser.
func (d *ClientAWGDevice) RemovePeer(publicKey string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}
	key, err := decodeKey(publicKey)
	if err != nil {
		return err
	}
	if _, exists := d.peers[publicKey]; !exists {
		return ErrPeerNotFound
	}
	if err := d.dev.IpcSet("public_key=" + hex.EncodeToString(key) + "\nremove=true\n"); err != nil {
		return errors.New("clientawg: upstream peer removal failed")
	}
	delete(d.peers, publicKey)
	return nil
}

// Close is idempotent. It waits for upstream shutdown and unblocks plaintext
// receivers through the engine-owned VirtualTUN closure.
func (d *ClientAWGDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		d.dev.Close()
	}
	return nil
}

// ReceiveOutbound returns an authenticated plaintext packet from a client.
// Close interrupts blocked receivers with virtualtun.ErrClosed.
func (d *ClientAWGDevice) ReceiveOutbound() ([]byte, error) { return d.tun.ReceiveOutbound() }

// InjectInbound queues a plaintext packet for upstream destination lookup,
// encryption and delivery to a client. The packet is copied before return.
func (d *ClientAWGDevice) InjectInbound(packet []byte) error {
	if len(packet) > d.mtu {
		d.tun.RecordDrop()
		return ErrPacketTooLarge
	}
	return d.tun.InjectInbound(packet)
}

// Stats reports bounded queue depths and loss accounting, including after Close.
func (d *ClientAWGDevice) Stats() virtualtun.StatsSnapshot { return d.tun.Stats() }
