package ssh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

// SSHClient defines the contract for remote server communication via SSH and SFTP.
//
//nolint:revive
type SSHClient interface {
	RunCommand(ctx context.Context, cmd string) (stdout string, stderr string, exitCode int, err error)
	RunSudoCommand(ctx context.Context, cmd string) (stdout string, stderr string, exitCode int, err error)
	RunScript(ctx context.Context, script string) (stdout string, stderr string, exitCode int, err error)
	RunSudoScript(ctx context.Context, script string) (stdout string, stderr string, exitCode int, err error)
	UploadFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error
	UploadSudoFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error
	DownloadFile(ctx context.Context, remotePath string) ([]byte, error)
	DownloadSudoFile(ctx context.Context, remotePath string) ([]byte, error)
	FileExists(ctx context.Context, remotePath string) (bool, error)
	TestConnection(ctx context.Context) (string, error)
	Close() error
	IsAlive() bool
	GetUnderlyingClient() *gossh.Client
	GetHost() string
	GetPort() int
	GetUser() string
	GetServerID() *int64
	GetLastActive() time.Time
	InUse() bool
}

// ErrProviderAbsent reports that an SSH session was refused because the
// provider's own inventory no longer lists the server it would be opened to.
//
// It is a refusal, not a transport failure: no connection was attempted, so a
// caller must not report it as an unreachable host or record it as a health
// sample. Pool admission and subsequent operations both enforce this refusal.
var ErrProviderAbsent = errors.New("ssh refused: the provider's inventory no longer lists this server")

// Config specifies the connection parameters for an SSH client.
type Config struct {
	Host                      string
	Port                      int
	User                      string
	Password                  string
	PrivateKey                string
	Passphrase                string
	Timeout                   time.Duration
	KeepAlivePeriod           time.Duration
	ServerID                  *int64
	Store                     HostKeyStore
	RequireFingerprintConfirm bool
	HostKeyCallback           gossh.HostKeyCallback
	// ProviderAbsent carries the server row's durable provider-absence
	// observation. Every config built from a stored row sets it, and checkout
	// refuses before opening a socket when it is true.
	ProviderAbsent bool
	presenceStore  ProviderPresenceStore
}

// Client implements the SSHClient interface with pooling, sudo, and SFTP support.
type Client struct {
	cfg                 Config
	sshClient           *gossh.Client
	sftpClient          *sftp.Client
	isRoot              bool
	capturedFingerprint string
	lastActive          atomic.Int64
	activeOps           atomic.Int64
	closed              bool
	mu                  sync.Mutex
}

// NewClient initializes an unconnected Client with the given configuration.
func NewClient(cfg Config) *Client {
	cfg.Host = strings.Trim(strings.TrimSpace(cfg.Host), "[]")
	if cfg.Port <= 0 {
		cfg.Port = 22
	}
	if cfg.User == "" {
		cfg.User = "root"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.KeepAlivePeriod <= 0 {
		cfg.KeepAlivePeriod = 30 * time.Second
	}

	client := &Client{
		cfg:    cfg,
		isRoot: cfg.User == "root",
	}
	client.lastActive.Store(time.Now().UnixNano())
	return client
}

// Dial creates a new Client and immediately establishes an SSH connection.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	// One-shot connections use the same admission path as reusable connections,
	// without background workers or ownership beyond the returned client.
	pool := &SSHClientPool{conns: make(map[string]*pooledEntry)}
	return pool.getOrCreate(ctx, PoolKey(cfg.Host, cfg.Port, cfg.User), cfg)
}

// DialFromServer constructs a Client from a models.Server instance and establishes connection.
func DialFromServer(ctx context.Context, server *models.Server, store HostKeyStore) (*Client, error) {
	if server == nil {
		return nil, errors.New("server cannot be nil")
	}

	cfg := Config{
		Host:            strings.Trim(strings.TrimSpace(server.Host), "[]"),
		Port:            server.SSHPort,
		User:            server.SSHUser,
		Password:        server.SSHPass,
		PrivateKey:      server.SSHKey,
		ServerID:        &server.ID,
		Store:           store,
		Timeout:         15 * time.Second,
		KeepAlivePeriod: 30 * time.Second,
		ProviderAbsent:  server.ProviderAbsent(),
	}

	return Dial(ctx, cfg)
}

// connect establishes a transport only after pool admission.
func (c *Client) connect(ctx context.Context) error {
	// The durable observation is read outside the client lock: it reaches the
	// store, and no store I/O may run under an internal mutex. Refusing here,
	// before a socket exists, is what keeps a config snapshot taken before the
	// observation from opening a connection to a removed address.
	if err := checkProviderPresence(ctx, c.cfg); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.sshClient != nil && !c.closed {
		return nil
	}

	if c.cfg.Host == "" {
		return errors.New("host is required")
	}

	sshConfig, err := c.buildClientConfig(ctx)
	if err != nil {
		return err
	}

	host := strings.Trim(strings.TrimSpace(c.cfg.Host), "[]")
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", c.cfg.Port))

	dialer := net.Dialer{Timeout: c.cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}

	// The handshake, not just the dial, is bounded and cancellable: the
	// transport exchange happens on this socket and would otherwise wait for a
	// silent peer indefinitely. handshake takes ownership of conn.
	sshConn, chans, reqs, err := handshake(ctx, conn, addr, sshConfig, c.cfg.Timeout)
	if err != nil {
		return err
	}

	if c.sftpClient != nil {
		_ = c.sftpClient.Close()
		c.sftpClient = nil
	}

	c.sshClient = gossh.NewClient(&presenceConn{Conn: sshConn, cfg: c.cfg}, chans, reqs)
	c.closed = false
	c.lastActive.Store(time.Now().UnixNano())

	return nil
}

// buildClientConfig resolves the authentication methods and the host-key policy
// into the configuration the transport handshake uses. It is split out of Connect
// so that function stays a sequence of decisions about the connection itself.
func (c *Client) buildClientConfig(ctx context.Context) (*gossh.ClientConfig, error) {
	authMethods, err := BuildAuthMethods(c.cfg.Password, c.cfg.PrivateKey, c.cfg.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to configure authentication: %w", err)
	}

	hostKeyCB := c.cfg.HostKeyCallback
	if hostKeyCB == nil {
		hostKeyCB = NewHostKeyCallback(ctx, HostKeyCallbackOptions{
			ServerID:               c.cfg.ServerID,
			Store:                  c.cfg.Store,
			RequireConfirm:         c.cfg.RequireFingerprintConfirm,
			CapturedFingerprintOut: &c.capturedFingerprint,
		})
	}

	return &gossh.ClientConfig{
		User:            c.cfg.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCB,
		Timeout:         c.cfg.Timeout,
	}, nil
}

// getSFTP returns an initialized SFTP client instance, creating one if not present or refreshing if stale.
func (c *Client) getSFTP() (*sftp.Client, error) {
	c.mu.Lock()
	cached, transport, closed := c.sftpClient, c.sshClient, c.closed
	c.mu.Unlock()
	if closed || transport == nil {
		return nil, ErrNotConnected
	}
	if cached != nil {
		if _, err := cached.Getwd(); err == nil {
			return cached, nil
		}
		_ = cached.Close()
	}
	candidate, err := sftp.NewClient(transport)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize sftp client: %w", err)
	}
	c.mu.Lock()
	if c.closed || c.sshClient != transport {
		c.mu.Unlock()
		_ = candidate.Close()
		return nil, ErrNotConnected
	}
	if current := c.sftpClient; current != nil && current != cached {
		c.mu.Unlock()
		_ = candidate.Close()
		return current, nil
	}
	c.sftpClient = candidate
	c.mu.Unlock()
	return candidate, nil
}

// RunCommand executes a command remotely and returns stdout, stderr, and exit code.
func (c *Client) RunCommand(ctx context.Context, cmd string) (string, string, int, error) {
	ctx, err := c.operationContext(ctx)
	if err != nil {
		return "", "", -1, err
	}
	defer c.startOp()()
	c.mu.Lock()
	client := c.sshClient
	c.mu.Unlock()

	if client == nil {
		return "", "", -1, ErrNotConnected
	}

	return RunSession(ctx, client, cmd, nil)
}

// RunSudoCommand executes a command with sudo privileges, delivering passwords via stdin safely.
func (c *Client) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	ctx, err := c.operationContext(ctx)
	if err != nil {
		return "", "", -1, err
	}
	defer c.startOp()()
	cleanCmd := CleanSudoCommand(cmd)
	if c.isRoot {
		return c.RunCommand(ctx, cleanCmd)
	}

	formattedCmd, stdinInput := FormatSudoCommand(cleanCmd, c.cfg.Password, false)

	c.mu.Lock()
	client := c.sshClient
	c.mu.Unlock()

	if client == nil {
		return "", "", -1, ErrNotConnected
	}

	var stdin io.Reader
	if stdinInput != "" {
		stdin = strings.NewReader(stdinInput)
	}

	return RunSession(ctx, client, formattedCmd, stdin)
}

// RunScript executes a multi-line shell script via bash stdin.
func (c *Client) RunScript(ctx context.Context, script string) (string, string, int, error) {
	ctx, err := c.operationContext(ctx)
	if err != nil {
		return "", "", -1, err
	}
	defer c.startOp()()
	c.mu.Lock()
	client := c.sshClient
	c.mu.Unlock()

	if client == nil {
		return "", "", -1, ErrNotConnected
	}

	normalized := NormalizeLineEndings([]byte(script))
	return RunSession(ctx, client, "/bin/bash -s", strings.NewReader(string(normalized)))
}

// RunSudoScript executes a multi-line script with root privileges.
func (c *Client) RunSudoScript(ctx context.Context, script string) (string, string, int, error) {
	ctx, err := c.operationContext(ctx)
	if err != nil {
		return "", "", -1, err
	}
	defer c.startOp()()
	if c.isRoot {
		return c.RunScript(ctx, script)
	}

	// Write script to /tmp via SFTP, then execute via sudo
	h := sha256.Sum256([]byte(script))
	tmpScript := fmt.Sprintf("/tmp/_amnz_script_%s.sh", hex.EncodeToString(h[:4]))

	normContent := NormalizeLineEndings([]byte(script))
	if err := c.UploadFile(ctx, tmpScript, normContent, 0700); err != nil {
		return "", "", -1, fmt.Errorf("failed to upload sudo script to %s: %w", tmpScript, err)
	}
	defer func() {
		_, _, _, _ = c.RunSudoCommand(ctx, fmt.Sprintf("rm -f %s", EscapeShellArg(tmpScript)))
	}()

	execCmd := fmt.Sprintf("/bin/bash %s", EscapeShellArg(tmpScript))
	return c.RunSudoCommand(ctx, execCmd)
}

// UploadFile uploads content to a remote path via SFTP.
func (c *Client) UploadFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	ctx, err := c.operationContext(ctx)
	if err != nil {
		return err
	}
	defer c.startOp()()
	sftpClient, err := c.getSFTP()
	if err != nil {
		return err
	}
	return SFTPUpload(ctx, sftpClient, remotePath, content, mode)
}

// UploadSudoFile uploads content to a root-owned remote path via atomic temp write and sudo move.
func (c *Client) UploadSudoFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	ctx, err := c.operationContext(ctx)
	if err != nil {
		return err
	}
	defer c.startOp()()

	stagingDir := GenerateRandomTempPath("stage")
	// Registered before staging and bound to an independent context so a failed or
	// canceled upload still removes any partially staged secret from /tmp.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _, _, _ = c.RunSudoCommand(cleanupCtx, fmt.Sprintf("rm -rf %s", EscapeShellArg(stagingDir)))
	}()

	// Pre-create a private directory and inode so SFTP truncation never exposes the payload
	// through the server's default umask between open and chmod.
	mkdirCmd := fmt.Sprintf("umask 077 && mkdir -p %s && chmod 0700 %s", EscapeShellArg(stagingDir), EscapeShellArg(stagingDir))
	if _, _, code, err := c.RunCommand(ctx, mkdirCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to create secure staging directory %s (code %d): %w", stagingDir, code, err)
	}

	tmpPath := path.Join(stagingDir, "payload")
	precreateCmd := fmt.Sprintf("umask 077 && install -m 0600 /dev/null %s", EscapeShellArg(tmpPath))
	if _, _, code, err := c.RunCommand(ctx, precreateCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to pre-create secure staging file %s (code %d): %w", tmpPath, code, err)
	}

	if err := c.UploadFile(ctx, tmpPath, content, 0600); err != nil {
		return fmt.Errorf("failed to upload temporary file: %w", err)
	}

	targetDir := path.Dir(remotePath)
	if _, _, code, err := c.RunSudoCommand(ctx, fmt.Sprintf("mkdir -p %s", EscapeShellArg(targetDir))); err != nil || code != 0 {
		return fmt.Errorf("failed to create target directory %s (code %d): %w", targetDir, code, err)
	}

	mvCmd := fmt.Sprintf("mv %s %s", EscapeShellArg(tmpPath), EscapeShellArg(remotePath))
	if _, stderr, code, err := c.RunSudoCommand(ctx, mvCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to move file to %s (code %d, err: %s): %w", remotePath, code, stderr, err)
	}

	chmodCmd := fmt.Sprintf("chmod %o %s", mode.Perm(), EscapeShellArg(remotePath))
	if _, stderr, code, err := c.RunSudoCommand(ctx, chmodCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to chmod file %s (code %d, err: %s): %w", remotePath, code, stderr, err)
	}

	chownCmd := fmt.Sprintf("chown root:root %s", EscapeShellArg(remotePath))
	if _, stderr, code, err := c.RunSudoCommand(ctx, chownCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to chown file %s (code %d, err: %s): %w", remotePath, code, stderr, err)
	}

	return nil
}

// DownloadFile downloads the complete content of a remote file via SFTP.
func (c *Client) DownloadFile(ctx context.Context, remotePath string) ([]byte, error) {
	ctx, err := c.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	defer c.startOp()()
	sftpClient, err := c.getSFTP()
	if err != nil {
		return nil, err
	}
	return SFTPDownload(ctx, sftpClient, remotePath)
}

// DownloadSudoFile downloads a root-owned remote file, elevating reads for non-root SSH users.
func (c *Client) DownloadSudoFile(ctx context.Context, remotePath string) ([]byte, error) {
	ctx, err := c.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	if c.isRoot {
		return c.DownloadFile(ctx, remotePath)
	}

	stdout, stderr, code, err := c.RunSudoCommand(ctx, fmt.Sprintf("cat %s", EscapeShellArg(remotePath)))
	if err != nil {
		return nil, fmt.Errorf("failed to download sudo file %s: %w", remotePath, err)
	}
	if code != 0 {
		return nil, fmt.Errorf("failed to download sudo file %s (code %d): %s", remotePath, code, stderr)
	}
	return []byte(stdout), nil
}

// FileExists checks if a remote file or directory exists via SFTP.
func (c *Client) FileExists(ctx context.Context, remotePath string) (bool, error) {
	ctx, err := c.operationContext(ctx)
	if err != nil {
		return false, err
	}
	defer c.startOp()()
	sftpClient, err := c.getSFTP()
	if err != nil {
		return false, err
	}
	return SFTPFileExists(ctx, sftpClient, remotePath)
}

// TestConnection verifies connectivity and returns OS and kernel details.
func (c *Client) TestConnection(ctx context.Context) (string, error) {
	stdout, stderr, code, err := c.RunCommand(ctx, "uname -sr && cat /etc/os-release 2>/dev/null | head -2")
	if err != nil {
		return "", fmt.Errorf("connection test failed: %w", err)
	}
	if code != 0 {
		return "", fmt.Errorf("connection test returned non-zero code %d: %s", code, stderr)
	}
	return stdout, nil
}

// IsAlive checks if the SSH transport connection is alive by sending a keepalive global request.
func (c *Client) IsAlive() bool {
	alive, _ := c.alive(context.Background())
	return alive
}

// alive distinguishes a refused check from a dead transport so the pool never
// evicts an in-use connection merely because its observation became absent.
//
// The request wrapper re-reads the observation, so the refusal can arrive here
// as the keepalive's own error even when this validation's first read still saw
// the row listed. That outcome is a refusal, not a dead connection, and it is
// returned as one: maintenance parks the entry and checkout refuses it, while a
// genuine transport failure still reports the connection dead.
func (c *Client) alive(ctx context.Context) (bool, error) {
	if err := checkProviderPresence(ctx, c.cfg); err != nil {
		return false, err
	}
	c.mu.Lock()
	if c.closed || c.sshClient == nil {
		c.mu.Unlock()
		return false, nil
	}
	client := c.sshClient
	c.mu.Unlock()

	doneCh := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		doneCh <- err
	}()

	select {
	case err := <-doneCh:
		if isPresenceBlocked(err) {
			return false, err
		}
		return err == nil, nil
	case <-time.After(5 * time.Second):
		return false, nil
	}
}

// Close terminates the SFTP and SSH connections.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	sftp := c.sftpClient
	ssh := c.sshClient
	c.sftpClient = nil
	c.sshClient = nil
	c.mu.Unlock()

	var errs []error
	if ssh != nil {
		if err := ssh.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if sftp != nil {
		if err := sftp.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// GetUnderlyingClient returns the raw *golang.org/x/crypto/ssh.Client.
func (c *Client) GetUnderlyingClient() *gossh.Client {
	if checkProviderPresence(context.Background(), c.cfg) != nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sshClient
}

// GetHost returns the configured host address.
func (c *Client) GetHost() string {
	return c.cfg.Host
}

// GetPort returns the configured SSH port.
func (c *Client) GetPort() int {
	return c.cfg.Port
}

// GetUser returns the configured SSH username.
func (c *Client) GetUser() string {
	return c.cfg.User
}

// GetServerID returns the associated database server ID if configured.
func (c *Client) GetServerID() *int64 {
	return c.cfg.ServerID
}

// GetLastActive returns the timestamp of the last executed operation.
func (c *Client) GetLastActive() time.Time {
	return time.Unix(0, c.lastActive.Load())
}

// touch updates the last active timestamp.
func (c *Client) touch() {
	c.lastActive.Store(time.Now().UnixNano())
}

// InUse reports whether the client is currently executing commands or file operations.
func (c *Client) InUse() bool {
	return c.activeOps.Load() > 0
}

func (c *Client) startOp() func() {
	c.touch()
	c.activeOps.Add(1)
	return func() {
		c.activeOps.Add(-1)
		c.touch()
	}
}

// CapturedFingerprint returns the host key fingerprint captured during handshake.
func (c *Client) CapturedFingerprint() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.capturedFingerprint
}

// Fingerprint is an alias for CapturedFingerprint.
func (c *Client) Fingerprint() string {
	return c.CapturedFingerprint()
}
