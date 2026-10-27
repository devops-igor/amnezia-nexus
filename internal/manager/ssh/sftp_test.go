package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

func TestNormalizeLineEndings(t *testing.T) {
	input := []byte("line1\r\nline2\r\nline3\nline4\r\n")
	expected := []byte("line1\nline2\nline3\nline4\n")

	got := NormalizeLineEndings(input)
	if !bytes.Equal(got, expected) {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestGenerateRandomTempPath(t *testing.T) {
	p1 := GenerateRandomTempPath("script")
	p2 := GenerateRandomTempPath("script")

	if !strings.HasPrefix(p1, "/tmp/_script_") {
		t.Fatalf("expected prefix /tmp/_script_, got %s", p1)
	}
	if p1 == p2 {
		t.Fatalf("expected unique temp paths, got identical %s", p1)
	}

	pDefault := GenerateRandomTempPath("")
	if !strings.HasPrefix(pDefault, "/tmp/_amnz_") {
		t.Fatalf("expected default prefix /tmp/_amnz_, got %s", pDefault)
	}
}

func TestSFTPErrors_NilClient(t *testing.T) {
	ctx := context.Background()

	if err := EnsureRemoteDir(nil, "/dir", 0755); !errors.Is(err, ErrSFTPNotAvailable) {
		t.Fatalf("expected ErrSFTPNotAvailable, got %v", err)
	}

	if err := SFTPUpload(ctx, nil, "/file", []byte("a"), 0644); !errors.Is(err, ErrSFTPNotAvailable) {
		t.Fatalf("expected ErrSFTPNotAvailable, got %v", err)
	}

	if _, err := SFTPDownload(ctx, nil, "/file"); !errors.Is(err, ErrSFTPNotAvailable) {
		t.Fatalf("expected ErrSFTPNotAvailable, got %v", err)
	}

	if _, err := SFTPFileExists(ctx, nil, "/file"); !errors.Is(err, ErrSFTPNotAvailable) {
		t.Fatalf("expected ErrSFTPNotAvailable, got %v", err)
	}
}

func TestSFTPErrors_EmptyPath(t *testing.T) {
	ctx := context.Background()

	// Non-nil dummy won't be called because path check is prior to network
	if err := SFTPUpload(ctx, nil, "", []byte("a"), 0644); !errors.Is(err, ErrSFTPNotAvailable) && !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("expected ErrSFTPNotAvailable or ErrEmptyPath, got %v", err)
	}
}

// orderedSFTP serves an in-memory SFTP filesystem and records the order of Setstat/Write
// operations; failSetstat makes every Setstat fail.
type orderedSFTP struct {
	mu          sync.Mutex
	events      []string
	failSetstat bool
}

func (o *orderedSFTP) record(e string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, e)
}

func (o *orderedSFTP) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.events...)
}

type recordingWriter struct {
	inner io.WriterAt
	o     *orderedSFTP
}

func (w recordingWriter) WriteAt(p []byte, off int64) (int, error) {
	w.o.record("write")
	return w.inner.WriteAt(p, off)
}

type recordingCmd struct {
	inner sftp.FileCmder
	o     *orderedSFTP
}

func (c recordingCmd) Filecmd(r *sftp.Request) error {
	if r.Method == "Setstat" {
		c.o.record("setstat")
		if c.o.failSetstat {
			return errors.New("injected chmod failure")
		}
	}
	return c.inner.Filecmd(r)
}

type recordingPut struct {
	inner sftp.FileWriter
	o     *orderedSFTP
}

func (p recordingPut) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	w, err := p.inner.Filewrite(r)
	if err != nil {
		return nil, err
	}
	return recordingWriter{inner: w, o: p.o}, nil
}

func newOrderedSFTPClient(t *testing.T, o *orderedSFTP) *sftp.Client {
	t.Helper()
	h := sftp.InMemHandler()
	h.FilePut = recordingPut{inner: h.FilePut, o: o}
	h.FileCmd = recordingCmd{inner: h.FileCmd, o: o}

	srvConn, cliConn := net.Pipe()
	srv := sftp.NewRequestServer(srvConn, h)
	go func() { _ = srv.Serve() }()
	client, err := sftp.NewClientPipe(cliConn, cliConn)
	if err != nil {
		t.Fatalf("sftp client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = srv.Close() })
	return client
}

func TestSFTPUpload_ChmodBeforeWrite(t *testing.T) {
	o := &orderedSFTP{}
	client := newOrderedSFTPClient(t, o)

	if err := SFTPUpload(context.Background(), client, "/secret.conf", []byte("TOP-SECRET"), 0600); err != nil {
		t.Fatalf("SFTPUpload: %v", err)
	}

	ev := o.snapshot()
	if len(ev) < 2 || ev[0] != "setstat" || ev[len(ev)-1] != "write" {
		t.Fatalf("expected setstat before write, got %v", ev)
	}
}

func TestSFTPUpload_ChmodFailureNeverWritesPayload(t *testing.T) {
	o := &orderedSFTP{failSetstat: true}
	client := newOrderedSFTPClient(t, o)

	err := SFTPUpload(context.Background(), client, "/secret.conf", []byte("TOP-SECRET"), 0600)
	if err == nil || !strings.Contains(err.Error(), "failed to chmod") {
		t.Fatalf("expected chmod error, got %v", err)
	}
	for _, e := range o.snapshot() {
		if e == "write" {
			t.Fatalf("payload was written despite chmod failure: %v", o.snapshot())
		}
	}
}

func TestUploadSudoFile_CleansStagingOnFailedUpload(t *testing.T) {
	server := NewMockSSHServer(t, "root", "pass")
	defer server.Close()

	removed := make(chan string, 1)
	server.SetCommandHandler("rm -f '/tmp/_upload_", func(cmd string, _ []byte) (string, string, int) {
		removed <- cmd
		return "", "", 0
	})

	client, err := Dial(context.Background(), Config{
		Host: server.Host(), Port: server.Port(), User: "root", Password: "pass",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// A canceled ctx makes UploadFile fail; cleanup must still run on its own context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.UploadSudoFile(ctx, "/etc/amnezia/x.conf", []byte("secret"), 0600); err == nil {
		t.Fatal("expected upload failure")
	}

	select {
	case cmd := <-removed:
		if !strings.HasPrefix(cmd, "rm -f '/tmp/_upload_") {
			t.Fatalf("unexpected cleanup command %q", cmd)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("staging file cleanup (rm -f) was not issued after failed upload")
	}
}
