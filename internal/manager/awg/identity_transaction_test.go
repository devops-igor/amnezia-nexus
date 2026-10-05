package awg

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityTransactionCompensationStates(t *testing.T) {
	for _, stage := range []string{"post-apply", "apply-artifacts", "restore-copy", "restore-strip", "restore-sync", "restore-artifacts"} {
		t.Run(stage, func(t *testing.T) {
			oldPriv, oldPub := identityTestKeypair(t, 110)
			newPriv, newPub := identityTestKeypair(t, 111)
			f := newIdentityFixture(oldPriv, oldPub, true)
			base := f.handle
			injected := errors.New("fixture transaction failure")
			compensating := false
			calledPostApply := false
			artifactCalls := 0
			f.sudoCmdHandler = func(cmd string) (string, string, int, error) {
				artifact := strings.Contains(cmd, "bash -c") && strings.Contains(cmd, serverPublicKeyArtifactPath)
				if artifact {
					artifactCalls++
				}
				fail := stage == "apply-artifacts" && artifactCalls == 1 && artifact
				if compensating {
					fail = fail || (stage == "restore-copy" && strings.HasPrefix(cmd, "docker cp ")) ||
						(stage == "restore-strip" && strings.Contains(cmd, " strip ")) ||
						(stage == "restore-sync" && strings.Contains(cmd, "syncconf")) ||
						(stage == "restore-artifacts" && artifact)
				}
				if fail {
					compensating = true
					return "", "fixture transaction failure", 1, injected
				}
				return base(cmd)
			}
			m := NewAWGManager(&mockAWGSSHProvider{client: f.mockAWGSSHClient})
			err := m.WriteConfigurationWithPostApply(context.Background(), identityServer(), identityServerConfig(newPriv), func(context.Context) error {
				calledPostApply = true
				compensating = true
				return injected
			})
			if !errors.Is(err, injected) {
				t.Fatal("transaction lost causal identity", err)
			}
			wantRollbackFailed := strings.HasPrefix(stage, "restore-")
			if errors.Is(err, ErrConfigurationRollbackFailed) != wantRollbackFailed {
				t.Fatal("incorrect rollback classification", err)
			}
			if stage == "apply-artifacts" && calledPostApply {
				t.Fatal("artifact failure committed caller state")
			}
			diskKey := interfacePrivateKey(string(f.files["/opt/amnezia/awg/awg0.conf"]))
			wantDisk, wantLive, wantArtifact := oldPriv, oldPub, oldPub
			switch stage {
			case "restore-copy":
				wantDisk, wantLive, wantArtifact = newPriv, newPub, newPub
			case "restore-strip", "restore-sync":
				wantLive, wantArtifact = newPub, newPub
			case "restore-artifacts":
				wantArtifact = newPub
			}
			if diskKey != wantDisk || f.livePublicKey != wantLive || string(f.files[serverPublicKeyArtifactPath]) != wantArtifact {
				t.Fatal("disk, runtime and artifact states do not match compensated transaction")
			}
		})
	}
}

func TestIdentityArtifactsPrivateBeforeWriteAndChecked(t *testing.T) {
	for _, state := range []string{"new", "existing-permissive", "blocked-private", "blocked-public"} {
		t.Run(state, func(t *testing.T) {
			h := newShellHarness(t)
			privatePath := filepath.Join(h.cfgDir, "wireguard_server_private_key.key")
			publicPath := filepath.Join(h.cfgDir, "wireguard_server_public_key.key")
			switch state {
			case "existing-permissive":
				if err := os.WriteFile(privatePath, []byte("old fixture"), 0644); err != nil {
					t.Fatal(err)
				}
			case "blocked-private":
				if err := os.Mkdir(privatePath, 0755); err != nil {
					t.Fatal(err)
				}
			case "blocked-public":
				if err := os.Mkdir(publicPath, 0755); err != nil {
					t.Fatal(err)
				}
			}
			c := newMockAWGSSHClient()
			c.sudoCmdHandler = func(cmd string) (string, string, int, error) {
				if strings.Contains(cmd, "bash -c") && strings.Contains(cmd, serverPublicKeyArtifactPath) {
					local := strings.ReplaceAll(cmd, "/opt/amnezia/awg", h.cfgDir)
					out, stderr, code := h.run(t, "umask 022; "+local)
					return out, stderr, code, nil
				}
				return c.defaultRunSudo(cmd)
			}
			oldPriv, _ := identityTestKeypair(t, 100)
			newPriv, _ := identityTestKeypair(t, 101)
			m := NewAWGManager(&mockAWGSSHProvider{client: c})
			err := m.reconcileServerIdentity(context.Background(), c, identityServer(), identityServerConfig(oldPriv), identityServerConfig(newPriv))
			blocked := strings.HasPrefix(state, "blocked-")
			if (err != nil) != blocked {
				t.Fatal("artifact write failure was masked or successful write rejected")
			}
			if state == "blocked-private" {
				if _, err := os.Stat(publicPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("public write executed after failed private write")
				}
				return
			}
			st, err := os.Stat(privatePath)
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != 0600 {
				t.Fatal("private artifact was not restricted to owner before secret write")
			}
		})
	}
}
