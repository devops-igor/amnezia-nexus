// awg-preflight audits durable portal identity without starting the VPN service.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// Exit codes: 0 = database preflight passes, 1 = validation blocks migration,
// 2 = usage, secret input, schema, or database access failure.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("awg-preflight", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("db", "", "existing SQLite database path (opened read-only)")
	secretFile := flags.String("secret-key-file", "", "existing SECRET_KEY file; otherwise use SECRET_KEY from environment")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *path == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: awg-preflight -db data/panel.db [-secret-key-file data/.secret_key]")
		return 2
	}
	secret := strings.TrimSpace(os.Getenv("SECRET_KEY"))
	if *secretFile != "" {
		data, err := os.ReadFile(*secretFile)
		if err != nil {
			fmt.Fprintln(stderr, "cannot read SECRET_KEY file")
			return 2
		}
		secret = strings.TrimSpace(string(data))
	}
	if secret == "" {
		fmt.Fprintln(stderr, "supply existing SECRET_KEY via environment or -secret-key-file; preflight never generates a key")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	report, err := database.AuditAWGMigration(ctx, *path, secret, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(stderr, "cannot write preflight report")
		return 2
	}
	if !report.Ready {
		return 1
	}
	return 0
}
