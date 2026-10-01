package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

func main() {
	dbPath := flag.String("db-path", "test-artifacts/runtime/panel_test.db", "Isolated SQLite DB path")
	configPath := flag.String("config-path", "test-artifacts/runtime/frozen-client.conf", "Frozen client config path")
	readyPath := flag.String("ready-path", "test-artifacts/runtime/subject.ready", "Readiness file path")
	listenPort := flag.Int("listen-port", 51820, "UDP listen port for subject engine")
	echoPort := flag.Int("echo-port", 40001, "TCP/UDP echo port")
	underlayIP := flag.String("underlay-ip", "10.254.250.1", "Underlay host IP for public endpoint")
	destIP := flag.String("dest-ip", "10.100.0.1", "Destination IP for echo services")
	engine := flag.String("engine", "upstream", "Client AWG engine (upstream)")
	reuseDB := flag.Bool("reuse-db", false, "Reuse existing database and frozen client configuration")
	flag.Parse()

	if *listenPort <= 0 || *listenPort > 65535 {
		log.Fatalf("[qualification-subject] invalid listen port: %d (must be 1-65535)", *listenPort)
	}
	if *echoPort <= 0 || *echoPort > 65535 {
		log.Fatalf("[qualification-subject] invalid echo port: %d (must be 1-65535)", *echoPort)
	}
	if *engine != "" && *engine != "upstream" {
		log.Fatalf("[qualification-subject] invalid engine: %q (upstream is the only runtime engine)", *engine)
	}

	cfg := vpn.QualificationSubjectConfig{
		DBPath:           *dbPath,
		FrozenConfigPath: *configPath,
		ReadyPath:        *readyPath,
		ListenPort:       *listenPort,
		EchoPort:         uint16(*echoPort), // #nosec G115 -- validated 1 <= *echoPort <= 65535
		UnderlayHostIP:   *underlayIP,
		DestinationIP:    *destIP,
		Engine:           *engine,
		ReuseDB:          *reuseDB,
	}

	subject, err := vpn.NewQualificationSubject(cfg)
	if err != nil {
		log.Fatalf("[qualification-subject] failed to initialize subject: %v", err)
	}
	defer func() {
		if err := subject.Stop(); err != nil {
			log.Printf("[qualification-subject] error stopping subject: %v", err)
		}
	}()

	fmt.Printf("[qualification-subject] subject ready on %s:%d, echo services on %s:%d\n", *underlayIP, *listenPort, *destIP, *echoPort)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	sig := <-sigCh
	fmt.Printf("[qualification-subject] received signal %v, shutting down cleanly...\n", sig)
}
