export GOFLAGS ?= -tags=with_utls

.PHONY: all build test test-race test-e2e lint gosec govulncheck security clean fmt vet check docker-build docker-scan

APP_NAME := panel
BIN_DIR := bin
CMD_DIR := cmd/panel

all: check build

build:
	@mkdir -p $(BIN_DIR)
	go build -tags with_utls -trimpath -ldflags="-s -w" -o $(BIN_DIR)/$(APP_NAME) ./$(CMD_DIR)

test:
	go test -tags with_utls -v ./...

test-race:
	go test -tags with_utls -race -v ./...

test-e2e:
	./scripts/run_e2e.sh

lint:
	PATH=$$PATH:$$HOME/go/bin:/usr/local/go/bin golangci-lint run ./...

gosec:
	PATH=$$PATH:$$HOME/go/bin:/usr/local/go/bin gosec -tags with_utls -quiet ./...

govulncheck:
	-PATH=$$PATH:$$HOME/go/bin:/usr/local/go/bin govulncheck ./...

security: gosec govulncheck

fmt:
	go fmt ./...

vet:
	go vet -tags with_utls ./...

clean:
	rm -rf $(BIN_DIR)

check: fmt vet lint security test-race

docker-build:
	docker build -t amnezia-web-panel:latest -f ../Dockerfile ..

docker-scan:
	docker build -t amnezia-nexus:local .
	trivy image --severity HIGH,CRITICAL amnezia-nexus:local

docker-run:
	docker run --rm -p 5000:5000 -p 51820:51820/udp amnezia-web-panel:latest
