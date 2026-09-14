# CI/CD Pipeline & Container Publishing Setup Guide

This document explains the setup, configuration, and operation of the automated CI/CD pipeline for **Amnezia Nexus** using GitHub Actions and GitHub Container Registry (GHCR).

---

## 1. Pipeline Architecture

The automated pipeline consists strictly of two core GitHub Actions workflows:

```
                  +-------------------------------------------------------+
                  |  Pull Request / Push to feat/**, fix/**, or main      |
                  +---------------------------+---------------------------+
                                              |
                                              v
                              +-------------------------------+
                              |    .github/workflows/ci.yml   |
                              |  - lint-and-security          |
                              |  - test (race, cover)         |
                              |  - build-matrix (amd64, arm64)|
                              +---------------+---------------+
                                              |
                               (On push to main / tag v*)
                                              |
                                              v
                            +-----------------------------------+
                            |   .github/workflows/docker.yml    |
                            |  - Multi-arch build (amd64/arm64) |
                            |  - Push to ghcr.io                |
                            |  - GHA layer caching              |
                            +-----------------+-----------------+
                                              |
                                              v
                              +-------------------------------+
                              |   Published Container Image   |
                              | ghcr.io/devops-igor/          |
                              |   amnezia-nexus:latest        |
                              +-------------------------------+
```

> [!NOTE]
> Automated continuous deployment (CD via SSH) has been deliberately removed from the CI/CD pipeline. Target server deployments are performed either manually or managed by dedicated infrastructure tooling, eliminating fragile SSH secrets in repository settings and preventing unwanted deployment side effects on code pushes.

---

## 2. GitHub Actions Workflows

### 1. Continuous Integration (`ci.yml`)
- **Triggers**: Pull requests targeting `main`, pushes to `main`, and feature/fix branches (`feat/**`, `fix/**`).
- **Jobs**:
  1. `lint-and-security`: Runs `golangci-lint`, `gosec`, and `govulncheck`.
  2. `test`: Runs the comprehensive test suite with race detector (`go test -race ./...`) and code coverage.
  3. `build-matrix`: Cross-compiles binaries for `linux/amd64` and `linux/arm64`.

### 2. Container Image Publishing (`docker.yml`)
- **Triggers**: Successful pushes to `main` and release tags (`v*`).
- **Jobs**:
  - `docker`: Builds multi-architecture container images (`linux/amd64` and `linux/arm64`) using Docker Buildx and pushes to GitHub Container Registry (`ghcr.io/devops-igor/amnezia-nexus`).
  - Employs GitHub Actions cache (`type=gha`) for fast incremental builds.
  - Automatically tags images with `latest`, branch names, commit SHAs, and release version tags.

---

## 3. GitHub Permissions Configuration

The container publishing workflow uses the built-in `GITHUB_TOKEN` for authenticating with GitHub Container Registry (`ghcr.io`).

Ensure that workflow permissions under **Repository Settings -> Actions -> General -> Workflow permissions** are set to **Read and write permissions** (or `packages: write` in the workflow file).

No third-party deployment secrets or SSH keys are required in GitHub repository settings.

---

## 4. Manual Deployment & Administration

Target hosts pull the pre-built container image published by `docker.yml`. All local host deployment assets reside in the `deploy/` directory:

### Production Compose File (`deploy/docker-compose.prod.yaml`)
Standardized configuration for `amnezia-panel`:
- Image: `ghcr.io/devops-igor/amnezia-nexus:latest`
- Runs as `user: root` with `cap_add: [NET_ADMIN]` for userspace TUN socket & WireGuard interface management.
- Mounts `/dev/net/tun`.
- Exposes port `8080:5000` (Web UI & REST API) and `51820:51820/udp` (AmneziaWG endpoint).
- Persistent volume `panel-data` mounted at `/app/data`.

### Host Deployment Script (`deploy/deploy-dev.sh`)
Optional local administration script for host-side updates:
1. Inspects and saves current active image ID/tag.
2. Authenticates to GHCR if `GHCR_TOKEN` is provided.
3. Pulls target container image.
4. Executes `docker compose up -d --force-recreate`.
5. Verifies health endpoint (`http://localhost:8080/api/health`) and VPN listener status.
6. Automatically rolls back to the previous image tag if health verification fails.

---

## 5. Host Administration Commands

```bash
# Pull latest published image from GHCR
docker pull ghcr.io/devops-igor/amnezia-nexus:latest

# Start or restart container using compose
cd /path/to/amnezia-deploy
docker compose -f docker-compose.prod.yaml up -d --force-recreate

# Inspect container status & logs
docker ps -a --filter name=amnezia-panel
docker logs --tail 100 -f amnezia-panel

# Verify API health endpoint
curl -i http://localhost:8080/api/health

# Manual rollback to a specific previous release / SHA
AMNEZIA_IMAGE=ghcr.io/devops-igor/amnezia-nexus:<TAG_OR_SHA> docker compose -f docker-compose.prod.yaml up -d --force-recreate
```
