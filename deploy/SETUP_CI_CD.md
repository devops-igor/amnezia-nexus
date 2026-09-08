# CI/CD Pipeline & Deployment Automation Setup Guide

This document explains the setup, configuration, and operation of the automated CI/CD pipeline for **Amnezia Nexus** using GitHub Actions and GitHub Container Registry (GHCR).

---

## 1. Pipeline Architecture

The pipeline consists of three automated GitHub Actions workflows:

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
                               (On docker.yml success on main)
                                              |
                                              v
                            +-----------------------------------+
                            |   .github/workflows/cd-dev.yml    |
                            |  Dual-Mode Deployment:            |
                            |  Option A: Self-hosted runner     |
                            |  Option B: Remote SSH deploy      |
                            |  - Recreates container            |
                            |  - Polls health (60s limit)       |
                            |  - Auto-rollback on failure       |
                            +-----------------------------------+
```

---

## 2. GitHub Secrets & Variables Configuration

Navigate to **Repository Settings -> Secrets and variables -> Actions** to configure the required credentials.

### Required Secrets for Remote SSH Deployment (Option B)

| Secret Name | Description | Example Value |
|---|---|---|
| `DEV_HOST` | IP address or hostname of the DEV server | `192.168.1.100` (or Tailscale IP / VPN hostname) |
| `DEV_USER` | Linux SSH username on the DEV server | `igor` |
| `DEV_SSH_KEY` | Private SSH key authorized for `DEV_USER` | `-----BEGIN OPENSSH PRIVATE KEY-----...` |
| `DEV_PORT` | SSH port (optional, defaults to `22`) | `22` |

> [!NOTE]
> The workflow automatically uses the built-in `GITHUB_TOKEN` for authenticating with GitHub Container Registry (`ghcr.io`). Ensure that workflow permissions under **Settings -> Actions -> General -> Workflow permissions** are set to **Read and write permissions**.

### Optional Variables

Under **Repository Settings -> Secrets and variables -> Actions -> Variables**:

| Variable Name | Description | Values | Default |
|---|---|---|---|
| `DEPLOY_MODE` | Preferred deployment mode for automated triggers | `ssh` or `self-hosted` | `ssh` |

---

## 3. Option A: Self-Hosted Runner Setup (Recommended for Private LAN)

When the DEV host is on a private subnet (e.g. `192.168.1.100`) without public inbound ports or VPN routing, running a lightweight GitHub Actions runner directly on the DEV host avoids exposing any ports.

### Step-by-Step Installation on ARM64 Linux / Raspberry Pi

1. SSH into the DEV server:
   ```bash
   ssh igor@192.168.1.100
   ```

2. Create a dedicated directory for the runner:
   ```bash
   mkdir -p ~/actions-runner && cd ~/actions-runner
   ```

3. Download the latest ARM64 runner package:
   ```bash
   curl -o actions-runner-linux-arm64.tar.gz -L https://github.com/actions/runner/releases/download/v2.321.0/actions-runner-linux-arm64-2.321.0.tar.gz
   tar xzf actions-runner-linux-arm64.tar.gz
   ```

4. Configure the runner with required labels (`[self-hosted, linux, arm64, dev]`):
   ```bash
   # Retrieve a registration token from:
   # Repository -> Settings -> Actions -> Runners -> New self-hosted runner
   ./config.sh --url https://github.com/devops-igor/amnezia-nexus \
               --token <REGISTRATION_TOKEN> \
               --name "dev-server-pi" \
               --labels "self-hosted,linux,arm64,dev" \
               --work "_work" \
               --unattended
   ```

5. Install and start the runner as a systemd service:
   ```bash
   sudo ./svc.sh install
   sudo ./svc.sh start
   sudo ./svc.sh status
   ```

6. Verify that `docker` and `docker compose` are accessible to the runner user (`igor`):
   ```bash
   docker --version
   docker compose version
   # Ensure user is in the docker group:
   sudo usermod -aG docker igor
   ```

7. In GitHub repository variables, set `DEPLOY_MODE` to `self-hosted`.

---

## 4. Option B: SSH Deploy Setup (For Runners with Network Route)

If the runner can reach the DEV server via Tailscale, VPN tunnel, or public IP:

1. Generate a dedicated deploy key pair:
   ```bash
   ssh-keygen -t ed25519 -C "github-actions-deploy@amnezia-nexus" -f ~/.ssh/gh_deploy_key
   ```

2. Add the public key (`~/.ssh/gh_deploy_key.pub`) to `~/.ssh/authorized_keys` on `igor@192.168.1.100`.

3. Add the private key (`~/.ssh/gh_deploy_key`) content as the `DEV_SSH_KEY` secret in GitHub.

4. Add `DEV_HOST` (`192.168.1.100` or VPN IP) and `DEV_USER` (`igor`) as repository secrets.

---

## 5. Deployment Artifacts

All deployment assets reside in the `deploy/` directory:

- **`deploy/docker-compose.prod.yaml`**:
  Standardized production configuration for `amnezia-panel`:
  - Image: `ghcr.io/devops-igor/amnezia-nexus:latest`
  - Runs as `user: root` with `cap_add: [NET_ADMIN]` for userspace TUN socket & WireGuard interface management.
  - Mounts `/dev/net/tun`.
  - Exposes port `8080:5000` (Web UI & REST API) and `51820:51820/udp` (AmneziaWG endpoint).
  - Persistent volume `panel-data` mounted at `/app/data`.

- **`deploy/deploy-dev.sh`**:
  Idempotent deployment script that:
  1. Inspects and saves the current active image ID/tag.
  2. Authenticates to GHCR if `GHCR_TOKEN` is set.
  3. Pulls the target container image.
  4. Runs `docker compose up -d --force-recreate`.
  5. Enters a 60-second polling loop verifying:
     - `http://localhost:8080/api/health` returns HTTP `200`
     - `http://localhost:8080/api/vpn/status` reports `"listener_running": true` (or verified via container runtime logs)
  6. Automatically rolls back to the previous image tag if health verification fails.

---

## 6. Manual Execution & Testing

### Trigger CI Workflow Manually
1. Go to **Actions -> Continuous Integration**.
2. Click **Run workflow**, select the target branch, and click **Run workflow**.

### Trigger Docker Multi-Arch Build Manually
1. Go to **Actions -> Docker Build & Push**.
2. Click **Run workflow** on `main`.

### Trigger Deployment Manually
1. Go to **Actions -> Continuous Deployment (DEV)**.
2. Click **Run workflow**.
3. Select:
   - `deploy_mode`: `ssh` or `self-hosted`
   - `image_tag`: tag or SHA to deploy (defaults to `latest`)
4. Click **Run workflow**.

---

## 7. Manual Rollback & Troubleshooting

If a container deployment needs manual inspection on the DEV host:

```bash
# Check container status
docker ps -a --filter name=amnezia-panel

# Inspect container logs
docker logs --tail 100 -f amnezia-panel

# Verify health endpoint
curl -i http://localhost:8080/api/health

# Verify VPN status endpoint
curl -s http://localhost:8080/api/vpn/status

# Roll back manually to a specific image tag
cd ~/amnezia-deploy
AMNEZIA_IMAGE=ghcr.io/devops-igor/amnezia-nexus:<PREVIOUS_SHA> docker compose -f docker-compose.prod.yaml up -d --force-recreate
```
