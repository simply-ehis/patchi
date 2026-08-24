---
id: iac-security-v1
name: Infrastructure-as-Code Security
version: 1.0.0
target_agents: [IaCScannerAgent, ContainerScannerAgent, ConfigAuditAgent, PolicyEngineAgent, GovernanceAgent]
cwe: [CWE-250, CWE-269, CWE-284, CWE-362, CWE-732, CWE-778, CWE-1104]
owasp: [A04:2021, A05:2021, A08:2021]
confidence_boost: 0.12
---

# IaC Security Detection Patterns

## Dockerfile Security

### Privileged Mode
```dockerfile
# DANGEROUS
RUN --privileged
# or
--privileged
```
→ **action: fix_code** — remove `--privileged`, add specific capabilities.

### Root User
```dockerfile
# DANGEROUS — no USER directive
# or:
USER root
```
→ **action: fix_code** — add `USER appuser` with non-root UID >= 1000. Expect `RUN addgroup -S appuser && adduser -S appuser -G appuser` before USER.

### Unpinned Base Image
```dockerfile
FROM python:latest
FROM node:alpine
FROM ubuntu:22.04  # OK — semver pinned
```
→ If no minor/patch pin (`3.9` not `3.9.19`) → **confidence: 0.5**. Pin to SHA256 digest for production.

### apt-get Without --no-install-recommends
```dockerfile
RUN apt-get update && apt-get install -y curl vim
```
→ **action: fix_code** — add `--no-install-recommends && rm -rf /var/lib/apt/lists/*`

### Exposed Port Without Health Check
```dockerfile
EXPOSE 80
```
→ Missing `HEALTHCHECK` instruction → **confidence: 0.3** (LOW). Add `HEALTHCHECK --interval=30s --timeout=3s ...`

### COPY (not ADD) of Untrusted Content
```dockerfile
ADD https://example.com/script.sh /tmp/
```
→ **action: fix_code** — use `COPY` for local files; use `RUN curl -fsSL ...` with checksum verification for remote.

## Docker Compose Security

### Container in Privileged Mode
```yaml
services:
  web:
    privileged: true
```
→ **action: fix_code** → set `privileged: false`, add `cap_add: [...]` for needed capabilities.

### Port Binding to 0.0.0.0
```yaml
ports:
  - "5432:5432"  # binds 0.0.0.0:5432
```
→ **action: patch_config** → `"127.0.0.1:5432:5432"` to bind loopback only.

### Volume Mounts Overriding System Directories
```yaml
volumes:
  - /etc:/etc  # host /etc mounted into container
```
→ **action: escalate** — risk of container escaping config manipulation.

### No Restart Policy
```yaml
services:
  web:
    image: web:latest
    # missing restart:
```
→ Add `restart: unless-stopped` for production services.

## Kubernetes Security

### Privileged Container
```yaml
securityContext:
  privileged: true
```
→ **action: fix_code** → remove privileged, add granular `capabilities`.

### Run As Root
```yaml
securityContext:
  runAsNonRoot: false  # or missing
```
→ **action: fix_code** → `runAsNonRoot: true`, set `runAsUser: 1000`.

### Host Network / PID / IPC
```yaml
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
```
→ Any of these → **action: escalate** (requires justification).

### Container with Latest Tag
```yaml
image: myapp:latest
image: myapp:dev
```
→ **action: fix_code** → pin to semantic version or SHA256 digest.

### Secrets as Env Vars
```yaml
env:
  - name: DB_PASSWORD
    value: "supersecret"
```
→ **action: fix_code** → use `valueFrom.secretKeyRef`.

### Security Context Missing
```yaml
spec:
  containers:
    - name: web
      # no securityContext
```
→ Add `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`.

## Terraform Security

### S3 Bucket Without Encryption
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  # no server_side_encryption_configuration
}
```
→ **action: fix_code** — add `server_side_encryption_configuration` with `aws:kms`.

### S3 Bucket Public Access
```hcl
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
```
→ Any `false` → **action: fix_code** → set all to `true`.

### Security Group Ingress 0.0.0.0/0
```hcl
ingress {
  cidr_blocks = ["0.0.0.0/0"]
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
}
```
→ **action: fix_code** → restrict to specific IP range. SSH specifically → confidence 0.9.

### IAM Policy With Wildcard Action
```hcl
action = ["s3:*", "ec2:*", "*"]
```
→ **action: escalate** — principle of least privilege violation.

### Unencrypted RDS Instance
```hcl
resource "aws_db_instance" "db" {
  storage_encrypted = false
}
```
→ **action: fix_code** → `storage_encrypted = true`.

### EBS Volume Without Encryption
```hcl
resource "aws_ebs_volume" "data" {
  encrypted = false
}
```
→ **action: fix_code** → `encrypted = true`.

## Multi-Agent Cross-Correlation
- `IaCScannerAgent` + `ContainerScannerAgent` on same Dockerfile → confidence += 0.15
- `ConfigAuditAgent` confirms misconfig → confidence += 0.2
- `GovernanceAgent` matches policy violation → confidence += 0.25
