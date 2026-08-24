#!/usr/bin/env bash
#
# deploy/setup.sh — Install patchi hosted mode as a systemd service
#
# Usage: sudo bash deploy/setup.sh
#
set -euo pipefail

INSTALL_DIR="/opt/patchi"
DATA_DIR="${INSTALL_DIR}/data"
SERVICE_NAME="patchi-guard"

echo "=== Patchi v0.6.0 Hosted Mode Setup ==="
echo "    26 Security Agents · Hosted Guard"
echo ""

# 1. Create system user
if ! id -u patchi &>/dev/null; then
    echo "Creating system user 'patchi'..."
    useradd --system --no-create-home --shell /usr/sbin/nologin patchi
fi

# 2. Install patchi
echo "Installing patchi to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
SRC_DIR="$(dirname "$0")/.."
if command -v rsync &>/dev/null; then
    rsync -a --delete \
        --exclude='.git/' --exclude='.venv/' --exclude='__pycache__/' \
        --exclude='.pytest_cache/' --exclude='.ruff_cache/' --exclude='.coverage' \
        --exclude='dist/' --exclude='*.egg-info/' --exclude='build/' \
        --exclude='.vscode/' --exclude='_planning_docs/' \
        --exclude='tests/' --exclude='docs/' --exclude='files/' --exclude='files-*/' \
        --exclude='test_keys.py' --exclude='node_modules/' \
        "${SRC_DIR}/" "${INSTALL_DIR}/src/"
else
    # Fallback: use tar piped through an exclude filter
    tar -C "${SRC_DIR}" -cf - \
        --exclude='.git' --exclude='.venv' --exclude='__pycache__' \
        --exclude='.pytest_cache' --exclude='.ruff_cache' --exclude='.coverage' \
        --exclude='dist' --exclude='*.egg-info' --exclude='build' \
        --exclude='.vscode' --exclude='_planning_docs' \
        --exclude='tests' --exclude='docs' --exclude='files' --exclude='files-*' \
        --exclude='test_keys.py' --exclude='node_modules' \
        . | tar -C "${INSTALL_DIR}/src" -xf -
fi
cd "${INSTALL_DIR}/src"

python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --no-cache-dir -e .

# 3. Create data directory
mkdir -p "${DATA_DIR}/.patchi/hosted"
chown patchi:patchi "${INSTALL_DIR}"
chown -R patchi:patchi "${DATA_DIR}"

# 4. Install systemd service
echo "Installing systemd service..."
cp "$(dirname "$0")/${SERVICE_NAME}.service" /etc/systemd/system/
systemctl daemon-reload

# 5. Prompt for configuration
echo ""
echo "=== Configuration ==="
echo "Run the interactive setup:"
echo "  sudo -u patchi ${INSTALL_DIR}/venv/bin/patchi hosted init"
echo ""
echo "Then start the service:"
echo "  sudo systemctl start ${SERVICE_NAME}"
echo "  sudo systemctl enable ${SERVICE_NAME}"
echo ""
echo "View logs:"
echo "  sudo journalctl -u ${SERVICE_NAME} -f"
echo ""
echo "=== Done ==="
