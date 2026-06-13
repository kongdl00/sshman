#!/bin/bash
# sshman system-wide install script
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_DIR/venv"

echo "==> sshman installer"

# 1. Create venv if not present
if [ ! -f "$VENV_DIR/bin/python3" ]; then
    echo "==> Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# 2. Install/upgrade dependencies
echo "==> Installing sshman..."
"$VENV_DIR/bin/pip" install -e "$PROJECT_DIR" --quiet

# 3. Install system-wide wrapper
echo "==> Installing /usr/local/bin/sshman..."
sudo tee /usr/local/bin/sshman > /dev/null << WRAPPER
#!/bin/bash
exec "$VENV_DIR/bin/sshman" "\$@"
WRAPPER
sudo chmod +x /usr/local/bin/sshman

# 4. Verify
echo "==> Done. Verify with: sshman --help"
"$VENV_DIR/bin/sshman" --version
