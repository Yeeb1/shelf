#!/bin/bash

# The Shelf - Installation Script
# Usage: bash <(curl -s https://raw.githubusercontent.com/Yeeb1/shelf/main/setup/install.sh)
# Or: ./setup/install.sh

set -euo pipefail

# Configuration
REPO_OWNER="Yeeb1"
REPO_NAME="shelf"
REPO_BRANCH="main"
RAW_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}"

# Directories
INSTALL_BASE="${HOME}/.local/shelf"
BIN_DIR="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.config/shelf"
BACKUP_DIR="${INSTALL_BASE}/backups"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[*]${NC} $1"; }
log_ok() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_err() { echo -e "${RED}[-]${NC} $1"; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

# Check dependencies
check_deps() {
    log_info "Checking dependencies..."
    local missing=()

    for cmd in curl python3; do
        if ! command_exists "$cmd"; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_err "Missing: ${missing[*]}"
        return 1
    fi

    log_ok "Dependencies OK"
}

# Create directories
setup_dirs() {
    log_info "Setting up directories..."
    mkdir -p "$INSTALL_BASE" "$BIN_DIR" "$CONFIG_DIR" "$BACKUP_DIR"

    # Add to PATH if needed
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "${HOME}/.bashrc" 2>/dev/null || true
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "${HOME}/.zshrc" 2>/dev/null || true
        log_warn "Added $BIN_DIR to PATH"
    fi

    log_ok "Directories ready"
}

# Download file from repo
download() {
    local src="$1"
    local dst="$2"
    mkdir -p "$(dirname "$dst")"
    curl -sSf "${RAW_URL}/${src}" -o "$dst" || return 1
}

# Download configs
setup_config() {
    log_info "Setting up zsh configuration..."

    # Backup existing zshrc
    if [ -f "${HOME}/.zshrc" ]; then
        cp "${HOME}/.zshrc" "${BACKUP_DIR}/.zshrc.backup.$(date +%s)"
        log_ok "Backed up .zshrc"
    fi

    # Download config files
    download "configs/.zsh_alias.sh" "${CONFIG_DIR}/.zsh_alias.sh"
    download "configs/.zsh_functions.sh" "${CONFIG_DIR}/.zsh_functions.sh"
    download "configs/.zshrc" "${CONFIG_DIR}/.zshrc.shelf"
    log_ok "Downloaded configs"

    # Add sourcing to zshrc if not present
    if ! grep -q "shelf.*alias" "${HOME}/.zshrc" 2>/dev/null; then
        cat >> "${HOME}/.zshrc" << 'EOF'

# Ensure ~/.local/bin is in PATH
export PATH="$HOME/.local/bin:$PATH"

# The Shelf Configuration
[ -f "${HOME}/.config/shelf/.zsh_alias.sh" ] && source "${HOME}/.config/shelf/.zsh_alias.sh"
[ -f "${HOME}/.config/shelf/.zsh_functions.sh" ] && source "${HOME}/.config/shelf/.zsh_functions.sh"
EOF
        log_ok "Added to .zshrc"
    fi
}

# Install Python tools
install_python_tools() {
    log_info "Installing Python tools..."

    # Ensure pipx is available
    if ! command_exists pipx; then
        log_info "Installing pipx..."
        python3 -m pip install --user pipx
        export PATH="${HOME}/.local/bin:$PATH"
    fi

    # Download dependencies.json
    local deps_file="${CONFIG_DIR}/dependencies.json"
    download "setup/dependencies.json" "$deps_file"

    log_ok "Python environment ready"
}

# Dynamically fetch files from GitHub API
fetch_github_files() {
    local dir=$1
    local local_base=$2

    # Use GitHub API to list files in a directory
    local api_url="https://api.github.com/repos/Yeeb1/shelf/contents/${dir}?ref=main"

    # Fetch file list from GitHub API using jq if available, otherwise simple grep
    local files
    if command_exists jq; then
        files=$(curl -s "$api_url" | jq -r '.[] | select(.name | test("\\.py$|\\.sh$")) | .name' 2>/dev/null)
    else
        # Fallback: extract filenames manually if jq not available
        files=$(curl -s "$api_url" | grep '"name"' | grep -oE '[a-zA-Z0-9_.-]+\.(py|sh)' | sort -u)
    fi

    local count=0
    while IFS= read -r file; do
        [ -z "$file" ] && continue

        if download "${dir}/${file}" "${local_base}/${file}"; then
            chmod +x "${local_base}/${file}"
            # Create symlink in bin for all executable files (scripts and Python tools)
            ln -sf "${local_base}/${file}" "${BIN_DIR}/${file}" 2>/dev/null || true
            ((count++))
        fi
    done <<< "$files"

    echo $count
}

# Install Python tools and shell scripts
install_tools() {
    log_info "Installing tools from GitHub..."

    local total=0

    # Download from tools/, exploits/, and ctf/ directories
    for dir in tools exploits ctf; do
        log_info "Fetching from $dir/..."
        mkdir -p "${INSTALL_BASE}/${dir}"

        local count=$(fetch_github_files "$dir" "${INSTALL_BASE}/${dir}")
        if [ "$count" -gt 0 ]; then
            log_ok "Downloaded $count files from $dir/"
            ((total += count))
        fi
    done

    log_ok "Downloaded and organized $total tools total"
}

# Create shelf management command
create_shelf_cmd() {
    log_info "Creating shelf command..."

    if ! mkdir -p "$BIN_DIR"; then
        log_err "Failed to create $BIN_DIR"
        return 1
    fi

    cat > "${BIN_DIR}/shelf" << 'EOF'
#!/bin/bash
CONFIG_DIR="${HOME}/.config/shelf"
SHELF_HOME="${HOME}/.local/shelf"
case "${1:-help}" in
    list)
        echo "[*] Shelf Tools:"
        echo ""
        echo "Python Tools (tools/):"
        find "$SHELF_HOME/tools" -maxdepth 1 -name "*.py" 2>/dev/null | xargs -I {} basename {} | sort
        echo ""
        echo "Exploits (exploits/):"
        find "$SHELF_HOME/exploits" -maxdepth 1 -name "*.py" 2>/dev/null | xargs -I {} basename {} | sort
        echo ""
        echo "Shell Scripts:"
        find "$SHELF_HOME" -maxdepth 2 -name "*.sh" 2>/dev/null | xargs -I {} basename {} | sort
        echo ""
        echo "CTF Tools (ctf/):"
        find "$SHELF_HOME/ctf" -maxdepth 1 -name "*.py" 2>/dev/null | xargs -I {} basename {} | sort
        ;;
    aliases)
        echo "[*] Available aliases:"
        grep '^alias ' "$CONFIG_DIR/.zsh_alias.sh" 2>/dev/null | sed 's/alias //'
        ;;
    functions)
        echo "[*] Available functions:"
        grep '^function ' "$CONFIG_DIR/.zsh_functions.sh" 2>/dev/null | awk '{print $2}' | sed 's/()//'
        ;;
    update)
        bash <(curl -s https://raw.githubusercontent.com/Yeeb1/shelf/main/setup/install.sh)
        ;;
    backup)
        echo "[*] Backups:"
        ls -lh "$SHELF_HOME/backups/" 2>/dev/null || echo "No backups found"
        ;;
    *)
        echo "The Shelf - Tool Management"
        echo "Usage: shelf <command>"
        echo "Commands: list, aliases, functions, update, backup, help"
        ;;
esac
EOF

    if [ ! -f "${BIN_DIR}/shelf" ]; then
        log_err "Failed to create shelf command"
        return 1
    fi

    chmod +x "${BIN_DIR}/shelf"
    log_ok "Created shelf command at ${BIN_DIR}/shelf"
}

# Main
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════╗"
    echo "║    The Shelf - Installer     ║"
    echo "╚══════════════════════════════╝"
    echo -e "${NC}"

    check_deps || exit 1
    setup_dirs
    setup_config
    install_python_tools
    install_tools
    create_shelf_cmd

    echo ""
    log_ok "Installation complete!"
    echo "Run: exec zsh"
    echo "Then: shelf list"
}

main "$@"
