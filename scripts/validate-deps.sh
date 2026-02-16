#!/bin/bash

# Dependency Validator for The Shelf
# Validates that all system and Python dependencies are installed
# Usage: ./scripts/validate-deps.sh [--fix]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
DEPS_FILE="${REPO_ROOT}/dependencies.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
MISSING_SYSTEM_DEPS=()
MISSING_PYTHON_DEPS=()
MISSING_PIPX_TOOLS=()

log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_system_dependencies() {
    log_info "Checking system dependencies..."
    echo ""

    local system_deps=(
        "curl:HTTP client"
        "python3:Python 3 runtime"
        "jq:JSON processor"
        "dig:DNS lookup utility"
        "aws-cli:AWS command line tool"
        "git:Version control system"
        "pipx:Python tool installer"
        "uv:Fast Python package installer"
    )

    for dep in "${system_deps[@]}"; do
        local cmd="${dep%:*}"
        local desc="${dep#*:}"

        if command_exists "$cmd"; then
            local version=$("$cmd" --version 2>/dev/null | head -n1 || echo "installed")
            log_success "$cmd - $version"
        else
            log_warning "$cmd - NOT INSTALLED ($desc)"
            MISSING_SYSTEM_DEPS+=("$cmd")
        fi
    done

    echo ""
    if [ ${#MISSING_SYSTEM_DEPS[@]} -gt 0 ]; then
        log_error "Missing system dependencies: ${MISSING_SYSTEM_DEPS[*]}"
        return 1
    else
        log_success "All system dependencies are installed"
        return 0
    fi
}

check_python_environment() {
    log_info "Checking Python environment..."
    echo ""

    if ! command_exists python3; then
        log_error "Python3 not found"
        return 1
    fi

    local python_version=$(python3 --version)
    log_success "$python_version"

    # Check pip
    if ! python3 -m pip --version >/dev/null 2>&1; then
        log_error "pip is not available"
        return 1
    fi

    log_success "pip is available"

    # Check pipx
    if ! command_exists pipx; then
        log_warning "pipx not found"
        return 1
    fi

    log_success "pipx is installed"
    return 0
}

check_python_tool_dependencies() {
    log_info "Checking Python tool dependencies..."
    echo ""

    if [ ! -f "$DEPS_FILE" ]; then
        log_error "dependencies.json not found at $DEPS_FILE"
        return 1
    fi

    # Extract all unique Python package dependencies
    local python_deps=$(jq -r '.tools[] | select(.type == "pipx") | .dependencies[]? | select(. != null)' "$DEPS_FILE" | sort -u)

    if [ -z "$python_deps" ]; then
        log_success "No specific Python package dependencies defined"
        return 0
    fi

    log_info "Found Python package dependencies:"
    while IFS= read -r dep; do
        if python3 -c "import $dep" 2>/dev/null; then
            log_success "$dep - installed"
        else
            log_warning "$dep - NOT INSTALLED"
            MISSING_PYTHON_DEPS+=("$dep")
        fi
    done <<< "$python_deps"

    echo ""
    if [ ${#MISSING_PYTHON_DEPS[@]} -gt 0 ]; then
        log_warning "Missing Python packages: ${MISSING_PYTHON_DEPS[*]}"
        return 1
    else
        log_success "All Python dependencies are available"
        return 0
    fi
}

check_installed_tools() {
    log_info "Checking installed tools..."
    echo ""

    if [ ! -d "${HOME}/.local/bin" ]; then
        log_warning "~/.local/bin directory not found"
        return 1
    fi

    local tool_count=$(ls "${HOME}/.local/bin" 2>/dev/null | wc -l)
    log_success "Found $tool_count tools in ~/.local/bin"

    # List some installed tools
    if [ $tool_count -gt 0 ]; then
        echo "    Installed tools:"
        ls "${HOME}/.local/bin" | head -10 | while read -r tool; do
            echo "      - $tool"
        done
        if [ $tool_count -gt 10 ]; then
            echo "      ... and $((tool_count - 10)) more"
        fi
    fi

    return 0
}

check_configurations() {
    log_info "Checking configurations..."
    echo ""

    local config_dir="${HOME}/.config/shelf"

    if [ ! -d "$config_dir" ]; then
        log_warning "~/.config/shelf directory not found"
        return 1
    fi

    local config_files=(".zsh_alias.sh" ".zsh_functions.sh" ".zshrc" ".tmux.conf.local")

    for config_file in "${config_files[@]}"; do
        if [ -f "${config_dir}/${config_file}" ]; then
            log_success "$config_file found"
        else
            log_warning "$config_file NOT FOUND"
        fi
    done

    # Check if shelf configs are sourced in ~/.zshrc
    if [ -f "${HOME}/.zshrc" ]; then
        if grep -q "source.*shelf" "${HOME}/.zshrc"; then
            log_success "Shelf configurations are sourced in ~/.zshrc"
        else
            log_warning "Shelf configurations NOT sourced in ~/.zshrc"
        fi
    fi

    return 0
}

# Fix missing dependencies
fix_dependencies() {
    log_info "Attempting to fix missing dependencies..."
    echo ""

    local can_fix=true

    if [ ${#MISSING_SYSTEM_DEPS[@]} -gt 0 ]; then
        log_info "Missing system dependencies: ${MISSING_SYSTEM_DEPS[*]}"
        log_warning "Install with: sudo apt-get install ${MISSING_SYSTEM_DEPS[*]}"
        can_fix=false
    fi

    if [ ${#MISSING_PYTHON_DEPS[@]} -gt 0 ]; then
        log_info "Installing missing Python packages..."
        for dep in "${MISSING_PYTHON_DEPS[@]}"; do
            pip3 install "$dep" || log_error "Failed to install $dep"
        done
    fi

    if [ "$can_fix" = true ]; then
        log_success "All fixable dependencies have been addressed"
        return 0
    else
        log_warning "Some dependencies require manual installation"
        return 1
    fi
}

# Main validation
main() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════╗"
    echo "║   The Shelf - Dependency Validator     ║"
    echo "╚════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""

    local fix_flag=false
    if [ "${1:-}" = "--fix" ]; then
        fix_flag=true
    fi

    # Run checks
    check_system_dependencies || true
    echo ""
    check_python_environment || true
    echo ""
    check_python_tool_dependencies || true
    echo ""
    check_installed_tools || true
    echo ""
    check_configurations || true
    echo ""

    # Offer to fix if requested
    if [ "$fix_flag" = true ]; then
        fix_dependencies
    else
        if [ ${#MISSING_SYSTEM_DEPS[@]} -gt 0 ] || [ ${#MISSING_PYTHON_DEPS[@]} -gt 0 ]; then
            log_info "Run with --fix flag to attempt automatic fixes:"
            log_info "  ./scripts/validate-deps.sh --fix"
        fi
    fi

    # Summary
    echo ""
    echo -e "${BLUE}Summary:${NC}"
    echo "  System dependencies missing: ${#MISSING_SYSTEM_DEPS[@]}"
    echo "  Python packages missing: ${#MISSING_PYTHON_DEPS[@]}"
    echo ""

    if [ ${#MISSING_SYSTEM_DEPS[@]} -eq 0 ] && [ ${#MISSING_PYTHON_DEPS[@]} -eq 0 ]; then
        log_success "All dependencies are satisfied!"
        return 0
    else
        log_warning "Some dependencies are missing"
        return 1
    fi
}

main "$@"
