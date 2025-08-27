#!/bin/bash
#
# pwn-mcp installer script for Linux/WSL2
# This script installs pwn-mcp and its dependencies
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="$HOME/.pwn-mcp"
REPO_URL="https://github.com/polarisxb/pwn-mcp.git"
REQUIRED_NODE_VERSION=18

# Functions
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

check_command() {
    if command -v "$1" &> /dev/null; then
        print_success "$1 is installed"
        return 0
    else
        print_error "$1 is not installed"
        return 1
    fi
}

check_node_version() {
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
        if [ "$NODE_VERSION" -ge "$REQUIRED_NODE_VERSION" ]; then
            print_success "Node.js version is $NODE_VERSION (>= $REQUIRED_NODE_VERSION)"
            return 0
        else
            print_error "Node.js version is $NODE_VERSION (< $REQUIRED_NODE_VERSION)"
            return 1
        fi
    else
        print_error "Node.js is not installed"
        return 1
    fi
}

install_system_deps() {
    print_info "Installing system dependencies..."
    
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y git build-essential python3 python3-pip
        
        # Optional tools
        if ! command -v rizin &> /dev/null; then
            print_info "Installing Rizin..."
            wget -q https://github.com/rizinorg/rizin/releases/download/v0.6.3/rizin_0.6.3_amd64.deb
            sudo dpkg -i rizin_0.6.3_amd64.deb || sudo apt-get -f install -y
            rm rizin_0.6.3_amd64.deb
        fi
        
        if ! command -v gdb &> /dev/null; then
            print_info "Installing GDB..."
            sudo apt-get install -y gdb
        fi
        
    elif [ -f /etc/redhat-release ]; then
        # RHEL/Fedora/CentOS
        sudo dnf install -y git gcc gcc-c++ make python3 python3-pip
        
        # Optional tools
        if ! command -v rizin &> /dev/null; then
            print_info "Installing Rizin..."
            sudo dnf install -y rizin
        fi
        
        if ! command -v gdb &> /dev/null; then
            print_info "Installing GDB..."
            sudo dnf install -y gdb
        fi
        
    elif [ -f /etc/arch-release ]; then
        # Arch Linux
        sudo pacman -Sy --needed git base-devel python python-pip
        
        # Optional tools
        if ! command -v rizin &> /dev/null; then
            print_info "Installing Rizin..."
            sudo pacman -S --needed rizin
        fi
        
        if ! command -v gdb &> /dev/null; then
            print_info "Installing GDB..."
            sudo pacman -S --needed gdb
        fi
    else
        print_error "Unsupported Linux distribution"
        exit 1
    fi
    
    # Install pwntools
    if ! python3 -c "import pwn" 2>/dev/null; then
        print_info "Installing pwntools..."
        pip3 install --user pwntools
    fi
}

install_node() {
    print_info "Installing Node.js..."
    
    # Install nvm
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
    
    # Load nvm
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    
    # Install latest LTS Node
    nvm install --lts
    nvm use --lts
}

install_pwn_mcp() {
    print_info "Installing pwn-mcp..."
    
    # Clone or update repository
    if [ -d "$INSTALL_DIR" ]; then
        print_info "Updating existing installation..."
        cd "$INSTALL_DIR"
        git pull
    else
        print_info "Cloning repository..."
        git clone "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi
    
    # Install and build
    print_info "Installing dependencies..."
    npm install
    
    print_info "Building packages..."
    npm run --workspaces build
    
    # Create symlink for easy access
    if [ ! -L "$HOME/.local/bin/pwn-mcp" ]; then
        mkdir -p "$HOME/.local/bin"
        ln -s "$INSTALL_DIR/packages/mcp-server/dist/server.js" "$HOME/.local/bin/pwn-mcp"
        print_success "Created symlink at ~/.local/bin/pwn-mcp"
    fi
}

setup_mcp_config() {
    print_info "Setting up MCP configuration..."
    
    # Create example config
    cat > "$INSTALL_DIR/mcp-config.json" << EOF
{
  "mcpServers": {
    "pwn-mcp": {
      "command": "node",
      "args": ["$INSTALL_DIR/packages/mcp-server/dist/server.js"],
      "env": {
        "SAFE_MCP_DEEP_STATIC": "true",
        "SAFE_MCP_GDB_EXEC": "true"
      }
    }
  }
}
EOF
    
    print_success "Created example MCP config at $INSTALL_DIR/mcp-config.json"
}

run_tests() {
    print_info "Running smoke tests..."
    cd "$INSTALL_DIR"
    
    if npm --workspace @pwn-mcp/mcp-server run smoke; then
        print_success "All tests passed!"
    else
        print_error "Some tests failed, but installation completed"
    fi
}

# Main installation flow
main() {
    echo "======================================"
    echo "   pwn-mcp Installer"
    echo "======================================"
    echo
    
    # Check system
    print_info "Checking system requirements..."
    
    # Check for required commands
    check_command git || install_system_deps
    
    # Check Node.js
    if ! check_node_version; then
        if [ -z "$SKIP_NODE_INSTALL" ]; then
            install_node
        else
            print_error "Node.js $REQUIRED_NODE_VERSION+ is required"
            exit 1
        fi
    fi
    
    # Install optional tools
    if [ -z "$SKIP_OPTIONAL" ]; then
        check_command rizin || print_info "Rizin not found (optional)"
        check_command gdb || print_info "GDB not found (optional)"
        check_command python3 || print_info "Python 3 not found (optional)"
    fi
    
    # Install pwn-mcp
    install_pwn_mcp
    
    # Setup configuration
    setup_mcp_config
    
    # Run tests
    if [ -z "$SKIP_TESTS" ]; then
        run_tests
    fi
    
    # Final message
    echo
    echo "======================================"
    print_success "Installation completed!"
    echo
    echo "To use pwn-mcp:"
    echo "  1. Add ~/.local/bin to your PATH if not already"
    echo "  2. Run: node $INSTALL_DIR/packages/mcp-server/dist/server.js"
    echo "  3. Or use the MCP config at: $INSTALL_DIR/mcp-config.json"
    echo
    echo "For more information, see: https://github.com/polarisxb/pwn-mcp"
    echo "======================================"
}

# Handle command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-node)
            SKIP_NODE_INSTALL=1
            shift
            ;;
        --skip-optional)
            SKIP_OPTIONAL=1
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=1
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --skip-node      Skip Node.js installation"
            echo "  --skip-optional  Skip optional tool installation"
            echo "  --skip-tests     Skip running tests"
            echo "  --help           Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main installation
main
