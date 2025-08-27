# pwn-mcp

[![CI](https://github.com/polarisxb/pwn-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/polarisxb/pwn-mcp/actions/workflows/ci.yml)
[![Docker](https://github.com/polarisxb/pwn-mcp/actions/workflows/docker.yml/badge.svg)](https://github.com/polarisxb/pwn-mcp/actions/workflows/docker.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Model Context Protocol (MCP) server that assists CTF pwn workflows through AI-powered analysis and guidance. Designed for educational purposes with safety-first approach - generates templates with TODOs, not weaponized exploits.

## 🎯 Features

- **Smart Binary Analysis**: Architecture, protections (NX/PIE/RELRO/Canary), PLT/GOT, sections, suspicious functions
- **Dynamic Execution**: Controlled crashes with GDB integration, offset calculation, memory mapping
- **AI-Driven Strategy**: Intelligent exploitation planning based on binary characteristics
- **Safe Templates**: Pwntools scaffolds with educational TODOs
- **Session Management**: Persistent analysis results and progress tracking
- **Extensible Design**: Clean hexagonal architecture with pluggable adapters

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ and npm
- Linux/WSL2 environment (recommended)
- Optional tools for enhanced features:
  - `rizin` or `radare2` - Deep static analysis
  - `gdb` with `pwndbg`/`gef` - Dynamic analysis
  - `gcc` - Compiling test binaries
  - Python 3 with `pwntools` - Running generated exploits

### Installation

#### Option 1: From Source

```bash
# Clone repository
git clone https://github.com/polarisxb/pwn-mcp.git
cd pwn-mcp

# Install and build
npm install
npm run --workspaces build

# Test installation
npm --workspace @pwn-mcp/mcp-server run smoke
```

#### Option 2: Docker (Recommended)

```bash
# Pull latest image
docker pull ghcr.io/polarisxb/pwn-mcp:latest

# Run with your challenge directory
docker run -it -v "$PWD/challenges:/workspace" \
  -e SAFE_MCP_DEEP_STATIC=true \
  -e SAFE_MCP_GDB_EXEC=true \
  ghcr.io/polarisxb/pwn-mcp:latest
```

#### Option 3: Quick Install (Linux/WSL2)

```bash
# One-line installer
curl -sSL https://raw.githubusercontent.com/polarisxb/pwn-mcp/main/install.sh | bash

# Or with wget
wget -qO- https://raw.githubusercontent.com/polarisxb/pwn-mcp/main/install.sh | bash
```

## 📖 Usage

### With Claude Desktop / Cursor

1. Add to MCP settings:

```json
{
  "mcpServers": {
    "pwn-mcp": {
      "command": "node",
      "args": ["/path/to/pwn-mcp/packages/mcp-server/dist/server.js"],
      "env": {
        "SAFE_MCP_DEEP_STATIC": "true",
        "SAFE_MCP_GDB_EXEC": "true"
      }
    }
  }
}
```

2. Start analyzing:
   - "Analyze this binary and find vulnerabilities"
   - "Help me exploit this stack overflow"
   - "Generate a pwntools template for this challenge"

### Standalone Server

```bash
# Start MCP server
npm --workspace @pwn-mcp/mcp-server run start

# With feature flags
SAFE_MCP_DEEP_STATIC=true SAFE_MCP_GDB_EXEC=true \
  npm --workspace @pwn-mcp/mcp-server run start
```

### Typical Workflow

1. **Initialize session**: `init_session` with target binary
2. **Analyze binary**: `analyze_binary` to get facts (arch, protections, symbols)
3. **Plan strategy**: `suggest_strategy` for exploitation approach
4. **Find offset**: `run_local` with cyclic pattern, then `calculate_offsets`
5. **Generate template**: `gen_exploit_template` for pwntools scaffold
6. **Export report**: `save_session` and `export_report` for documentation

## 🛠️ Architecture

```
pwn-mcp/
├── packages/
│   ├── core/          # Domain types and interfaces
│   ├── adapters/      # Tool integrations (rizin, gdb)
│   ├── orchestrator/  # Decision engine
│   ├── templates/     # Code generators
│   ├── config/        # Feature flags
│   ├── storage/       # Session persistence
│   └── mcp-server/    # MCP protocol server
```

## 🔧 Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `SAFE_MCP_DEEP_STATIC` | Enable Rizin for analysis | Auto-detect |
| `SAFE_MCP_GDB_EXEC` | Enable GDB for execution | Auto-detect |

## 🧪 Testing

```bash
# Basic smoke test
npm --workspace @pwn-mcp/mcp-server run smoke

# End-to-end test
npm --workspace @pwn-mcp/mcp-server run e2e

# Full test suite
npm test
```

## 🐳 Docker Support

```bash
# Build locally
docker build -t pwn-mcp .

# Run with volume mount
docker run -it --rm \
  -v "$PWD/challenges:/workspace" \
  -e SAFE_MCP_DEEP_STATIC=true \
  -e SAFE_MCP_GDB_EXEC=true \
  pwn-mcp

# Development mode
docker run -it --rm \
  -v "$PWD:/app" \
  -w /app \
  pwn-mcp \
  npm run --workspaces build
```

## 📚 Examples

### Basic Stack Overflow

```bash
# Download a vulnerable binary
wget https://example.com/vuln_binary

# Analyze with pwn-mcp
echo '{"target": "./vuln_binary"}' | \
  node packages/mcp-server/dist/server.js

# Follow AI guidance to exploit
```

### With Real CTF Challenge

```python
# Generated template example
from pwn import *

binary = './challenge'
elf = ELF(binary)

# TODO: Set up process/remote
p = process(binary)

# TODO: Find offset (from calculate_offsets)
offset = 72

# TODO: Build ROP chain
payload = b'A' * offset
payload += p64(0x401234)  # TODO: Add gadgets

p.sendline(payload)
p.interactive()
```

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push branch (`git push origin feature/amazing`)
5. Open Pull Request

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

## ⚠️ Security & Ethics

- **Educational tool only** - for learning and authorized CTF competitions
- **No weaponized exploits** - generates templates with TODOs
- **Local execution only** - no remote attack capabilities
- **User responsibility** - ensure legal and ethical use

## 🙏 Acknowledgments

- [pwntools](https://github.com/Gallopsled/pwntools) - CTF framework
- [rizin](https://rizin.re/) - RE framework
- [Model Context Protocol](https://modelcontextprotocol.io/) - AI integration
- CTF community for inspiration and feedback

---

Made with ❤️ for the CTF community | [Report Issues](https://github.com/polarisxb/pwn-mcp/issues)