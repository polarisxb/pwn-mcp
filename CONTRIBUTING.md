# Contributing to pwn-mcp

First off, thank you for considering contributing to pwn-mcp! It's people like you that make pwn-mcp such a great tool for the CTF community.

## Code of Conduct

By participating in this project, you are expected to uphold our Code of Conduct:
- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Remember that this is an educational tool

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, please include:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- System information (OS, Node.js version, installed tools)
- Relevant logs or error messages

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When suggesting an enhancement:

- Use a clear and descriptive title
- Provide a detailed description of the proposed functionality
- Explain why this enhancement would be useful
- Consider implementation complexity and maintainability

### Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added code, add tests that cover your changes
3. Ensure all tests pass: `npm test`
4. Make sure your code follows the existing style
5. Write clear, descriptive commit messages

## Development Setup

```bash
# Clone your fork
git clone https://github.com/polarisxb/pwn-mcp.git
cd pwn-mcp

# Install dependencies
npm install

# Build all packages
npm run --workspaces build

# Run tests
npm --workspace @pwn-mcp/mcp-server run smoke
```

## Project Structure

- `packages/core/` - Core types and domain logic
- `packages/adapters/` - Tool integrations (Rizin, GDB)
- `packages/orchestrator/` - Decision engine
- `packages/templates/` - Code generators
- `packages/config/` - Configuration management
- `packages/storage/` - Persistence layer
- `packages/mcp-server/` - MCP protocol server

## Adding New Features

### Adding a New Analyzer

1. Create adapter in `packages/adapters/src/static/`
2. Implement `StaticAnalyzerPort` interface
3. Add feature flag in `packages/config/`
4. Wire up in `packages/mcp-server/src/server.ts`

### Adding a New Tool

1. Define types in `packages/core/src/domain/types.ts`
2. Implement tool handler in `packages/mcp-server/src/server.ts`
3. Add tests in `packages/mcp-server/scripts/`
4. Update documentation

## Testing

- Unit tests: `npm test` (when available)
- Smoke test: `npm --workspace @pwn-mcp/mcp-server run smoke`
- E2E test: `npm --workspace @pwn-mcp/mcp-server run e2e`

## Code Style

- Use TypeScript for all new code
- Follow existing naming conventions
- Keep functions small and focused
- Document complex logic with comments
- Use meaningful variable names

## Commit Messages

Follow conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions/changes
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

## Security Considerations

Remember that pwn-mcp is an educational tool:
- Never include actual exploits or weaponized code
- Use TODO placeholders in generated templates
- Focus on teaching concepts, not providing ready-to-use attacks
- Respect responsible disclosure practices

## Questions?

Feel free to open an issue for any questions about contributing!
