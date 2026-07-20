# jar-tools-mcp

MCP server for [jar.tools](https://jar.tools)' JAR security scanner. Scan a local `.jar`, `.zip`, or `.class` file for supply-chain risk — network activity, file access, process execution, and obfuscation/decompiler-evasion signals — directly from an AI agent, without opening a browser.

## Features

- Static behavioral analysis of `.jar`/`.zip`/`.class` files — the file is never executed
- Suspicious-class counts broken down by category (network, file access, process execution, hard-to-review code)
- Decompiler-anomaly detection (obfuscation/evasion signals)
- Optional Pro license key raises the `.jar` size cap from 64MB to 256MB

## Use Cases

- **Audit a dependency before adding it to a build** — scan a resolved JAR pulled from Maven/Gradle before trusting it
- **Investigate a suspicious plugin or mod** — check a Minecraft mod or IDE plugin JAR before installing
- **Review a vendor SDK** — static analysis of a third-party binary before shipping it to production

## Installation

```bash
npm install -g github:gogainda/jar-tools-mcp
```

Until the npm registry release is available, this installs directly from the
public GitHub repository. No API key is required for the default free tier.

## Configuration

### Codex Setup

Add the MCP server with the Codex CLI:

```bash
codex mcp add jar-tools -- npx -y github:gogainda/jar-tools-mcp
```

Verify that Codex can see it:

```bash
codex mcp list
```

You can also add it manually to `~/.codex/config.toml`:

```toml
[mcp_servers.jar-tools]
command = "npx"
args = ["-y", "github:gogainda/jar-tools-mcp"]
```

For Pro scans, export `JARTOOLS_LICENSE_KEY` before starting Codex and allow the
MCP server to receive it:

```toml
[mcp_servers.jar-tools]
command = "npx"
args = ["-y", "github:gogainda/jar-tools-mcp"]
env_vars = ["JARTOOLS_LICENSE_KEY"]
```

In an active Codex session, use `/mcp` to confirm that `jar-tools` is connected.

### Claude Code Setup

Add the MCP server using the CLI:

```bash
claude mcp add jar-tools -- npx -y github:gogainda/jar-tools-mcp
```

Or add manually to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "jar-tools": {
      "command": "npx",
      "args": ["-y", "github:gogainda/jar-tools-mcp"]
    }
  }
}
```

### Optional: Pro License Key

If you have a [jar.tools Pro](https://jar.tools/pro) license and need to scan `.jar` files larger than 64MB:

```bash
export JARTOOLS_LICENSE_KEY=your-license-key
```

Or pass `license_key` as a tool argument on individual calls.

## Usage

Ask your agent to scan a file:

```
Scan ./vendor/some-library.jar for supply-chain risk before I add it as a dependency.
```

The tool returns a text summary (suspicious-class count, top signal categories, decompiler-anomaly flags) plus the full JSON findings report.

## API Reference

This server is a thin wrapper around the public [jar.tools Security Scan API](https://jar.tools/kb/security-scan-api) (`POST /api/v1/security-scan/jar-report` / `class-report`). See that page for the full response schema if you want to parse the JSON output yourself.

## Development

```bash
# Build
npm run build

# Test
npm test

# Run directly
node dist/index.js
```

## Author

Visit my personal site: https://igorstechnoclub.com

## License

MIT
