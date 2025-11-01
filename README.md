# Codex MCP HTTP proxy

This repository packages a small utility that launches the Codex CLI MCP server
command and exposes it through an HTTP/WebSocket proxy protected by HTTP Basic
Authentication. The proxy makes it possible to safely expose Codex to the wider
internet while keeping the upstream MCP server bound to localhost.

## Features

- Launches the Codex MCP CLI server as a managed subprocess and captures its
  stdout/stderr for logging.
- Exposes an HTTP and WebSocket reverse proxy that forwards requests to the
  Codex MCP server.
- Enforces optional HTTP Basic Authentication before forwarding any traffic.
- Gracefully shuts down the Codex process when the proxy exits or receives
  termination signals.

## Installation

```bash
pip install .
```

This installs the `codex-mcp-http-proxy` console script.

## Usage

Run the proxy by passing the Codex CLI command after a `--` separator:

```bash
codex-mcp-http-proxy \
  --listen-host 0.0.0.0 \
  --listen-port 8080 \
  --upstream-host 127.0.0.1 \
  --upstream-port 3333 \
  --username myuser \
  --password mypassword \
  -- codex mcp server --port 3333
```

### Command-line arguments

- `--listen-host` / `--listen-port`: Network interface and port the proxy
  listens on (defaults to `0.0.0.0:8000`).
- `--upstream-host` / `--upstream-port`: Address of the locally bound Codex MCP
  server. The proxy forwards traffic to this endpoint.
- `--upstream-scheme`: Scheme used when forwarding traffic to Codex. Use
  `http`/`https` when the Codex server exposes HTTP endpoints or `ws`/`wss` for a
  pure WebSocket server (defaults to `http`).
- `--username` and `--password`: Optional HTTP Basic Auth credentials required
  from all clients. Leave unset to disable authentication.
- `--log-level`: Logging verbosity for the proxy (defaults to `INFO`).
- `command`: The Codex CLI command to execute. Everything after `--` is passed
  directly to the subprocess.

Press `Ctrl+C` or send `SIGTERM` to stop the proxy. The Codex subprocess will be
terminated automatically.
