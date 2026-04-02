# Network Proxy

`agent-jail` can export two explicit proxies inside a session:

- an HTTP proxy for `HTTP_PROXY` and `HTTPS_PROXY`
- a SOCKS5 proxy for `SOCKS_PROXY`

Both use the same `network` rules stored in `policy.json`.

## Rule model

Network rules use:

- `host`
- optional `port`
- optional `scheme`
- `allow`

Example:

```json
{
  "kind": "network",
  "host": "api.openai.com",
  "port": 443,
  "scheme": "tcp",
  "allow": true
}
```

## CLI

Manage rules directly:

```bash
python3 agent-jail network allow api.openai.com --port 443 --scheme tcp
python3 agent-jail network deny example.com --port 443 --scheme tcp
python3 agent-jail network list
python3 agent-jail network test api.openai.com --port 443 --scheme tcp --default-deny
```

## Running with the proxy

Start a session with proxying enabled:

```bash
python3 agent-jail run --proxy codex --dangerously-bypass-approvals-and-sandbox
python3 agent-jail run --proxy --deny-network-by-default claude --allow-dangerously-skip-permissions
```

Inside the session:

- HTTP(S) clients typically use `HTTP_PROXY` / `HTTPS_PROXY`
- SOCKS-aware clients typically use `SOCKS_PROXY`

If a client expects `ALL_PROXY`, set it explicitly:

```bash
export ALL_PROXY="$SOCKS_PROXY"
```

## Smoke test

```bash
AGENT_JAIL_HOME=/tmp/agent-jail-proxy-test \
python3 agent-jail network allow example.com --port 443 --scheme tcp

AGENT_JAIL_HOME=/tmp/agent-jail-proxy-test \
python3 agent-jail run --proxy --deny-network-by-default \
python3 -c "import urllib.request; print(urllib.request.urlopen('https://example.com', timeout=5).status)"
```

## Current limits

- explicit-proxy only; clients must respect proxy environment variables
- SOCKS support is TCP `CONNECT` only
- UDP is not proxied yet
