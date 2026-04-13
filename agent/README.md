# PySOAR Endpoint Agent

Single-file, zero-dependency endpoint agent for the PySOAR unified
BAS / Live Response / Purple Team platform.

## What it does

Receives signed commands from a PySOAR server and executes them
against a cryptographically pinned local allowlist. An agent
installed with `--mode bas` literally cannot run Live Response
actions even if PySOAR authorizes them — the handler dispatch table
is built from the enrolled capability set at poll time and every
unknown action is rejected with `exit_code=126`.

See `src/agents/capabilities.py` for the full action matrix and
`src/agents/service.py` for the server-side hash-chained audit trail.

## Running as a Python script

The agent is stdlib-only (no pip install) so you can run it
directly wherever Python 3.9+ exists:

```bash
# Exchange enrollment token for a long-lived agent token
python pysoar_agent.py \
    --server https://pysoar.example.com \
    --enroll pse_xxxxxxxxxxxxxxxxxxxxxxxx

# Start the poll loop (runs forever)
python pysoar_agent.py --server https://pysoar.example.com --poll
```

The long-lived token is stored at `~/.pysoar/agent.token` (0600) and
the enrolled capability list at `~/.pysoar/agent.token.caps`.

## Building a single-file binary

For customer shipments you usually want a static binary, not a
Python script. PyInstaller wraps the agent and its interpreter into
one executable. PyInstaller is **not** a cross-compiler: build each
target on a host of that platform+arch.

### Linux / macOS

```bash
cd agent
./build.sh
# -> dist/pysoar-agent-linux-x86_64
# -> dist/pysoar-agent-darwin-arm64
# (whichever host you ran it on)
```

### Windows

```cmd
cd agent
build.bat
:: -> dist\pysoar-agent-windows-amd64.exe
```

The build scripts print the SHA-256 of the output so you can publish
a checksum alongside the binary. Operators should verify the hash
before running on a production endpoint:

```bash
sha256sum pysoar-agent-linux-x86_64
```

### Multi-platform via CI

A typical release matrix:

| Target                     | Runner                 | Output                             |
| -------------------------- | ---------------------- | ---------------------------------- |
| linux/amd64                | ubuntu-22.04           | pysoar-agent-linux-x86_64          |
| linux/arm64                | ubuntu-22.04-arm       | pysoar-agent-linux-aarch64         |
| darwin/arm64               | macos-14               | pysoar-agent-darwin-arm64          |
| darwin/x86_64              | macos-13               | pysoar-agent-darwin-x86_64         |
| windows/amd64              | windows-2022           | pysoar-agent-windows-amd64.exe     |

Each job runs `./build.sh` (or `build.bat`) and uploads the binary
and its SHA-256 to your release asset store.

## Usage with the binary

Identical to the Python-script path, just with the binary in place:

```bash
./pysoar-agent-linux-x86_64 --server https://pysoar.example.com \
    --enroll pse_xxxxxxxxxxxxxxxxxxxxxxxx

./pysoar-agent-linux-x86_64 --server https://pysoar.example.com --poll
```

## What the agent will and will not do

**Will** (with `bas` capability): run atomic test commands, collect
process list, collect network connections.

**Will** (with `ir` capability): kill process, isolate host, release
host, disable account, collect file, collect memory dump, quarantine
file, unquarantine file. Everything destructive is gated by a
server-side second-analyst approval workflow before dispatch.

**Will not, ever** (regardless of capability): open a reverse shell,
execute arbitrary commands outside the allowlist, establish
persistence, load shellcode, connect to anything other than the
`--server` URL, exfiltrate files outside a specific `collect_file`
action, sideload new handlers without a re-install.

This is intentional. PySOAR is a defensive platform with safe live
response; it is not a C2. If a future use case requires a new
action, add it to `src/agents/capabilities.py`, implement a bounded
handler in `pysoar_agent.py`, rebuild, and re-enroll. There is no
dynamic code path.
