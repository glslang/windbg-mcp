# Use with an MCP client

Point your client at the built binary, e.g. Claude Code:

```jsonc
// .mcp.json  (or claude_desktop_config.json under "mcpServers")
{
  "mcpServers": {
    "windbg": {
      "command": "C:\\workspace\\windbg-mcp\\target\\release\\windbg-mcp.exe"
    }
  }
}
```

## On another machine

The server has to run where DbgEng does, but the client and the model do not. `--listen <addr>`
serves the same tools over HTTP instead of stdio, so a Mac can drive a Windows VM:

```console
# Windows, with WINDBG_MCP_LISTEN_TOKEN set to a long random string
windbg-mcp.exe --listen 127.0.0.1:8765
# client machine — the same string, spelled out: the variable lives on the Windows
# host, and a shell without it sends an empty bearer and gets a 401 on every call
ssh -N -L 8765:127.0.0.1:8765 windbg-vm
claude mcp add windbg-vm --transport http http://127.0.0.1:8765/ \
  --header "Authorization: Bearer <the same string>"
```

Install it as a **Windows service** (`--install-service --listen <addr>`, elevated, and from a
directory Windows protects — see [Run it as a Windows
service](remote-listener.md#run-it-as-a-windows-service)) and it survives
logout, starts at boot, and gets a defined `PATH` and working directory — which is what decides
whether the engine DLLs beside the exe are the ones that load. `Stop-Service` releases every debug
target before exiting, because a live kernel that is merely killed is left frozen. Its clients are
changed in place — `--add-listen-client`, `--remove-listen-client`, `--rotate-listen-client`, each
generating the token itself, writing it beside the credential file and printing only a fingerprint,
and `--set-listen-client-tools` for which tools one of them is served — so adding, revoking or
re-toolling one costs neither a reinstall nor the sessions the service is holding.
`--list-listen-clients` asks who may connect and what each is served **without changing anything**,
and answers for the environment instead where no service is installed.

**Bind loopback and forward over SSH.** This endpoint runs `execute`, `debug_batch` and `launch`
against a live kernel, and the token is sent in clear — a hypervisor's guest network is not private
when the machine being debugged shares it. [`remote-listener.md`](./remote-listener.md)
covers the tokens — **one per client**, each with its own sessions and, where you want one, its own
tool surface, so two people or two agents on one listener cannot reach each other's targets and need
not share a budget — the session lease and its grace, and the one thing a `409` means: this
credential's own expired sessions are still being released, so ask again in a moment. Nothing else
is refused for contention — a credential may hold several MCP sessions, and requests of one client
never wait on another's. For a one-off, [`remote-phase0.md`](./remote-phase0.md) does the
same job over plain `ssh` with no listener; for driving it from a **local model** rather than a
hosted one, [`local-model.md`](./local-model.md) is the runbook and the numbers that
decide whether it fits.

## As a Claude Code plugin

This repo is also a single-plugin [Claude Code marketplace](https://code.claude.com/docs/en/plugin-marketplaces):
installing it registers the `windbg` MCP server **and** a `windbg-debugging` skill that
knows how to drive it (setup, crash-dump, live/kernel, and TTD playbooks).

```text
/plugin marketplace add glslang/windbg-mcp
/plugin install windbg-mcp@windbg-mcp
```

The plugin ships source, not a binary, so after installing you still put the server binary in
place — download a prebuilt release or build from source — and (for `.run` replay, crash-dump
`!analyze`, and the kernel driver tools) bundle the WinDbg engine — the skill's `setup.md`
walks through it, and it mirrors the [*Build or download*](./install.md#build-or-download) and
[*Bundling the WinDbg engine*](./install.md#bundling-the-windbg-engine) sections of the install
guide. Then `/reload-plugins` to connect the server. The plugin points at `${CLAUDE_PLUGIN_ROOT}/target/release/windbg-mcp.exe`.

## From the official MCP registry

The server is listed in the [official MCP registry](https://registry.modelcontextprotocol.io) as
**`io.github.glslang/windbg-mcp`**. Clients that support the registry — or that install
[MCPB](https://github.com/anthropics/mcpb) bundles directly — can add it by name: the client
downloads that release's `.mcpb` bundle, verifies its SHA-256, and wires up the `windbg-mcp.exe`
inside it as an stdio server, with no Rust build or manual binary placement.

The bundle is **Windows x64 only** and ships just the server binary, so the one-time engine setup
still applies — for TTD `.run` replay, crash-dump `!analyze`, and the
`driver_object`/`device_object`/`irp_stack` tools, drop the WinDbg engine DLLs next to the
client-extracted `windbg-mcp.exe` (the skill's `setup.md` covers it). Basic live and crash-dump
work runs on the in-box `System32` engine without them — a kernel attach included, but not those
three tools, which need `winxp\kdexts.dll`.
