# Remote phase 0 — the server on the VM, the client somewhere else

DbgEng is Windows-only, so `windbg-mcp` runs where Windows is. The harness and the model have no
such requirement. This is the **zero-code** way to separate them: register the MCP server as an
`ssh` command, so the stdio transport tunnels to the VM and nothing in this repo changes.

It is deliberately **throwaway**. It exists to answer four questions (see
[What to measure](#what-to-measure)) before any transport code is written, and its rough edges are
artifacts of launching an exe through a login session rather than anything structural. Do not fix
them here; running the server as a Windows service removes them at once.

## What it gives you, and what it doesn't

| | |
| --- | --- |
| **Works** | Dumps, TTD replay, live user-mode, `attach_kernel` by profile, `debug_batch`, the pool and heap walks |
| **Works, unchanged** | Client disconnect still releases live targets — closing the ssh channel closes the remote stdin, the supervisor exits, and workers follow via EOF |
| **Works, but verify** | The elevation-only tools, `record_trace` and `attach_kernel_local`. Windows OpenSSH grants a member of the Administrators group a **full, unfiltered token**, so these do work — but that is a property of the host's logon policy, not a guarantee. Check rather than assume (below) |
| **Not addressed** | Sessions do not survive a client restart; there is no lease, no adopt, no progress notification, and worker logs reach you only as ssh stderr |

Confirm the elevation question on your own host before relying on either answer — it is one
command, and getting it wrong in the optimistic direction costs a confusing failure much later:

```console
ssh windbg-vm powershell -NoProfile -Command "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')"
```

The KD link is unaffected by any of this. `attach_kernel` is the debugger host dialing its target
over KDNET — how *you* reached the debugger host does not enter into it — which makes it the most
interesting thing to test here.

## Steps

### 1. Install and start OpenSSH Server on the VM

```pwsh
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service sshd -StartupType Automatic
Start-Service sshd
```

The capability install adds a firewall rule — but **it is scoped to the `Private` and `Domain`
profiles, and a hypervisor's guest network usually comes up `Public`**. That combination is the
most confusing failure here, because sshd is running and listening and everything looks correct
from inside the guest, while the host's SYNs are silently dropped. A drop presents as `ssh`
**hanging** after `Connecting to <address> port 22`, where nothing listening at all would have
given you `Connection refused` immediately.

Check both halves, not just the service:

```pwsh
Get-Service sshd | Format-Table Name,Status,StartType -AutoSize
Get-NetConnectionProfile | Format-Table Name,NetworkCategory -AutoSize
Get-NetFirewallRule -Name *OpenSSH* | Format-Table Name,Enabled,Direction,Profile,Action -AutoSize
```

If the profile is `Public` and the rule says `Private`, open the one port to the one host that
needs it rather than reclassifying the network:

```pwsh
New-NetFirewallRule -Name sshd-from-hypervisor-host `
  -DisplayName "OpenSSH Server (hypervisor host only)" `
  -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow `
  -Profile Any -RemoteAddress <host-address-on-the-guest-network> -Enabled True
```

`Set-NetConnectionProfile -NetworkCategory Private` also works and is one line shorter, but it
activates every other `Private`-scoped inbound rule as a side effect — file and printer sharing,
network discovery. On a debugger VM that shares a subnet with the target it is kernel-debugging,
that is a lot of surface bought for one port.

### 2. Keep `cmd.exe` as the default shell

```pwsh
Get-ItemProperty HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -ErrorAction SilentlyContinue
```

If that returns PowerShell, remove the key or point it back at `C:\Windows\System32\cmd.exe`.

**Why it matters:** OpenSSH runs an exec request through the default shell. `cmd /c` hands the
child process the inherited pipe handles and stays out of the way; PowerShell captures a native
command's output through its own pipeline and applies its output encoding, which can rewrite the
line endings underneath line-delimited JSON-RPC. Step 6 is what actually catches this — the point
here is to not be surprised by it.

### 3. Install the key — and mind the administrators file

If the VM user is in the Administrators group, which it will be if you are kernel debugging, sshd
**ignores `~/.ssh/authorized_keys`** and reads `C:\ProgramData\ssh\administrators_authorized_keys`
instead. On the VM, elevated:

```pwsh
Add-Content C:\ProgramData\ssh\administrators_authorized_keys '<contents of your id_ed25519.pub>'
icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
```

The `icacls` line is not optional: sshd refuses the file outright if any other principal can write
it, and the refusal is not logged anywhere you would think to look. This is the single most common
way this step fails silently.

### 4. Give the host a stable name on the client

```ssh-config
Host windbg-vm
    HostName <vm-address>
    User <vm-user>
    IdentityFile ~/.ssh/id_ed25519
    RequestTTY no
    BatchMode yes
    ServerAliveInterval 30
    ServerAliveCountMax 6
```

`RequestTTY no` is load-bearing — a PTY would apply echo and line discipline to the transport.
`BatchMode yes` makes a missing key fail immediately instead of hanging on a prompt no one will
ever see, because an MCP client's stdin belongs to the protocol.

*Finding* the VM is topology-specific and this is one instance, not the procedure: under Parallels
with a `shared` network adapter, the guest gets a `10.211.55.x` address from the hypervisor's own
DHCP, which is not routable off the host machine. That address moves — but Parallels also registers
the guest as `<vm-name>.shared`, so prefer that as the `HostName` and the drift stops mattering.

When a connection fails, the useful first question is whether the guest is reachable at layer 2 at
all, which separates a stale address from a filtered one:

```console
arp -a | grep <guest-subnet>
```

An entry resolving to the guest's MAC means the address is current and the guest answered — so
anything above that is being dropped, and the firewall is where to look. No entry means the address
itself is wrong. `prlctl list -f` reports what the hypervisor believes, and
`prlctl exec <vm> <command>` runs inside the guest through the Tools channel rather than the
network, which is how you ask a machine why it is not answering.

### 5. Configure kernel profiles in the file, not the environment

An ssh session inherits machine and user environment variables from the registry, but **nothing**
from a PowerShell `$PROFILE` or an interactive shell. A `WINDBG_MCP_PROFILE_<NAME>` variable set
the way most people set one will simply be absent, and `attach_kernel {}` will report no profiles
at all.

Use `%USERPROFILE%\.windbg-mcp\profiles.json` instead — it is read from disk by the process itself,
so it is immune to how that process was started. Check both it and the binary over ssh rather than
interactively, since that is the environment that will actually run:

```console
ssh windbg-vm "where windbg-mcp.exe & dir %USERPROFILE%\.windbg-mcp"
```

`&` chains work because the remote shell is `cmd` — which is also a trap for anything more
elaborate. `ssh` joins its remaining arguments into **one string** and hands it to that shell, so
`cmd` parses `|` and `;` before PowerShell ever sees them, and a remote one-liner with a pipe in it
fails with something misleading like `'Select-Object' is not recognized`. Encode it instead:

```console
ENC=$(iconv -f UTF-8 -t UTF-16LE < script.ps1 | base64 | tr -d '\n')
ssh windbg-vm "powershell -NoProfile -EncodedCommand $ENC"
```

Bear in mind too that a non-interactive PowerShell serializes its progress and error streams as
**CLIXML on stderr** (`#< CLIXML`, then a wall of XML). Harmless here, but it is a concrete preview
of why step 2 matters: routed through the MCP server's stdout, that is a corrupted transport.

### 6. Probe the handshake before registering anything

```console
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
    | ssh -T windbg-vm '<path>\windbg-mcp.exe' | cat -vet | head -3
```

What you want is a single line of JSON on **stdout** carrying `serverInfo`, and
`windbg-mcp starting on stdio` on **stderr** — that second line is also your proof the log path
survives the hop.

`cat -vet` renders a carriage return as `^M` (that is BSD's spelling; GNU `cat -A` is the same
thing). If you see one, or a shell banner, or a blank first line, the shell is interfering: go back
to step 2. Nothing past this point works if this does not, and the failure mode downstream is an
unreadable parse error rather than anything that names the cause.

A clean run answers `{"jsonrpc":"2.0","id":1,"result":{...,"serverInfo":{"name":"windbg-mcp",...}}}`
on stdout with no `^M`, and the startup line on stderr. Note what this does **not** prove: the
supervisor never loads DbgEng — only its workers do — so a successful handshake says nothing about
whether the debugger works. `open_dump` is the first call that finds out.

### 7. Register it with the client

```console
claude mcp add windbg-vm --scope local -- ssh -T windbg-vm '<path>\windbg-mcp.exe'
```

**`--scope local`, not `--scope project`.** The `project` scope writes `.mcp.json` into the
repository, and this wiring is machine-specific in exactly the way [`CLAUDE.md`](../CLAUDE.md) says
to keep out of version control — an address, a user name and an absolute path that are true for one
host.

Note also that the plugin build (`windbg-mcp@windbg-mcp`) and any local `target\release` server
registration are unaffected and unaware of this one. If you are running both, they are separate
servers with separate session registries; name them so you can tell which is which.

## What to measure

Phase 0 exists to answer these four questions. Answer them deliberately, then decide whether the
rest of the plan is worth building.

| Question | How |
| --- | --- |
| **Does the latency matter?** | Time a `modules` call over ssh against the same call made on the VM. A hop that disappears into the noise of a debugger operation settles the transport question. |
| **Do long calls survive?** | Run `crash_triage` with `analyze: true`, or a `pool_census`. Both produce no output for a long stretch; this confirms the keepalive probes do not disturb a call inside its 300 s budget. |
| **Does teardown still work?** | Quit the client, then `ssh windbg-vm "tasklist \| findstr windbg-mcp"`. Empty is the answer. This is the real check that the channel closing reaches the supervisor's stdin, and that its workers follow. |
| **Can the model cope?** | Point the harness at whichever model you intend to use and watch it choose among 53 tools. This is the finding that sizes everything about tool-surface curation. |

The teardown check is the one worth being fussy about. It is the property `src/main.rs` gives up
its runtime to guarantee, and a live kernel target that is killed rather than released is left
*frozen* — so "no orphaned process" and "the guest came back" are the same assertion.

## Where this stops being enough

Four things push you off phase 0, roughly in the order you will hit them:

1. **Session lifetime.** Every client restart costs you every open session, which for a KDNET
   attach means a reboot cycle on the target.
2. **Logs.** Worker stderr arrives interleaved on the ssh channel and vanishes with it. There is no
   log file and no way to ask for one.
3. **Long-call visibility.** Nothing reports progress, so a parked `attach_kernel` and a healthy
   90-second walk look identical from the client.
4. **Start-up.** The server exists only while a client is connected to it, from whatever directory
   and environment that login session happened to have.

All four are the same fix — an HTTP listener running as a service, with leases and progress
notifications — which is where this stops being a configuration exercise and starts being code.

Note that **elevation is not on this list**, though an earlier draft of this document had it at the
top. A Windows service is elevated by construction, which is a real advantage over *some* ways of
starting a process — but not over ssh, which already hands an Administrators member a full token.
The service earns its place on the four points above; claiming elevation as well would be talking
up a problem that measurement does not support.

## See also

- [`CLAUDE.md`](../CLAUDE.md) — the supervisor/worker split, and why a worker's stdout is not the
  protocol
- [`smoke-test.md`](./smoke-test.md) — the tiers, including the live-kernel one this setup does not
  change
