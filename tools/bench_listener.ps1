# A foreground listener for a benchmark run: three clients, three tool surfaces, one port.
#
# The eval measures the tool surface as an axis, and since PR #196 a surface is a property of
# the *client* rather than of the run - so one listener serves all three, told apart by which
# bearer token the driver presents. Nothing is installed and nothing is left behind: the
# listener lives as long as the ssh channel that started it.
#
# The three tokens arrive as JSON on **stdin**, never on a command line, where every process
# on the box could read them:
#
#     ssh -L 8766:127.0.0.1:8766 <vm> 'powershell -NoProfile -File C:\path\bench_listener.ps1' `
#       < bench-tokens.json
#
# Windows PowerShell 5.1 is the only PowerShell a debuggee is guaranteed to have, so this file
# stays ASCII - see CLAUDE.md on what a BOM-less non-ASCII character does to a 5.1 parse.
$ErrorActionPreference = 'Stop'

$exe = $env:WINDBG_MCP_EXE
if (-not $exe) { $exe = 'C:\workspace\windbg-mcp\target\release\windbg-mcp.exe' }
$listen = $env:WINDBG_MCP_BENCH_ADDR
if (-not $listen) { $listen = '127.0.0.1:8766' }

$raw = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($raw)) {
    throw 'nothing on stdin: pipe in the JSON token file, e.g. ... < bench-tokens.json'
}
$cfg = $raw | ConvertFrom-Json

# Named here rather than discovered later. The server already refuses to start when a *tools*
# spec names a client it has no token for, so a missing 'lean' or 'min' is caught - but a missing
# 'full' has no spec beside it, so the listener would start happily with two clients and the
# eval's whole first column would fail authentication one cell at a time. Say which surface is
# missing, and never say what any of the values are.
foreach ($client in 'full', 'lean', 'min') {
    if ([string]::IsNullOrWhiteSpace($cfg.$client)) {
        throw "the token file on stdin has no token for the '$client' client"
    }
}

# No unnamed token: that one would name a client called `local`, which is what the *editor*
# connects as on the other listener. Two clients of one name on two ports is a confusion this
# run does not need.
Remove-Item Env:WINDBG_MCP_LISTEN_TOKEN -ErrorAction SilentlyContinue

$env:WINDBG_MCP_LISTEN_TOKEN_FULL = $cfg.full
$env:WINDBG_MCP_LISTEN_TOKEN_LEAN = $cfg.lean
$env:WINDBG_MCP_TOOLS_LEAN        = 'session,inspect,crash'
$env:WINDBG_MCP_LISTEN_TOKEN_MIN  = $cfg.min
$env:WINDBG_MCP_TOOLS_MIN         = 'crash'

Write-Host "starting $exe --listen $listen with clients: full (all), lean (session,inspect,crash), min (crash)"
& $exe --listen $listen
