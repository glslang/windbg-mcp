# Releasing

The plugin sets an explicit `version` in
[`.claude-plugin/plugin.json`](../.claude-plugin/plugin.json), so users only receive an update
when that version changes — pushing commits alone does not trigger one. To cut a release, bump
`version` in `plugin.json` and `Cargo.toml`, bump the release badge near the top of [`README.md`](../README.md),
add a matching entry to
[`CHANGELOG.md`](../CHANGELOG.md), and tag the commit `vX.Y.Z`. Run
`claude plugin validate . --strict` before publishing. Pushing the tag runs
[`release.yml`](../.github/workflows/release.yml), which verifies the tag matches both manifest
versions and the README badge, builds `windbg-mcp.exe`, and attaches the zip + SHA256 checksum to the GitHub release.
It also builds an [MCPB](https://github.com/anthropics/mcpb) bundle
(`windbg-mcp-vX.Y.Z-windows-x64.mcpb`, described by
[`packaging/mcpb/manifest.json`](../packaging/mcpb/manifest.json)) and publishes a
[`server.json`](../server.json) entry to the [official MCP Registry](https://registry.modelcontextprotocol.io)
(`io.github.glslang/windbg-mcp`) with the `mcp-publisher` CLI over GitHub OIDC — no secrets. CI
stamps the release version into both files and the bundle's SHA-256 into `server.json`, so
neither is part of the manual bump list above.
The zip also gets a signed
[build-provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
tying it to the workflow run that built it — verify with:

```pwsh
gh attestation verify <zip> --repo glslang/windbg-mcp `
   --signer-workflow glslang/windbg-mcp/.github/workflows/release.yml
```

(`--repo` alone only proves the attestation came from *some* workflow in this repo;
`--signer-workflow` pins it to the release workflow.)

## What the release is not

**It is not Authenticode signed**, so SmartScreen shows an "unknown publisher" prompt and Defender
may quarantine it — `Trojan:Win32/Bearfoos.B!ml` is the verdict this project has actually drawn, on
a locally built binary. That suffix marks a machine-learning score rather than a signature match, so
the same file lands either side of the line on different days. The attestation above does not help:
it is a supply-chain claim a user verifies deliberately, and nothing on the machine reads it. The
binary does carry a full PE version resource, which is the other cause Microsoft names for that
detection on its own binaries, but the metadata is the cheap half rather than the fix
([`FOLLOWUPS.md`](../FOLLOWUPS.md) item 50 is the certificate decision that remains).

So if a release is reported as quarantined, the two things to do are to point the reporter at
[`skills/windbg-debugging/setup.md`](../skills/windbg-debugging/setup.md)'s note — verify the
SHA-256 and the attestation *first*, since those answer a question the verdict does not — and to
submit the artifact to [Microsoft's file submission portal](https://www.microsoft.com/wdsi/filesubmission)
as a false positive. That submission is per artifact, so a new release needs a new one.
