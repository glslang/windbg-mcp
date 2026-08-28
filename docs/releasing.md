# Releasing

The plugin sets an explicit `version` in
[`.claude-plugin/plugin.json`](../.claude-plugin/plugin.json), so users only receive an update
when that version changes — pushing commits alone does not trigger one. **That is also the answer to
"is a documentation change worth a release?"**: the `skills/` a plugin installs come with it, so a
skill fix merged to `main` reaches GitHub and nobody's machine until the version moves. 0.13.1 was
exactly that and nothing else.

To cut a release, bump
`version` in `plugin.json` and `Cargo.toml`, bump the release badge near the top of [`README.md`](../README.md),
add a matching entry to
[`CHANGELOG.md`](../CHANGELOG.md), and tag the commit `vX.Y.Z`. The checklist below is the whole of
it, in order, with the three things that are not in that sentence. Pushing the tag runs
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

## The checklist

**Release prep goes straight to `main`.** It bypasses the repo's *Main Branch* ruleset (a PR plus
`Build & test` and `Documentation lint`) on admin privilege, and that is sanctioned for this and
nothing else: version bumps and a CHANGELOG section its own author wrote carry no review value, the
bypass is logged by GitHub either way, and the required checks still run on the pushed commit.
**Every other change — features, fixes, documentation, the examples — takes a PR.** Read the
ruleset with `gh api repos/glslang/windbg-mcp/rules/branches/main`; the branch-protection endpoint
404s here, because protection is a ruleset rather than branch protection, which reads as "no
protection" if you stop there.

1. **Bump four files, not three.** `Cargo.toml`, `.claude-plugin/plugin.json`, the `README.md`
   badge — and **`Cargo.lock`**, which holds this crate's own version. `cargo update -p windbg-mcp`
   does it. The workflow builds `--locked`, so a stale lock fails the release build after the
   guards have passed, which is the expensive place to find out. Leave `server.json` and
   `packaging/mcpb/manifest.json` alone: CI stamps both.

   **Not `--offline`, and not `--locked` either** — both fail here, for opposite reasons, and the
   flag that looks like the safe one is the one that breaks. `--offline` cannot check out the
   pinned `dbgscope` revision on a cache that has not already got it, so on a fresh clone it exits
   101 without touching the lock. A `cargo fetch --locked` to populate that cache first is worse:
   at this point in the checklist `Cargo.toml` is *ahead* of `Cargo.lock` by construction — that is
   the whole point of the step — so `--locked` refuses with *"cannot update the lock file … because
   --locked was passed"*. What confines the update is **`-p`**, not either flag: measured on this
   crate, the bare command reports *"45 unchanged dependencies behind latest"* and moves one line.
   `git diff Cargo.lock` is the check, and it should show exactly that line.
2. **Add the CHANGELOG section, and keep an empty `## [Unreleased]` above it.** *Renaming*
   `## [Unreleased]` to `## [X.Y.Z]` leaves the `[Unreleased]:` link definition at the foot of the
   file unreferenced, and **Documentation lint fails on MD053** — the one gate that catches release
   prep, and it catches it after the push. Add the new `[X.Y.Z]:` definition beside it and repoint
   `[Unreleased]:` at the new tag. That section *is* the GitHub release body.
3. **Dry-run both guards locally**, rather than by eye. They are twenty lines into
   [`release.yml`](../.github/workflows/release.yml) and take a second in `pwsh` — but copy them
   with one change, or the dry-run is worse than not running it. The workflow reads the tag from
   `$env:GITHUB_REF_NAME`, which Actions supplies and your shell does not, so a **verbatim** copy
   compares all three manifests against an empty string and reports a mismatch on a correct tree.
   Set `$tag` yourself. The second guard needs no tag at all: like the workflow, it takes the
   version from `Cargo.toml`, which the first guard has just pinned to the tag.

   ```pwsh
   $tag    = '0.13.1'   # the version about to be released, without the leading v
   $cargo  = [regex]::Match((Get-Content Cargo.toml -Raw), '(?ms)^\[package\].*?^version\s*=\s*"([^"]+)"').Groups[1].Value
   $plugin = (Get-Content .claude-plugin/plugin.json -Raw | ConvertFrom-Json).version
   $readme = [regex]::Match((Get-Content README.md -Raw), 'img\.shields\.io/badge/release-v([^-]+)-').Groups[1].Value
   if ($cargo -ne $tag -or $plugin -ne $tag -or $readme -ne $tag) {
     throw "Version mismatch: tag v$tag, Cargo.toml $cargo, plugin.json $plugin, README badge $readme"
   }
   if ((Get-Content CHANGELOG.md -Raw) -notmatch "(?m)^## \[$([regex]::Escape($cargo))\]") {
     throw "CHANGELOG.md has no '## [$cargo]' section"
   }
   "guards pass: $tag"
   ```

   Dry-run the lint too, with CI's own globs:
   `npx markdownlint-cli2@0.23.2 README.md CHANGELOG.md "docs/**/*.md" "skills/**/*.md"`.
4. **`claude plugin validate . --strict`** — worth running, but know what it answers. In this repo
   it validates `.claude-plugin/marketplace.json` and says so in its output; it is **not** a check
   that the version bump is consistent, and it passes just as happily before the bump as after.
   The version agreement is release.yml's guard and nothing else's.
5. **Commit, push, and wait for `main`'s CI to go green *before* tagging.** Then tag annotated —
   `git tag -a vX.Y.Z -m "Release X.Y.Z"` — and push the tag.

**Tagging is the irreversible step**, which is why it is last and why the wait is not optional: the
tag push publishes to the official MCP Registry, and a version number there is spent. A failed
build can be re-run; a published `io.github.glslang/windbg-mcp` version cannot be taken back and
reused.

## What the release is not

**It is not Authenticode signed**, so SmartScreen shows an "unknown publisher" prompt and Defender
may quarantine it — `Trojan:Win32/Bearfoos.B!ml` is the verdict this project has actually drawn, on
a locally built binary. That suffix marks a machine-learning score rather than a signature match, so
the same file lands either side of the line on different days. The attestation above does not help:
it is a supply-chain claim a user verifies deliberately, and nothing on the machine reads it. The
binary does carry a full PE version resource, which is the other cause Microsoft names for that
detection on its own binaries, but the metadata is the cheap half rather than the fix
([`FOLLOWUPS.md`](../FOLLOWUPS.md) item 50 is the certificate decision that remains).

So if a release is reported as quarantined, the fix is a **developer submission**, and it is the
maintainer's to make rather than the reporter's. At
[Microsoft's file submission portal](https://www.microsoft.com/wdsi/filesubmission), submit the
artifact as a **software developer** rather than as a customer: that route runs automated analysis
against the file and, for a clean one, clears the detection for every machine rather than for the
one that reported it — usually within hours, though nothing promises a turnaround. Point the
reporter at [`skills/windbg-debugging/setup.md`](../skills/windbg-debugging/setup.md)'s note
meanwhile: verify the SHA-256 and the attestation, and leave the file in quarantine until the
submission is answered.

Two things about that. It is **per artifact**, so every release needs its own — and the release
before it having been cleared says nothing, since an `!ml` verdict is scored on the file in front of
it. And it is the step that gets *shorter* once the binary is signed: a signature is a stable
identity for the reputation to attach to, where an unsigned build starts from nothing each time.
Worth doing pre-emptively on a release rather than waiting for the first report.
