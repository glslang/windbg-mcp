---
paths:
  - "**/*.md"
---

**Two of CI's gates are not Rust and both run on a Mac in seconds**, which matters because this repo
is edited from one and compiled on a VM — so the checks that need no Windows are the cheapest ones
to forget. `cargo fmt --all --check` is the first step of *Build & test*. The other is
**`Documentation lint`**, a markdownlint over `README.md`, `CHANGELOG.md`, `docs/**` and
`skills/**` — note `CLAUDE.md`, `FOLLOWUPS.md`, `DONE.md` and everything under `.claude/` are
**not** in its globs, so a clean run says nothing about them. `skills/**` is the *shipped* plugin
skill; `.claude/skills/` is this repo's own guidance and is unlinted like the rules beside it. `.markdownlint.jsonc` — *not* `.markdownlint-cli2.jsonc`, which does not exist
here — turns off three of the defaults and leaves every other one on: no line-length rule (MD013),
no table-pipe spacing (MD060), and duplicate headings flagged only among siblings (MD024), which is
what lets `CHANGELOG.md` repeat `### Added` under every version. **MD051 — a link fragment with no
matching heading — is the one that has actually bitten**, because it is what *renaming a heading*
does to every in-file link pointing at it, and it cost a red round on #196; it is not the only rule
that can fail the job. Same version as CI:

```console
npx markdownlint-cli2@0.23.2 README.md CHANGELOG.md "docs/**/*.md" "skills/**/*.md"
```

It checks *same-file* fragments only, so a cross-file `../README.md#some-heading` is still yours to
verify by hand.

