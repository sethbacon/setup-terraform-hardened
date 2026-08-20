# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities through GitHub's private vulnerability
reporting on this repository (**Security → Report a vulnerability**). Please do
not open a public issue for an unfixed vulnerability.

Include the action version or commit SHA, the inputs in use, and what an
attacker would gain. You should get an acknowledgement within a few days.

## Supported versions

Fixes land on `main` and ship in the next `v1.x` tag. The floating `v1` alias is
moved by the release workflow to the newest `v1.x`, so a consumer pinned to `v1`
picks the fix up on its next run. Older majors are not maintained.

| Version | Supported |
| ------- | --------- |
| `v1.x`  | yes       |

## What this action does and does not guarantee

Worth stating plainly, because the guarantees are narrower than the name
suggests:

- **Signature verification covers `SHA256SUMS`, not the archive.** Both the GPG
  path (Terraform) and the cosign path (OpenTofu) authenticate the checksum
  file. What binds the downloaded archive to that authenticated file is the
  separate checksum comparison, so `require-checksum` is not independent of the
  two signature toggles — it is the second half of the same control. The action
  forces `require-checksum` back on when either signature check is enabled, and
  warns when it does.
- **Disabling signature verification leaves transfer integrity only.**
  `SHA256SUMS` is fetched from the same origin, over the same channel, as the
  archive. With `require-gpg-signature: "false"` (or the cosign equivalent) a
  run proves the bytes arrived intact, not that they came from HashiCorp or the
  OpenTofu project. The action emits a warning saying so.
- **The GPG trust root is vendored, not fetched.** `keys/hashicorp.asc` is
  committed here and a signature is accepted only when gpg reports the pinned
  fingerprint as the signing key or its primary key. Rotating that key is a
  reviewed change to this repository.
- **`cosign` must already be on PATH.** The action does not install it; add
  `sigstore/cosign-installer` before this step. It fails closed rather than
  skipping verification if cosign is absent.

## Pinning

For supply-chain-sensitive workflows, pin this action to a full commit SHA
rather than to `@v1`. See the README's "Pinning this action" section — `@v1` is
a mutable pointer that this repository's maintainers can move.

## Shared CI workflows

Part of this repository's CI is **defined in another repository** — [`4cloudguru/shared-workflows`](https://github.com/4cloudguru/shared-workflows) — and called from `.github/workflows/`. That is a real supply-chain relationship, and it is recorded here so an audit of this repository does not stop at this repository's own tree.

**What runs, and where it is pinned.** Each caller in `.github/workflows/` names the shared workflow on its `uses:` line, pinned to a full 40-hex commit SHA with a trailing comment naming the release that SHA is. The tag is a label; the SHA is what runs. An unlabelled SHA is rejected by the workflow-hardening gate, because a bare 40-hex ref cannot be reviewed or updated deliberately.

**Why the pins have to agree across repositories.** A shared definition drifts differently from a duplicated file: every repository looks like it is using "the shared one" while sitting on different commits, which is *harder* to see than divergent files, not easier. A signature in `security-orchestration` (`shared-workflow-pin-parity`) reports **disagreement** between callers of the same shared workflow — it reports disagreement rather than staleness, because a repository deliberately held back is a decision while N repositories disagreeing without anyone deciding is drift.

**What the shared repository is itself protected by.** Its `main` requires its own zizmor and actionlint checks with `enforce_admins` enabled, restricts which third-party actions may run to an explicit allowlist, issues a read-only default `GITHUB_TOKEN`, and runs the workflow-hardening gate against itself.

**What this repository still controls.** Triggers, concurrency, and the secrets it passes. Secrets are passed **by name** — never `secrets: inherit`, which would forward every secret in this repository to a workflow owned by someone else. Any `vars.*` a shared workflow reads resolve against **this** repository, so credentials and their installation scope do not move.
