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
