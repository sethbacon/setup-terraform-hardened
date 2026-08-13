# setup-terraform-hardened

[![GitHub release](https://img.shields.io/github/v/release/sethbacon/setup-terraform-hardened?logo=github&label=Marketplace&color=2ea44f)](https://github.com/marketplace/actions/setup-terraform-hardened)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Install Terraform **or** OpenTofu with supply-chain verification, and add it to
PATH. No CLI wrapper is installed, so raw exit codes (e.g.
`plan -detailed-exitcode`) are preserved for drift detection.

## Inputs

| Input | Default | Notes |
|-------|---------|-------|
| `binary` | `terraform` | `terraform` or `tofu` (OpenTofu) |
| `version` | `latest` | exact version (e.g. `1.9.5`) or `latest` |
| `require-checksum` | `true` | compare the archive against the published `SHA256SUMS`; always performed when a signature is verified |
| `require-gpg-signature` | `auto` | **Terraform only** — verify `SHA256SUMS` with HashiCorp's GPG key. `auto` means `true` for `terraform`, `false` for `tofu` |
| `require-cosign-verification` | `auto` | **OpenTofu only** — verify `SHA256SUMS` with cosign. `auto` means `true` for `tofu`, `false` for `terraform`. Requires `cosign` on PATH |

Each input accepts only the values listed; anything else is an error rather than a
silently disabled check.

## What gets verified

`SHA256SUMS` is fetched from the same origin as the archive it describes, so on its
own a checksum proves the download was not corrupted in transit — not who produced
it. Authenticity comes from the signature over `SHA256SUMS`, and the two projects
have different trust roots:

- **Terraform** — `SHA256SUMS.sig` is verified against HashiCorp's release key. The
  key is vendored at [`keys/hashicorp.asc`](keys/hashicorp.asc) and pinned to
  fingerprint `C874 011F 0AB4 0511 0D02 1055 3436 5D94 72D7 468F`. The signature is
  accepted only if gpg reports it was made by that key or by one of its subkeys.
- **OpenTofu** — `SHA256SUMS.sig` and `SHA256SUMS.pem` are verified with
  `cosign verify-blob` against the OpenTofu release workflow identity and the GitHub
  Actions OIDC issuer. This needs the cosign CLI on PATH; add
  `sigstore/cosign-installer` before this step.

The signature is checked before `SHA256SUMS` is used, and the archive is always
compared against it afterwards — `require-checksum: false` is ignored (with a
warning) while a signature is being verified, because that comparison is the only
thing binding the signature to the bytes on disk.

Setting `require-gpg-signature: "false"` or `require-cosign-verification: "false"`
installs a binary whose origin has not been established. It is allowed, and it emits
a `::warning::` on every run.

## Outputs

| Output | Notes |
|--------|-------|
| `version` | resolved version installed |
| `path` | install directory (also added to PATH) |

## Examples

```yaml
# Terraform: GPG-verified, no configuration needed.
- uses: sethbacon/setup-terraform-hardened@v1
  with: { binary: terraform, version: 1.9.5 }

# OpenTofu: cosign has to be on PATH first.
- uses: sigstore/cosign-installer@v3
- uses: sethbacon/setup-terraform-hardened@v1
  with: { binary: tofu, version: latest }
```

Sources: Terraform from `releases.hashicorp.com`; OpenTofu from the
`opentofu/opentofu` GitHub releases.

## Key rotation

If HashiCorp rotates its release-signing key, both `keys/hashicorp.asc` and the
`HASHICORP_FPR` pin in `action.yml` have to be updated in the same commit, so the
key and its fingerprint stay reviewable together in one diff. `tests/run-tests.sh`
fails if they ever disagree.

## Tests

`tests/run-tests.sh` extracts the step script from `action.yml` and executes it
against fixtures, asserting that verification failures stop the install. Set
`SKIP_ONLINE=1` to skip the two cases that fetch real releases.
