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
| `require-checksum` | `true` | verify the archive against the published `SHA256SUMS` |
| `require-gpg-signature` | `false` | **Terraform only** — verify `SHA256SUMS` with HashiCorp's GPG key (fingerprint asserted before use) |
| `require-cosign-verification` | `false` | **OpenTofu only** — verify with cosign; requires `cosign` on PATH (add `sigstore/cosign-installer` first) |

## Outputs

| Output | Notes |
|--------|-------|
| `version` | resolved version installed |
| `path` | install directory (also added to PATH) |

## Examples

```yaml
- uses: sethbacon/setup-terraform-hardened@v1
  with: { binary: terraform, version: 1.9.5, require-gpg-signature: "true" }

- uses: sigstore/cosign-installer@v3
- uses: sethbacon/setup-terraform-hardened@v1
  with: { binary: tofu, version: latest, require-cosign-verification: "true" }
```

Sources: Terraform from `releases.hashicorp.com`; OpenTofu from the
`opentofu/opentofu` GitHub releases.
