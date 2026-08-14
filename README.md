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
| `github-token` | `""` | only used to resolve `version: latest` for OpenTofu. Pass `${{ github.token }}` — see [Rate limiting](#rate-limiting) |

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

Both are safe to interpolate into a later `run:` block. That is a property of the
action, not an accident: with `version: latest` the version string arrives from a
network response, so it is asserted to contain only letters, digits, `.`, `_`,
`+` and `-` before it is written to `$GITHUB_OUTPUT`, and the install path is
rejected if it carries anything outside that set plus `/`. Neither can carry a
newline, a quote or a shell metacharacter into your workflow.

If you install the **same binary twice in one job** at two different versions,
both install directories end up on `PATH` and a bare `terraform` resolves to
whichever `$GITHUB_PATH` prepended last. Reference `steps.<id>.outputs.path`
explicitly in that case — the outputs are per-step and unambiguous.

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

## Network egress

If you run this action behind an egress allow-list (`step-security/harden-runner`
in block mode, a corporate proxy, or a restrictive NAT policy), this is the
complete set of hosts it contacts. An allow-list built from the examples above
rather than from this table is how a hardened runner ends up with the policy
turned off.

| Host | When |
|------|------|
| `checkpoint-api.hashicorp.com` | only `binary: terraform` with `version: latest` |
| `api.github.com` | only `binary: tofu` with `version: latest` |
| `releases.hashicorp.com` | every `binary: terraform` run (archive, `SHA256SUMS`, `.sig`) |
| `github.com` | every `binary: tofu` run — issues the download, then redirects |
| `release-assets.githubusercontent.com` | the redirect target that actually serves OpenTofu assets. GitHub has changed this host before; it appears in no source file here |
| `fulcio.sigstore.dev`, `rekor.sigstore.dev`, `tuf-repo-cdn.sigstore.dev` | reached by `cosign verify-blob`, not by this action, whenever cosign verification runs |

No GPG key is fetched at run time — HashiCorp's is vendored at
[`keys/hashicorp.asc`](keys/hashicorp.asc).

Pinning an explicit `version` removes the first two rows entirely. Note that
`checkpoint-api.hashicorp.com` is HashiCorp's version-check/telemetry endpoint,
so a default-configured `binary: terraform` run reports in to it.

### Rate limiting

The OpenTofu `latest` lookup calls `api.github.com`. Unauthenticated, that is
capped at **60 requests/hour per source IP** — and a hosted runner's egress
address is shared with every other tenant on it, so the call fails intermittently
with a 403. Pass a token to raise it to 1,000/hour for your repository:

```yaml
- uses: sethbacon/setup-terraform-hardened@v1
  with:
    binary: tofu
    version: latest
    github-token: ${{ github.token }}
```

`contents: read` is sufficient, and the token is sent to `api.github.com` and
nowhere else. It is passed to curl through a config file rather than on the
command line, so it does not appear in the process's arguments.

### `version: latest` trusts an unauthenticated feed

`latest` is resolved from `checkpoint-api.hashicorp.com` (Terraform) or
`api.github.com` (OpenTofu). Neither response is signed, and **none of the three
verification controls detects a rollback**: an attacker who can influence that
response names an older version, and the action then downloads a genuine,
correctly checksummed, correctly signed release of it. Checksum, GPG and cosign
all establish authenticity; none of them establishes freshness. The resolved
version is logged on every run (`Installing terraform 1.9.5 (linux/amd64)`).

For production workflows, pin an explicit `version`.

## Differences from the upstream actions

This action is deliberately narrower than
[`hashicorp/setup-terraform`](https://github.com/hashicorp/setup-terraform) and
[`opentofu/setup-opentofu`](https://github.com/opentofu/setup-opentofu). If you
are migrating from either:

- **No version constraint syntax.** `version` takes an exact version or
  `latest`; ranges such as `~1.1.0` or `<1.2.0` are not parsed.
- **No tool caching.** Every run downloads and verifies the release. There is no
  `cache` input and no use of the Actions tool cache.
- **No `*_version_file` input.**
- **No CLI wrapper.** `hashicorp/setup-terraform` installs a wrapper that
  captures stdout/stderr and changes exit codes; this action does not, which is
  the point — `plan -detailed-exitcode` keeps its raw exit code.
- **No credentials handling.** `cli_config_credentials_token` has no equivalent
  here.

What it adds in exchange is the verification described above: a vendored,
pinned GPG trust root, cosign verification against the OpenTofu release
identity, and defaults that fail closed.

Sources: Terraform from `releases.hashicorp.com`; OpenTofu from the
`opentofu/opentofu` GitHub releases.

## Pinning this action

The examples above use `@v1` for readability. **`v1` is a mutable tag** — this
repository's maintainers move it to each new `v1.x`, so what your workflow
executes changes without any diff on your side. That is a convenience, and it is
a trust decision you are making about this repository.

For supply-chain-sensitive workflows, pin the full commit SHA instead:

```yaml
- uses: sethbacon/setup-terraform-hardened@<full-40-char-sha> # v1.0.0
  with: { binary: terraform, version: 1.9.5 }
```

The trailing comment is what makes the pin maintainable — Dependabot reads it,
and so does the next human. The tradeoff is the mirror image of `@v1`: a SHA pin
never changes under you, and it never picks up a fix either, so it needs
updating deliberately.

Releases are cut by [`release.yml`](.github/workflows/release.yml), which
re-runs the full test suite against the tagged tree, refuses a tag that is not
reachable from `main`, emits a
[build-provenance attestation](https://docs.github.com/actions/security-guides/using-artifact-attestations)
over `action.yml` and the vendored key, and only then moves the `v1` alias. You
can verify a release with:

```bash
gh attestation verify --owner sethbacon --repo setup-terraform-hardened action.yml
```

## Key rotation

If HashiCorp rotates its release-signing key, both `keys/hashicorp.asc` and the
`HASHICORP_FPR` pin in `action.yml` have to be updated in the same commit, so the
key and its fingerprint stay reviewable together in one diff. `tests/run-tests.sh`
fails if they ever disagree.

## Tests

`tests/run-tests.sh` extracts the step script from `action.yml` and executes it
against fixtures, asserting that verification failures stop the install. Set
`SKIP_ONLINE=1` to skip the two cases that fetch real releases.
