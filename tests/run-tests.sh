#!/usr/bin/env bash
#
# Behavioural tests for the shell implementation inside action.yml.
#
# The step script is extracted from action.yml and executed for real. Downloads
# are served by a curl test double from a per-case fixture directory, and cosign
# is stood in for by a double that matches the identity regexp the action passes
# the same way cosign matches it against the certificate SAN. Every assertion is
# an observed exit status or an observed line of output.
#
# Usage:  tests/run-tests.sh
#   SKIP_ONLINE=1    skip the cases that hit releases.hashicorp.com / github.com
#   ACTION_YML=path  run against a copy of action.yml (used for mutation checks)
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION_YML="${ACTION_YML:-$REPO_ROOT/action.yml}"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

PASS=0
FAIL=0
SEQ=0

note() { printf '\n=== %s\n' "$1"; }
pass() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n     %s\n' "$1" "$2"; }

# ---------------------------------------------------------------- extraction --
python3 - "$ACTION_YML" >"$T/install.sh" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
step = [s for s in doc["runs"]["steps"] if s.get("id") == "install"][0]
sys.stdout.write(step["run"])
PY

PIN="$(awk -F'"' '/^ *HASHICORP_FPR=/{print $2; exit}' "$T/install.sh")"
[ -n "$PIN" ] || { echo "could not read HASHICORP_FPR out of $ACTION_YML" >&2; exit 1; }

# The declared defaults are what a consumer gets from `- uses: ...@v1` with no
# `with:` block, so the default-configuration cases are driven from them rather
# than from values written out again here.
python3 - "$ACTION_YML" >"$T/defaults.env" <<'PY'
import sys, yaml
i = yaml.safe_load(open(sys.argv[1]))["inputs"]
print("DEF_CHECKSUM=%s" % i["require-checksum"]["default"])
print("DEF_GPG=%s" % i["require-gpg-signature"]["default"])
print("DEF_COSIGN=%s" % i["require-cosign-verification"]["default"])
PY
# shellcheck disable=SC1090
. "$T/defaults.env"

# The pinned fingerprint is HashiCorp's, so the GPG cases run against a copy of
# the script whose pin is a throwaway test key. The substitution is verified,
# because a silent no-op here would make the pinning cases pass vacuously.
SCRIPT="$T/install.sh"
use_pin() {
  SCRIPT="$T/install.pin-$1.sh"
  if [ ! -f "$SCRIPT" ]; then
    sed "s|^\( *\)HASHICORP_FPR=\".*\"|\1HASHICORP_FPR=\"$1\"|" "$T/install.sh" >"$SCRIPT"
    grep -q "HASHICORP_FPR=\"$1\"" "$SCRIPT" || { echo "pin substitution failed" >&2; exit 1; }
  fi
}
use_real_pin() { SCRIPT="$T/install.sh"; }

# ------------------------------------------------------------- test doubles --
mkdir -p "$T/bin" "$T/bin-cosign"

cat >"$T/bin/curl" <<'SH'
#!/usr/bin/env bash
# curl double: serves $FIXTURES/<basename of URL>, exits 22 when it is absent.
# Records its full argv to $CURL_ARGV_LOG when set, so the flags the action
# actually passes can be asserted from an observed invocation.
set -uo pipefail
[ -n "${CURL_ARGV_LOG:-}" ] && printf '%s\n' "$*" >>"$CURL_ARGV_LOG"
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    http://*|https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
[ -n "$url" ] || { echo "curl-double: no URL in args" >&2; exit 2; }
f="$FIXTURES/$(basename "${url%%\?*}")"
[ -f "$f" ] || { echo "curl-double: 404 $url" >&2; exit 22; }
if [ -n "$out" ]; then cp "$f" "$out"; else cat "$f"; fi
SH

cat >"$T/bin-cosign/cosign" <<'SH'
#!/usr/bin/env bash
# cosign double for `verify-blob`: applies --certificate-identity-regexp to
# $COSIGN_FAKE_IDENTITY, standing in for the SAN of the release certificate.
set -uo pipefail
re=""; cert=""; sig=""
while [ $# -gt 0 ]; do
  case "$1" in
    --certificate-identity-regexp) re="$2"; shift 2 ;;
    --certificate) cert="$2"; shift 2 ;;
    --signature) sig="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -f "$cert" ] || { echo "cosign-double: missing certificate" >&2; exit 1; }
[ -f "$sig" ] || { echo "cosign-double: missing signature" >&2; exit 1; }
[ "${COSIGN_FAKE_FAIL:-0}" = "1" ] && { echo "cosign-double: signature verification failed" >&2; exit 1; }
printf '%s' "${COSIGN_FAKE_IDENTITY:-}" | grep -Eq "$re" || {
  echo "cosign-double: none of the expected identities matched: ${COSIGN_FAKE_IDENTITY:-}" >&2; exit 1; }
echo "Verified OK"
SH
chmod +x "$T/bin/curl" "$T/bin-cosign/cosign"

# A PATH holding only the tools the script (and the curl double) need. There is
# no way to hide a tool that is on the real PATH, so a case that needs one of
# them absent runs against a copy of this directory with that link removed.
mkdir -p "$T/bin-min" "$T/bin-nogpg"
for t in bash env cat cp basename uname tr mktemp grep head cut awk sha256sum unzip mkdir chmod gpg; do
  p="$(command -v "$t" || true)"
  [ -n "$p" ] || { echo "test prerequisite missing: $t" >&2; exit 1; }
  ln -sf "$p" "$T/bin-min/$t"
  [ "$t" = gpg ] || ln -sf "$p" "$T/bin-nogpg/$t"
done

# ----------------------------------------------------------------- fixtures --
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; esac

# Throwaway signing keys: "good" is the one the pin names, "evil" is the key an
# attacker would smuggle into the imported bundle.
export GNUPGHOME="$T/signer"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
  --quick-generate-key "Good Signer <good@test.invalid>" default default never
gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
  --quick-generate-key "Evil Signer <evil@test.invalid>" default default never
GOOD_FPR="$(gpg --batch --with-colons --list-keys good@test.invalid | awk -F: '/^fpr:/{print $10; exit}')"
EVIL_FPR="$(gpg --batch --with-colons --list-keys evil@test.invalid | awk -F: '/^fpr:/{print $10; exit}')"
# A signing subkey on the good key reproduces the real HashiCorp shape, where
# SHA256SUMS is signed by a subkey of the pinned primary key.
gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
  --quick-add-key "$GOOD_FPR" default sign never
GOOD_SUB_FPR="$(gpg --batch --with-colons --list-keys --with-subkey-fingerprints good@test.invalid |
  awk -F: '$1=="sub"{cap=$12} $1=="fpr" && cap ~ /s/ {print $10; exit}')"
gpg --batch --quiet --armor --export good@test.invalid >"$T/good.asc"
gpg --batch --quiet --armor --export evil@test.invalid >"$T/evil.asc"
cat "$T/good.asc" "$T/evil.asc" >"$T/good-plus-evil.asc"

# mkfix_extra <fixture-dir> <binary> <version> <extra-name>
#   Same as mkfix, but the archive also carries <extra-name> — the shape a
#   tampered release would use to shadow a tool on the consumer's PATH.
mkfix_extra() {
  local dir="$1" bin="$2" ver="$3" extra="$4" stage
  rm -rf "$dir"; mkdir -p "$dir"
  stage="$T/stage.$((++SEQ))"; mkdir -p "$stage"
  printf '#!/bin/sh\necho fake %s\n' "$bin" >"$stage/$bin"
  printf '#!/bin/sh\necho SHADOWED\n' >"$stage/$extra"
  chmod +x "$stage/$bin" "$stage/$extra"
  (cd "$stage" && zip -q "$dir/${bin}_${ver}_${OS}_${ARCH}.zip" "$bin" "$extra")
  (cd "$dir" && sha256sum "${bin}_${ver}_${OS}_${ARCH}.zip" >"${bin}_${ver}_SHA256SUMS")
}

# mkfix_missing <fixture-dir> <binary> <version>
#   An archive that does NOT contain the binary the action claims to install.
mkfix_missing() {
  local dir="$1" bin="$2" ver="$3" stage
  rm -rf "$dir"; mkdir -p "$dir"
  stage="$T/stage.$((++SEQ))"; mkdir -p "$stage"
  printf '#!/bin/sh\necho SHADOWED\n' >"$stage/git"
  chmod +x "$stage/git"
  (cd "$stage" && zip -q "$dir/${bin}_${ver}_${OS}_${ARCH}.zip" git)
  (cd "$dir" && sha256sum "${bin}_${ver}_${OS}_${ARCH}.zip" >"${bin}_${ver}_SHA256SUMS")
}

# mkfix <fixture-dir> <binary> <version>  -> archive + SHA256SUMS
mkfix() {
  local dir="$1" bin="$2" ver="$3" stage
  rm -rf "$dir"; mkdir -p "$dir"
  stage="$T/stage.$((++SEQ))"; mkdir -p "$stage"
  printf '#!/bin/sh\necho fake %s\n' "$bin" >"$stage/$bin"
  chmod +x "$stage/$bin"
  (cd "$stage" && zip -q "$dir/${bin}_${ver}_${OS}_${ARCH}.zip" "$bin")
  (cd "$dir" && sha256sum "${bin}_${ver}_${OS}_${ARCH}.zip" >"${bin}_${ver}_SHA256SUMS")
}

# sign_sums <fixture-dir> <sums-file> <signing key>
sign_sums() {
  gpg --batch --quiet --yes --pinentry-mode loopback --passphrase '' \
    --local-user "$3" --detach-sign --output "$1/$2.sig" "$1/$2"
}

# tamper <fixture-dir> <zip>  -> archive no longer matches SHA256SUMS
tamper() {
  local stage="$T/tamper.$((++SEQ))"
  mkdir -p "$stage"
  printf '#!/bin/sh\necho pwned\n' >"$stage/payload"
  (cd "$stage" && zip -q "$1/$2" payload)
}

# actiondir <name> <key file>  -> a GITHUB_ACTION_PATH holding keys/hashicorp.asc
actiondir() {
  local d="$T/action.$1"
  mkdir -p "$d/keys"
  cp "$2" "$d/keys/hashicorp.asc"
  printf '%s' "$d"
}

# ------------------------------------------------------------------- runner --
STATUS=0
OUT=""
LAST=""
WITH_COSIGN=0
PATH_OVERRIDE=""

# The offline cases decide for themselves whether cosign exists, so an ambient
# cosign (developer machine, cosign-installer in CI) is filtered out of PATH.
BASE_PATH=""
while IFS= read -r d; do
  if [ -n "$d" ] && [ ! -x "$d/cosign" ]; then BASE_PATH="${BASE_PATH:+$BASE_PATH:}$d"; fi
done < <(printf '%s' "$PATH" | tr ':' '\n')

# run_step <fixture-dir> <action-dir> [VAR=VAL ...]
run_step() {
  local fixtures="$1" adir="$2"
  shift 2
  local rt="$T/run.$((++SEQ))" path="$T/bin:$BASE_PATH"
  [ "$WITH_COSIGN" = "1" ] && path="$T/bin:$T/bin-cosign:$BASE_PATH"
  [ -n "$PATH_OVERRIDE" ] && path="$T/bin:$PATH_OVERRIDE"
  mkdir -p "$rt"
  : >"$rt/github_path"
  : >"$rt/github_output"
  set +e
  env PATH="$path" FIXTURES="$fixtures" GITHUB_ACTION_PATH="$adir" \
    GITHUB_PATH="$rt/github_path" GITHUB_OUTPUT="$rt/github_output" \
    RUNNER_TEMP="$rt/install" GNUPGHOME= "$@" \
    bash "$SCRIPT" >"$rt/out" 2>&1
  STATUS=$?
  set -e
  OUT="$(cat "$rt/out")"
  LAST="$rt"
}

# run_default <fixture-dir> <action-dir> <binary> <version> [VAR=VAL ...]
# The configuration a consumer gets from `- uses: ...@v1` with no `with:` block.
run_default() {
  local fixtures="$1" adir="$2" bin="$3" ver="$4"
  shift 4
  run_step "$fixtures" "$adir" BINARY="$bin" VERSION_IN="$ver" \
    REQUIRE_CHECKSUM="$DEF_CHECKSUM" REQUIRE_GPG="$DEF_GPG" REQUIRE_COSIGN="$DEF_COSIGN" "$@"
}

# run_step_online <action-dir> [VAR=VAL ...] -- real curl, real network
run_step_online() {
  local adir="$1"
  shift
  local rt="$T/run.$((++SEQ))"
  mkdir -p "$rt"
  : >"$rt/github_path"
  : >"$rt/github_output"
  set +e
  env GITHUB_ACTION_PATH="$adir" GITHUB_PATH="$rt/github_path" \
    GITHUB_OUTPUT="$rt/github_output" RUNNER_TEMP="$rt/install" GNUPGHOME= "$@" \
    bash "$SCRIPT" >"$rt/out" 2>&1
  STATUS=$?
  set -e
  OUT="$(cat "$rt/out")"
  LAST="$rt"
}

expect_ok() { # expect_ok <name> [regex ...]
  local name="$1" re
  shift
  if [ "$STATUS" -ne 0 ]; then
    fail "$name" "expected success, got exit $STATUS: $(printf '%s' "$OUT" | tail -3 | tr '\n' '|')"
    return
  fi
  for re in "$@"; do
    if ! printf '%s\n' "$OUT" | grep -Eq "$re"; then
      fail "$name" "expected output to match /$re/: $(printf '%s' "$OUT" | tail -3 | tr '\n' '|')"
      return
    fi
  done
  pass "$name"
}

expect_fail() { # expect_fail <name> <regex>
  local name="$1" re="$2"
  if [ "$STATUS" -eq 0 ]; then
    fail "$name" "expected a non-zero exit, got 0: $(printf '%s' "$OUT" | tail -3 | tr '\n' '|')"
    return
  fi
  if ! printf '%s\n' "$OUT" | grep -Eq "$re"; then
    fail "$name" "expected output to match /$re/: $(printf '%s' "$OUT" | tail -3 | tr '\n' '|')"
    return
  fi
  pass "$name"
}

# ================================================================== the cases =
V=9.9.9
GOOD_DIR="$(actiondir good "$T/good.asc")"
BUNDLE_DIR="$(actiondir bundle "$T/good-plus-evil.asc")"

note "terraform / GPG"
use_pin "$GOOD_FPR"

# Default configuration must not install anything it cannot authenticate.
F="$T/fx-default-nosig"
mkfix "$F" terraform "$V"
run_default "$F" "$GOOD_DIR" terraform "$V"
expect_fail "default terraform run fails closed when SHA256SUMS.sig is absent" \
  '::error::could not download terraform_9\.9\.9_SHA256SUMS\.sig'

F="$T/fx-good"
mkfix "$F" terraform "$V"
sign_sums "$F" "terraform_${V}_SHA256SUMS" good@test.invalid
run_default "$F" "$GOOD_DIR" terraform "$V"
expect_ok "good path: signature by the pinned key installs" \
  'GPG signature OK' 'checksum OK' "Installed terraform $V"
grep -q "terraform-$V" "$LAST/github_path" ||
  fail "good path adds the install dir to GITHUB_PATH" "github_path is $(cat "$LAST/github_path")"
# Outputs are written in the random-delimiter heredoc form, so the value sits
# on its own line between two delimiter lines rather than after a `=`.
awk -v want="$V" '
  /^version<<ghout-/ { d = substr($0, index($0, "<<") + 2); getline v; if (v == want) ok = 1 }
  END { exit ok ? 0 : 1 }
' "$LAST/github_output" ||
  fail "good path sets the version output" "github_output is $(cat "$LAST/github_output")"

F="$T/fx-good-subkey"
mkfix "$F" terraform "$V"
sign_sums "$F" "terraform_${V}_SHA256SUMS" "$GOOD_SUB_FPR!"
run_default "$F" "$GOOD_DIR" terraform "$V"
expect_ok "good path: signature by a subkey of the pinned primary key installs" \
  "GPG signature OK \(signing key $GOOD_SUB_FPR, primary $GOOD_FPR\)"

F="$T/fx-good"
PATH_OVERRIDE="$T/bin-nogpg"
run_default "$F" "$GOOD_DIR" terraform "$V"
expect_fail "default terraform run fails closed when gpg is missing" \
  '::error::gpg not found on PATH'
PATH_OVERRIDE=""

F="$T/fx-badsig"
mkfix "$F" terraform "$V"
sign_sums "$F" "terraform_${V}_SHA256SUMS" evil@test.invalid
run_default "$F" "$GOOD_DIR" terraform "$V"
expect_fail "signature from an unknown key is rejected" \
  '::error::GPG verification of terraform_9\.9\.9_SHA256SUMS failed'

# The defect in #2: the pinned key and an attacker key both in the bundle, with
# SHA256SUMS signed by the attacker key.
run_default "$F" "$BUNDLE_DIR" terraform "$V"
expect_fail "a second key in the bundle cannot satisfy the pin" \
  "::error::terraform_9\.9\.9_SHA256SUMS was signed by $EVIL_FPR .* not the pinned HashiCorp key $GOOD_FPR"

# gpg exits 0 for a signature made by a revoked key, and VALIDSIG still names the
# pinned fingerprint, so the GOODSIG requirement is the only thing rejecting it.
gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
  --quick-generate-key "Revoked Signer <revoked@test.invalid>" default default never
REVOKED_FPR="$(gpg --batch --with-colons --list-keys revoked@test.invalid | awk -F: '/^fpr:/{print $10; exit}')"
gpg --batch --quiet --armor --export revoked@test.invalid >"$T/revoked.asc"
F="$T/fx-revoked"
mkfix "$F" terraform "$V"
sign_sums "$F" "terraform_${V}_SHA256SUMS" revoked@test.invalid
# gpg stores the auto-generated revocation certificate with every line prefixed
# by a colon, to stop it being applied by accident.
sed 's/^://' "$GNUPGHOME/openpgp-revocs.d/${REVOKED_FPR}.rev" >>"$T/revoked.asc"
use_pin "$REVOKED_FPR"
run_default "$F" "$(actiondir revoked "$T/revoked.asc")" terraform "$V"
expect_fail "signature from a revoked key is rejected" \
  '::error::no good GPG signature over terraform_9\.9\.9_SHA256SUMS'
use_pin "$GOOD_FPR"

F="$T/fx-tampered"
mkfix "$F" terraform "$V"
sign_sums "$F" "terraform_${V}_SHA256SUMS" good@test.invalid
tamper "$F" "terraform_${V}_${OS}_${ARCH}.zip"
run_default "$F" "$GOOD_DIR" terraform "$V"
expect_fail "archive that does not match the signed SHA256SUMS is rejected" \
  'FAILED|computed checksum did NOT match'

# require-checksum=false must not be able to switch off the only link between
# the authenticated SHA256SUMS and the bytes on disk.
run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN="$V" \
  REQUIRE_CHECKSUM=false REQUIRE_GPG=auto REQUIRE_COSIGN=auto
expect_fail "require-checksum=false is ignored while a signature is verified" \
  '::warning::require-checksum=false ignored'

F="$T/fx-optout"
mkfix "$F" terraform "$V"
run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN="$V" \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=false REQUIRE_COSIGN=auto
expect_ok "explicit opt-out installs unauthenticated bytes, loudly" \
  '::warning::signature verification is disabled for terraform' 'checksum OK'

run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN="$V" \
  REQUIRE_CHECKSUM=false REQUIRE_GPG=false REQUIRE_COSIGN=auto
expect_ok "opting out of everything warns about both" \
  '::warning::signature verification is disabled' '::warning::require-checksum=false: '

note "input validation"
run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN="$V" \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=True REQUIRE_COSIGN=auto
expect_fail "a mistyped boolean is an error, not a silently disabled check" \
  "::error::require-gpg-signature must be 'true', 'false' or 'auto'"

run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN="$V" \
  REQUIRE_CHECKSUM=yes REQUIRE_GPG=auto REQUIRE_COSIGN=auto
expect_fail "a mistyped require-checksum is an error" \
  "::error::require-checksum must be 'true' or 'false'"

run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN="$V" \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=auto REQUIRE_COSIGN=true
expect_fail "cosign cannot be requested for terraform" \
  '::error::require-cosign-verification applies to tofu only'

note "tofu / cosign"
use_real_pin
TOFU_ID='https://github.com/opentofu/opentofu/.github/workflows/release.yml@refs/heads/v9.9'
F="$T/fx-tofu"
mkfix "$F" tofu "$V"
: >"$F/tofu_${V}_SHA256SUMS.sig"
: >"$F/tofu_${V}_SHA256SUMS.pem"

WITH_COSIGN=0
run_default "$F" "$GOOD_DIR" tofu "$V"
expect_fail "default tofu run fails closed when the cosign CLI is missing" \
  '::error::cosign not found on PATH'

WITH_COSIGN=1
run_default "$F" "$GOOD_DIR" tofu "$V" \
  COSIGN_FAKE_IDENTITY="$TOFU_ID"
expect_ok "good path: cosign verification against the OpenTofu release identity" \
  'cosign verification OK' 'checksum OK' "Installed tofu $V"

run_default "$F" "$GOOD_DIR" tofu "$V" \
  COSIGN_FAKE_IDENTITY="$TOFU_ID" COSIGN_FAKE_FAIL=1
# The annotation, not just the exit status: a supply-chain verification failure
# that reaches the Checks UI as nothing but a tool's stderr is the one failure
# in this script a consumer most needs named.
expect_fail "failed cosign verification stops the install with an annotation" \
  '::error::cosign verification of tofu_9\.9\.9_SHA256SUMS failed'

for bad in \
  'https://github.com/opentofu/opentofu-evil/.github/workflows/release.yml@refs/heads/v9.9' \
  'https://github.com/evil/mirror?u=https://github.com/opentofu/opentofu/.github/workflows/release.yml@refs/heads/v9.9'; do
  run_default "$F" "$GOOD_DIR" tofu "$V" COSIGN_FAKE_IDENTITY="$bad"
  expect_fail "identity ${bad:19:30}… is not accepted as the OpenTofu release identity" \
    'cosign-double: none of the expected identities matched'
done

rm -f "$F/tofu_${V}_SHA256SUMS.pem"
run_default "$F" "$GOOD_DIR" tofu "$V" \
  COSIGN_FAKE_IDENTITY="$TOFU_ID"
expect_fail "a missing certificate is a failure, not a skipped check" \
  '::error::could not download tofu_9\.9\.9_SHA256SUMS\.pem'

run_step "$F" "$GOOD_DIR" BINARY=tofu VERSION_IN="$V" \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=true REQUIRE_COSIGN=auto
expect_fail "GPG cannot be requested for tofu" \
  '::error::require-gpg-signature applies to terraform only'

note "version resolution"
WITH_COSIGN=0
F="$T/fx-latest"
mkfix "$F" tofu 1.8.2
printf '{"tag_name":"v1.8.2"}\n' >"$F/latest"
run_step "$F" "$GOOD_DIR" BINARY=tofu VERSION_IN=latest \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=auto REQUIRE_COSIGN=false
expect_ok "'latest' resolves and installs the resolved version" \
  'Installing tofu 1\.8\.2' 'Installed tofu 1\.8\.2'

F="$T/fx-latest-broken"
mkfix "$F" tofu 1.8.2
printf '{"tag_name":""}\n' >"$F/latest"
run_step "$F" "$GOOD_DIR" BINARY=tofu VERSION_IN=latest \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=auto REQUIRE_COSIGN=false
expect_fail "an empty resolved version stops the install" '::error::could not resolve version'

# A release feed that does not carry a version at all trips pipefail, which is
# still fail-closed: nothing is downloaded and nothing is installed.
printf '{}\n' >"$F/latest"
run_step "$F" "$GOOD_DIR" BINARY=tofu VERSION_IN=latest \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=auto REQUIRE_COSIGN=false
if [ "$STATUS" -ne 0 ] && ! printf '%s\n' "$OUT" | grep -q 'Installed'; then
  pass "an unparseable release feed stops the install"
else
  fail "an unparseable release feed stops the install" "exit $STATUS: $OUT"
fi

# ---------------------------------------------------- install hygiene (#3) --
# $GITHUB_PATH PREPENDS, so the install directory sits ahead of /usr/bin for
# every later step in the consumer's job. The property under test is that the
# consumer receives exactly ONE vetted file, whatever the archive contained.
note "install hygiene"
WITH_COSIGN=0
use_pin "$GOOD_FPR"

# Table: <case> <fixture-builder> <extra-entry> <expectation>
F="$T/fx-extra"
mkfix_extra "$F" terraform 1.9.5 git
run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN=1.9.5 \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=false REQUIRE_COSIGN=false
if [ "$STATUS" -eq 0 ]; then
  d="$(head -1 "$LAST/github_path")"
  if [ -e "$d/git" ]; then
    fail "an extra archive entry never reaches the consumer's PATH" "$d/git exists and would shadow git"
  elif [ ! -x "$d/terraform" ]; then
    fail "an extra archive entry never reaches the consumer's PATH" "terraform missing from $d"
  elif [ "$(find "$d" -type f | wc -l)" -ne 1 ]; then
    fail "an extra archive entry never reaches the consumer's PATH" "expected exactly 1 file in $d, found: $(find "$d" -type f | tr '\n' ' ')"
  else
    pass "an extra archive entry never reaches the consumer's PATH"
  fi
else
  fail "an extra archive entry never reaches the consumer's PATH" "exit $STATUS: $(printf '%s' "$OUT" | tail -2 | tr '\n' '|')"
fi

F="$T/fx-missing"
mkfix_missing "$F" terraform 1.9.5
run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN=1.9.5 \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=false REQUIRE_COSIGN=false
expect_fail "an archive without the expected binary stops the install" \
  '::error::archive did not contain the expected terraform binary'

# mkdir -p ADOPTS an existing directory and unzip -o only overwrites entries
# that are in the archive, so a stale file used to survive into PATH.
F="$T/fx-stale"
mkfix "$F" terraform 1.9.5
rt_pre="$T/pre-install"
mkdir -p "$rt_pre/install/terraform-1.9.5"
printf '#!/bin/sh\necho STALE\n' >"$rt_pre/install/terraform-1.9.5/node"
chmod +x "$rt_pre/install/terraform-1.9.5/node"
set +e
env PATH="$T/bin:$BASE_PATH" FIXTURES="$F" GITHUB_ACTION_PATH="$GOOD_DIR" \
  GITHUB_PATH="$rt_pre/github_path" GITHUB_OUTPUT="$rt_pre/github_output" \
  RUNNER_TEMP="$rt_pre/install" GNUPGHOME= \
  BINARY=terraform VERSION_IN=1.9.5 REQUIRE_CHECKSUM=true REQUIRE_GPG=false REQUIRE_COSIGN=false \
  bash "$SCRIPT" >"$rt_pre/out" 2>&1
st=$?
set -e
if [ "$st" -eq 0 ] && [ ! -e "$rt_pre/install/terraform-1.9.5/node" ]; then
  pass "a pre-existing file in the install directory does not survive into PATH"
else
  fail "a pre-existing file in the install directory does not survive into PATH" \
    "exit $st; node still present: $([ -e "$rt_pre/install/terraform-1.9.5/node" ] && echo yes || echo no)"
fi

# ------------------------------------------ runner file-command boundary (#4) --
# $GITHUB_PATH and $GITHUB_OUTPUT are parsed line by line. The primary control
# is the version shape assertion; the delimiter form is the second layer.
note "runner file-command boundary"
F="$T/fx-boundary"
mkfix "$F" terraform 1.9.5

# Table: every version an action input can legally carry that must be refused.
for bad_case in \
  'newline:1.9.5
path=/evil' \
  'carriage-return:1.9.5\rpath=/evil' \
  'space:1.9.5 evil' \
  'semicolon:1.9.5;id' \
  'slash:1.9.5/../../etc'
do
  label="${bad_case%%:*}"; val="${bad_case#*:}"
  val="$(printf '%b' "$val")"
  run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN="$val" \
    REQUIRE_CHECKSUM=true REQUIRE_GPG=false REQUIRE_COSIGN=false
  if [ "$STATUS" -ne 0 ] && printf '%s\n' "$OUT" | grep -q '::error::version must contain only'; then
    pass "version with a $label is refused"
  else
    fail "version with a $label is refused" "exit $STATUS: $(printf '%s' "$OUT" | tail -2 | tr '\n' '|')"
  fi
done

run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN=1.9.5 \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=false REQUIRE_COSIGN=false
if [ "$STATUS" -eq 0 ]; then
  # Exactly the two documented outputs, each in delimiter form, and no forged
  # third key. Counting `<<` keys is what distinguishes the safe form.
  keys="$(grep -c '<<ghout-' "$LAST/github_output" || true)"
  lines="$(wc -l <"$LAST/github_path")"
  if [ "$keys" -ne 2 ]; then
    fail "outputs are written in the random-delimiter form" "expected 2 delimiter key lines (version, path), got $keys"
  elif [ "$lines" -ne 1 ]; then
    fail "outputs are written in the random-delimiter form" "expected exactly 1 PATH line, got $lines"
  elif grep -Eq '^(version|path)=' "$LAST/github_output"; then
    fail "outputs are written in the random-delimiter form" "unsafe key=value form still present"
  else
    pass "outputs are written in the random-delimiter form"
  fi
else
  fail "outputs are written in the random-delimiter form" "exit $STATUS"
fi

# ------------------------------------------------------ fetch hardening (#6) --
# Asserted from the double's observed argv, not by grepping the script: the
# question is what the action actually passed to curl.
note "fetch hardening"
F="$T/fx-flags"
mkfix "$F" terraform 1.9.5
ARGV_LOG="$T/curl-argv.log"; : >"$ARGV_LOG"
export CURL_ARGV_LOG="$ARGV_LOG"
run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN=1.9.5 \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=false REQUIRE_COSIGN=false
unset CURL_ARGV_LOG
missing=""
for flag in -- '--proto =https' '--proto-redir =https' '--max-redirs 3' \
  '--connect-timeout 10' '--max-time 300' '--retry 3' '--retry-all-errors'
do
  [ "$flag" = "--" ] && continue
  while read -r line; do
    [ -z "$line" ] && continue
    printf '%s\n' "$line" | grep -q -- "$flag" || missing="$missing [$flag]"
  done <"$ARGV_LOG"
done
if [ -z "$missing" ] && [ -s "$ARGV_LOG" ]; then
  pass "every fetch is protocol-pinned, bounded and retrying"
else
  fail "every fetch is protocol-pinned, bounded and retrying" "missing on some invocation:$missing"
fi

# The two version-API bodies are read into a command substitution, so they also
# need a size ceiling. Only those fetches should carry it.
F="$T/fx-latest-flags"
mkfix "$F" tofu 1.8.2
printf '{"tag_name":"v1.8.2"}\n' >"$F/latest"
LATEST_LOG="$T/curl-argv-latest.log"; : >"$LATEST_LOG"
export CURL_ARGV_LOG="$LATEST_LOG"
run_step "$F" "$GOOD_DIR" BINARY=tofu VERSION_IN=latest \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=false REQUIRE_COSIGN=false
unset CURL_ARGV_LOG
if grep -q -- '--max-filesize' "$LATEST_LOG"; then
  pass "the version-API fetch carries a response size ceiling"
else
  fail "the version-API fetch carries a response size ceiling" \
    "no --max-filesize in: $(head -1 "$LATEST_LOG")"
fi

# --------------------------------------------------- release-feed parsing (#5) --
# checkpoint-api returns compact JSON; api.github.com PRETTY-PRINTS. A pattern
# written for the compact shape matched nothing against the pretty one, and the
# only fixture in this suite was compact — so the suite could not tell a working
# parser from one that fails for every `binary: tofu` + `version: latest`
# consumer, which is the manifest's own default.
note "release-feed parsing"
WITH_COSIGN=0
F="$T/fx-latest-pretty"
mkfix "$F" tofu 1.8.2
printf '{\n  "url": "https://api.github.com/repos/opentofu/opentofu/releases/1",\n  "tag_name": "v1.8.2",\n  "name": "v1.8.2"\n}\n' >"$F/latest"
run_step "$F" "$GOOD_DIR" BINARY=tofu VERSION_IN=latest \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=auto REQUIRE_COSIGN=false
expect_ok "pretty-printed release JSON resolves 'latest' (the shape api.github.com returns)" \
  'Installing tofu 1\.8\.2' 'Installed tofu 1\.8\.2'

# The compact shape must keep working: checkpoint-api still returns it.
F="$T/fx-latest-compact"
mkfix "$F" terraform 1.8.2
printf '{"product":"terraform","current_version":"1.8.2","current_release":1783532758}\n' >"$F/terraform"
run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN=latest \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=false REQUIRE_COSIGN=auto
expect_ok "compact release JSON resolves 'latest' (the shape checkpoint-api returns)" \
  'Installing terraform 1\.8\.2' 'Installed terraform 1\.8\.2'

# The token must not be reachable from another process's view of this one.
F="$T/fx-latest-token"
mkfix "$F" tofu 1.8.2
# Compact on purpose, so this case fails only for a token-handling regression and
# not also for a parser one.
printf '{"tag_name":"v1.8.2"}\n' >"$F/latest"
TOKEN_LOG="$T/curl-argv-token.log"; : >"$TOKEN_LOG"
export CURL_ARGV_LOG="$TOKEN_LOG"
run_step "$F" "$GOOD_DIR" BINARY=tofu VERSION_IN=latest \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=auto REQUIRE_COSIGN=false \
  GH_TOKEN_IN=ghs_SENTINELTOKENVALUE
unset CURL_ARGV_LOG
if [ "$STATUS" -eq 0 ] && ! grep -q 'SENTINELTOKENVALUE' "$TOKEN_LOG" && grep -q -- '--config' "$TOKEN_LOG"; then
  pass "github-token never appears in curl's argv"
else
  fail "github-token never appears in curl's argv" \
    "exit $STATUS; argv log: $(head -2 "$TOKEN_LOG" | tr '\n' '|')"
fi

# ------------------------------------------------- checksum line selection (#6) --
# $zip was interpolated into a grep BRE, so its dots matched any character. A
# SHA256SUMS carrying a near-miss filename therefore selected two lines, and the
# whole run failed on the decoy rather than verifying the real archive.
note "checksum line selection"
F="$T/fx-decoy"
mkfix "$F" terraform 1.9.5
{
  printf '%s  terraform_1x9y5_%s_%s.zip\n' "$(printf 'd%.0s' $(seq 64))" "$OS" "$ARCH"
  cat "$F/terraform_1.9.5_SHA256SUMS"
} >"$F/sums.new"
mv "$F/sums.new" "$F/terraform_1.9.5_SHA256SUMS"
run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN=1.9.5 \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=false REQUIRE_COSIGN=false
expect_ok "a near-miss filename in SHA256SUMS does not change which line is verified" \
  'checksum OK' 'Installed terraform 1\.9\.5'

F="$T/fx-nosuchline"
mkfix "$F" terraform 1.9.5
: >"$F/terraform_1.9.5_SHA256SUMS"
run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN=1.9.5 \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=false REQUIRE_COSIGN=false
expect_fail "a SHA256SUMS with no entry for the archive fails with an annotation" \
  '::error::checksum verification of terraform_1\.9\.5'

# ------------------------------------------------------- runner preconditions --
# The install directory is prepended to the PATH of every later step, so the
# fallback that used to fire here put a predictable path inside a world-writable
# directory at the front of it.
note "runner preconditions"
F="$T/fx-runnertemp"
mkfix "$F" terraform 1.9.5
rt="$T/run.rt"; mkdir -p "$rt"; : >"$rt/github_path"; : >"$rt/github_output"
# `env -u`, not merely omitting it: a real runner has RUNNER_TEMP in the ambient
# environment, so an assertion that only leaves it out of the explicit list
# passes locally and proves nothing in CI.
set +e
env -u RUNNER_TEMP PATH="$T/bin:$BASE_PATH" FIXTURES="$F" GITHUB_ACTION_PATH="$GOOD_DIR" \
  GITHUB_PATH="$rt/github_path" GITHUB_OUTPUT="$rt/github_output" GNUPGHOME= \
  BINARY=terraform VERSION_IN=1.9.5 REQUIRE_CHECKSUM=true REQUIRE_GPG=false REQUIRE_COSIGN=false \
  bash "$SCRIPT" >"$rt/out" 2>&1
STATUS=$?
set -e
OUT="$(cat "$rt/out")"
expect_fail "an unset RUNNER_TEMP fails closed rather than installing into /tmp" \
  '::error::RUNNER_TEMP is not set'

# `:-` fired when the variable was unset OR EMPTY, so both shapes are cases.
run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN=1.9.5 \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=false REQUIRE_COSIGN=false RUNNER_TEMP=
expect_fail "an empty RUNNER_TEMP fails closed rather than installing into /tmp" \
  '::error::RUNNER_TEMP is not set'

PATH_OVERRIDE="$T/bin-nounzip"
mkdir -p "$T/bin-nounzip"
for t in bash env cat cp basename uname tr mktemp grep head cut awk sha256sum mkdir chmod install rm; do
  p="$(command -v "$t" || true)"
  [ -n "$p" ] && ln -sf "$p" "$T/bin-nounzip/$t"
done
run_step "$F" "$GOOD_DIR" BINARY=terraform VERSION_IN=1.9.5 \
  REQUIRE_CHECKSUM=true REQUIRE_GPG=false REQUIRE_COSIGN=false
expect_fail "a missing unzip is diagnosed instead of dying as 'command not found'" \
  '::error::unzip not found on PATH'
PATH_OVERRIDE=""

# A composite action has no post: hook, so the only thing that removes the
# downloaded archive, SHA256SUMS and the imported keyring is the EXIT trap.
F="$T/fx-cleanup"
mkfix "$F" terraform "$V"
sign_sums "$F" "terraform_${V}_SHA256SUMS" good@test.invalid
use_pin "$GOOD_FPR"
SCRATCH="$T/scratch-tmp"; rm -rf "$SCRATCH"; mkdir -p "$SCRATCH"
run_default "$F" "$GOOD_DIR" terraform "$V" TMPDIR="$SCRATCH"
if [ "$STATUS" -eq 0 ] && [ -z "$(ls -A "$SCRATCH")" ]; then
  pass "the work directory (archive, sums, keyring) is removed when the step exits"
else
  fail "the work directory (archive, sums, keyring) is removed when the step exits" \
    "exit $STATUS; left behind: $(ls -A "$SCRATCH" | tr '\n' ' ')"
fi

note "action manifest"
# The vendored key and the pin have to be the same key, or the terraform default
# path fails for every consumer.
(
  export GNUPGHOME="$T/vendored"
  mkdir -p "$GNUPGHOME"
  chmod 700 "$GNUPGHOME"
  gpg --batch --quiet --import "$REPO_ROOT/keys/hashicorp.asc"
  got="$(gpg --batch --with-colons --fingerprint | awk -F: '/^fpr:/{print $10; exit}')"
  [ "$got" = "$PIN" ] || { echo "vendored key is $got, pin is $PIN"; exit 1; }
) && pass "vendored key matches the pinned fingerprint" ||
  fail "vendored key matches the pinned fingerprint" "keys/hashicorp.asc does not match HASHICORP_FPR"

# A composite action's ${{ }} expressions are substituted into the script text
# before bash parses it, so inputs must only ever arrive through env:.
if grep -q '\${{' "$T/install.sh"; then
  fail "no expression interpolation inside the run script" "$(grep -n '\${{' "$T/install.sh" | head -3)"
else
  pass "no expression interpolation inside the run script"
fi

python3 - "$ACTION_YML" <<'PY' && pass "advertised defaults are the fail-closed ones" ||
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
i = d["inputs"]
assert i["require-checksum"]["default"] == "true", i["require-checksum"]
assert i["require-gpg-signature"]["default"] == "auto", i["require-gpg-signature"]
assert i["require-cosign-verification"]["default"] == "auto", i["require-cosign-verification"]
assert len(d["description"]) <= 125, len(d["description"])
PY
  fail "advertised defaults are the fail-closed ones" "action.yml defaults changed"

# ------------------------------------------------------------------- online --
if [ "${SKIP_ONLINE:-0}" = "1" ]; then
  note "online (skipped: SKIP_ONLINE=1)"
else
  note "online"
  use_real_pin
  run_step_online "$REPO_ROOT" BINARY=terraform VERSION_IN=1.9.5 \
    REQUIRE_CHECKSUM="$DEF_CHECKSUM" REQUIRE_GPG="$DEF_GPG" REQUIRE_COSIGN="$DEF_COSIGN"
  expect_ok "real terraform release verifies against the vendored HashiCorp key" \
    "GPG signature OK \(signing key 374EC75B485913604A831CC7C820C6D5CD27AB87, primary $PIN\)" \
    'checksum OK' 'Installed terraform 1\.9\.5'

  if command -v cosign >/dev/null 2>&1; then
    run_step_online "$REPO_ROOT" BINARY=tofu VERSION_IN=1.8.2 \
      REQUIRE_CHECKSUM="$DEF_CHECKSUM" REQUIRE_GPG="$DEF_GPG" REQUIRE_COSIGN="$DEF_COSIGN"
    expect_ok "real OpenTofu release verifies with cosign against the release identity" \
      'cosign verification OK' 'checksum OK' 'Installed tofu 1\.8\.2'
  else
    printf 'skip cosign online case (cosign not on PATH)\n'
  fi
fi

# ------------------------------------------------------- SIGPIPE under pipefail --
# An early-exiting READER under `set -o pipefail` is an intermittent exit 141:
# it closes the pipe once it has what it needs, and any LATER write upstream
# takes SIGPIPE. It only bites when the writer's output is split across writes
# with a gap between them -- `terraform version` writes its version line,
# consults the upgrade-notice service, then writes the platform line -- so it
# reads as flake rather than breakage. It failed this repo's own CI twice on
# 2026-08-24, passing in between, and left main red for three days.
#
# Early-exiting readers: `head -N`, `grep -q`, `grep -m N`.
# `tail -N` is NOT one -- it must consume to EOF to know which lines are last,
# so it never closes early. Flagging it would be a false positive; the sibling
# repo terraform-drift-contract has a legitimate `npm pack | tail -n1`.
# A `printf`/`echo` writer is likewise exempt: one small buffered write always
# completes before the reader can exit.
#
# Scanned as text on purpose: the defect is the SHAPE of the pipeline, and every
# file here that runs under pipefail is shell embedded in YAML, which no shell
# linter reads.
sigpipe_scan() {
  grep -rnE '\|[[:space:]]*(head[[:space:]]+-|grep([[:space:]]+-[a-zA-Z]*)*[[:space:]]+-(q|m)\b)' "$@" 2>/dev/null \
    | grep -vE '^[^:]*:[0-9]+:[[:space:]]*#' \
    | grep -vE '(printf|echo)[^|]*\|' || true
}

note "no SIGPIPE-prone pipelines under pipefail"
# Count the universe before trusting a clean result. A mis-pathed or emptied
# scan produces no hits and is indistinguishable from a repo with no defects --
# the exact way this guard was observed to pass while examining nothing.
sigpipe_targets="$REPO_ROOT/action.yml $REPO_ROOT/.github/workflows"
# shellcheck disable=SC2086  # deliberate word-splitting: two search roots
sigpipe_files=$(find $sigpipe_targets -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | wc -l || true)
sigpipe_hits=$(sigpipe_scan "$REPO_ROOT/action.yml" "$REPO_ROOT/.github/workflows")
if [ "$sigpipe_files" -lt 3 ]; then
  fail "no SIGPIPE-prone pipelines under pipefail" \
    "scanned $sigpipe_files file(s) -- the universe is empty or mis-pathed, so a clean result means nothing"
elif [ -n "$sigpipe_hits" ]; then
  fail "no SIGPIPE-prone pipelines under pipefail" "$sigpipe_hits"
else
  pass "no SIGPIPE-prone pipelines under pipefail ($sigpipe_files files scanned)"
fi

# Guards the guard, in BOTH directions, with each probe carrying EXACTLY ONE
# shape. A probe holding both (`cmd | head -1 | grep -q x`) still matches after
# the scanner is blinded to one of them, so it cannot show which branch works --
# that mistake made an earlier version of this test certify a blind scanner.
sigpipe_probe="$T/sigpipe-probe"
mkdir -p "$sigpipe_probe"
printf 'run: |\n  set -euo pipefail\n  terraform version | head -1\n' >"$sigpipe_probe/bad-head.yml"
printf 'run: |\n  set -euo pipefail\n  some_cmd | grep -q x\n'        >"$sigpipe_probe/bad-grepq.yml"
printf 'run: |\n  set -euo pipefail\n  npm pack --silent | tail -n1\n' >"$sigpipe_probe/ok-tail.yml"
printf 'run: |\n  set -euo pipefail\n  printf "%%s" "$x" | grep -q y\n' >"$sigpipe_probe/ok-printf.yml"

sigpipe_head=$(sigpipe_scan "$sigpipe_probe/bad-head.yml")
sigpipe_grepq=$(sigpipe_scan "$sigpipe_probe/bad-grepq.yml")
sigpipe_safe=$(sigpipe_scan "$sigpipe_probe/ok-tail.yml" "$sigpipe_probe/ok-printf.yml")
if [ -n "$sigpipe_head" ] && [ -n "$sigpipe_grepq" ] && [ -z "$sigpipe_safe" ]; then
  pass "the SIGPIPE scanner catches head and grep -q, and neither safe shape"
else
  fail "the SIGPIPE scanner catches head and grep -q, and neither safe shape" \
    "head=[$sigpipe_head] grepq=[$sigpipe_grepq] safe=[$sigpipe_safe]"
fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
