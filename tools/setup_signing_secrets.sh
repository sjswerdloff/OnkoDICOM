#!/bin/bash
# Stores everything the package workflow needs to sign and notarise the macOS installer as GitHub
# secrets on sjswerdloff/OnkoDICOM (copied from midst-editor, only REPO changed). Run it on a Mac, giving it the folder that holds:
#   developer_id_application.key / .cer   Developer ID Application private key and certificate
#   developer_id_installer.key / .cer     Developer ID Installer private key and certificate
#   AuthKey_<KeyID>.p8                    App Store Connect TEAM API key (for notarisation)
#   issuer_id.txt                         the Issuer ID shown with that key
#
#     bash tools/setup_signing_secrets.sh ~/midst-signing
#
# Needs: gh, signed in as the owner of sjswerdloff/OnkoDICOM (brew install gh; gh auth login). It asks
# nothing. It checks each certificate matches its key and comes from Apple's G2 authority, builds
# a .p12 for each with a random password that only ever exists in GitHub, and sets seven secrets:
#   CSC_LINK, CSC_KEY_PASSWORD, CSC_INSTALLER_LINK, CSC_INSTALLER_KEY_PASSWORD,
#   APPLE_API_KEY, APPLE_API_KEY_ID, APPLE_API_ISSUER
# Running it again replaces them, which is how credentials are rotated. The step-by-step process,
# including making the keys and certificates, is in midst-editor docs/macos-signing.md.
set -euo pipefail

REPO=sjswerdloff/OnkoDICOM
OPENSSL=/usr/bin/openssl   # macOS LibreSSL: its .p12 output is what `security import` accepts
[ $# -eq 1 ] || { echo "usage: $0 <folder holding the keys and certificates>" >&2; exit 2; }
cd "$1"

die() { echo "ERROR: $*" >&2; exit 1; }

command -v gh >/dev/null || die "gh is not installed: brew install gh && gh auth login"
gh auth status >/dev/null 2>&1 || die "gh is not signed in: gh auth login"
gh api "repos/$REPO" --jq .full_name >/dev/null 2>&1 || die "gh cannot see $REPO with this account"

for f in developer_id_application developer_id_installer; do
  for ext in key cer; do [ -f "$f.$ext" ] || die "missing $f.$ext in $(pwd)"; done
done
[ -f DeveloperIDG2CA.cer ] || curl -fsSLO https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer
$OPENSSL x509 -inform DER -in DeveloperIDG2CA.cer -out DeveloperIDG2CA.pem

build_p12() {  # $1 = base name, $2 = secret for the .p12, $3 = secret for its password
  local n=$1 pass
  $OPENSSL x509 -inform DER -in "$n.cer" -out "$n.pem"
  local cert_mod key_mod
  cert_mod=$($OPENSSL x509 -noout -modulus -in "$n.pem" | shasum)
  key_mod=$($OPENSSL rsa -noout -modulus -in "$n.key" 2>/dev/null | shasum)
  [ "$cert_mod" = "$key_mod" ] || die "$n.cer does not match $n.key -- was it made from this CSR?"
  $OPENSSL x509 -noout -issuer -in "$n.pem" | grep -q 'G2' || die "$n.cer is not from the G2 authority"

  # A random password: it only ever needs to exist in GitHub, so nobody has to choose or keep it.
  pass=$($OPENSSL rand -base64 24)
  P12_PASS="$pass" $OPENSSL pkcs12 -export -inkey "$n.key" -in "$n.pem" \
    -certfile DeveloperIDG2CA.pem -name "$($OPENSSL x509 -noout -subject -in "$n.pem" | sed 's/.*CN *= *//; s/,.*//')" \
    -passout env:P12_PASS -out "$n.p12"
  chmod 600 "$n.p12"
  # Prove the .p12 opens with that password before storing anything.
  P12_PASS="$pass" $OPENSSL pkcs12 -in "$n.p12" -passin env:P12_PASS -noout \
    || die "$n.p12 did not open with its own password"

  base64 -i "$n.p12" | gh secret set "$2" -R "$REPO"
  printf '%s' "$pass" | gh secret set "$3" -R "$REPO"
  echo "ok: $n.p12 -> $2, $3"
}

build_p12 developer_id_application CSC_LINK CSC_KEY_PASSWORD
build_p12 developer_id_installer CSC_INSTALLER_LINK CSC_INSTALLER_KEY_PASSWORD

# Notarisation: the App Store Connect team API key. The Key ID is in the .p8's file name.
shopt -s nullglob
p8s=(AuthKey_*.p8)
[ ${#p8s[@]} -eq 1 ] || die "expected exactly one AuthKey_<KeyID>.p8 here, found ${#p8s[@]}"
p8=${p8s[0]}
key_id=${p8#AuthKey_}; key_id=${key_id%.p8}
[[ $key_id =~ ^[A-Z0-9]{10}$ ]] || die "$p8: the Key ID in its name should be 10 letters/digits"
grep -Eq '^-----BEGIN [A-Z ]*KEY-----' "$p8" || die "$p8 does not look like a private key"
[ -f issuer_id.txt ] || die "missing issuer_id.txt (the Issuer ID from App Store Connect)"
issuer=$(tr -d '[:space:]' < issuer_id.txt)
[[ $issuer =~ ^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$ ]] \
  || die "issuer_id.txt should hold one UUID; found: $issuer"
base64 -i "$p8" | gh secret set APPLE_API_KEY -R "$REPO"
printf '%s' "$key_id" | gh secret set APPLE_API_KEY_ID -R "$REPO"
printf '%s' "$issuer" | gh secret set APPLE_API_ISSUER -R "$REPO"
echo "ok: $p8 -> APPLE_API_KEY, APPLE_API_KEY_ID ($key_id), APPLE_API_ISSUER"

echo
echo "Secrets now on $REPO:"
gh secret list -R "$REPO"
echo
echo "Done. Back up the two .key files and $p8 somewhere safe (Apple keeps no copy of the .p8);"
echo "the .p12 files can be deleted once you are happy the builds sign."
