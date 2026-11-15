#!/bin/sh
# Create the OpenPGP key that signs the Delbert packages (deb, rpm) and print what to do with it
# (docs/install.md "Signing the packages").
#
#   packaging/generate-signing-key.sh --name "Example Corp packages" --email packages@example.com --out keys
#
# Options:
#   --name NAME        owner shown in the key (required)
#   --email ADDRESS    address shown in the key (required)
#   --out DIR          where the two files are written (default: .)
#   --expires PERIOD   validity, as gpg understands it: 2y, 18m, 0 for never (default 2y)
#   --passphrase-file FILE   protect the private key with the passphrase in FILE (first line).
#                      Without it the key is unprotected: fine for a secret store, not for a disk.
#   --staging          mark the key as a staging key in its name (what CI does when no key is configured)
#
# Writes <out>/delbert-signing-key.private.asc (mode 0600: the secret; never commit it) and
# <out>/delbert-signing-key.asc (public: publish it, users import it to verify packages).
# The key is RSA 4096: the rpm of older distributions cannot verify Ed25519 signatures.
# gpg works in a temporary home: nothing is added to your own keyring.
set -eu

NAME=""
EMAIL=""
OUT="."
EXPIRES="2y"
PASSFILE=""
STAGING=0

die() {
    echo "generate-signing-key: $*" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --name) NAME="$2"; shift 2 ;;
        --email) EMAIL="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --expires) EXPIRES="$2"; shift 2 ;;
        --passphrase-file) PASSFILE="$2"; shift 2 ;;
        --staging) STAGING=1; shift ;;
        -h | --help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
done

command -v gpg >/dev/null 2>&1 || die "gpg (GnuPG 2.1 or later) is required"
[ -n "$NAME" ] && [ -n "$EMAIL" ] || die "--name and --email are required"
case "$NAME$EMAIL" in *"<"* | *">"*) die "name and address must not contain < or >" ;; esac
[ "$STAGING" -eq 0 ] || NAME="$NAME (STAGING, not for production)"
PASSPHRASE=""
if [ -n "$PASSFILE" ]; then
    [ -r "$PASSFILE" ] || die "cannot read $PASSFILE"
    PASSPHRASE="$(head -n 1 "$PASSFILE")"
    [ -n "$PASSPHRASE" ] || die "$PASSFILE is empty"
fi

mkdir -p "$OUT"
PRIVATE="$OUT/delbert-signing-key.private.asc"
PUBLIC="$OUT/delbert-signing-key.asc"
[ ! -e "$PRIVATE" ] && [ ! -e "$PUBLIC" ] || die "refusing to overwrite the key files in $OUT"

GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
trap 'gpgconf --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT
chmod 700 "$GNUPGHOME"

gpg --batch --quiet --no-auto-check-trustdb --pinentry-mode loopback --passphrase "$PASSPHRASE" \
    --quick-generate-key "$NAME <$EMAIL>" rsa4096 sign "$EXPIRES"
FINGERPRINT="$(gpg --batch --with-colons --list-keys | awk -F: '$1 == "fpr" { print $10; exit }')"
[ -n "$FINGERPRINT" ] || die "gpg did not create a key"

umask 077
gpg --batch --quiet --pinentry-mode loopback --passphrase "$PASSPHRASE" --armor --export-secret-keys "$FINGERPRINT" >"$PRIVATE"
umask 022
gpg --batch --quiet --armor --export "$FINGERPRINT" >"$PUBLIC"

cat <<EOF
Signing key created: $NAME <$EMAIL>
  fingerprint : $FINGERPRINT
  expires     : $EXPIRES
  private key : $PRIVATE   (secret)
  public key  : $PUBLIC

Next:
  1. Store the private key as the repository secret PACKAGE_SIGNING_KEY$([ -z "$PASSPHRASE" ] || echo " and its passphrase as PACKAGE_SIGNING_PASSPHRASE"):
       gh secret set PACKAGE_SIGNING_KEY < $PRIVATE
     then keep one offline copy and delete the file.
  2. Commit the public key as packaging/delbert-signing-key.asc: the release publishes it and
     install-agent.sh imports it before installing an rpm.
  3. Write the fingerprint down where your users will look for it (README, website).
EOF
