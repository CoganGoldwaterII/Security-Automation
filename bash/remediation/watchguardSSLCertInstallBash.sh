# ============================================================================
# NAME: Install WatchGuard ProxyCA Certificate - Linux
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Linux Endpoints / NinjaOne Automation
# VARIABLES:
#   Required: None
#   Optional: None
# OUTPUT TOKENS:
#   Existing console output:
#     [WatchGuardCert] Certificate already installed.
#     [WatchGuardCert] Certificate imported successfully.
#     [WatchGuardCert] ERROR: <error message>
#   Does not currently implement RESULT / NO_ACTION / ERROR tokens.
#   Existing exit codes: Success=0, Failure=1
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
#   Downloads ProxyCA.cer directly from the detected gateway.
# LOGGING PATH:
#   None; output is written to the NinjaOne execution console.
# DESCRIPTION:
#   Installs the WatchGuard ProxyCA certificate into the Linux system
#   Trusted Root certificate store.
#
#   Requires root privileges, ip, curl, and openssl.
#
#   Detects the default IPv4 gateway using the Linux routing table.
#   Downloads the ProxyCA certificate from:
#     http://<gateway>:4126/ProxyCA.cer
#
#   Accepts PEM or DER certificate encoding and converts the
#   downloaded certificate to PEM format when necessary.
#
#   Calculates the SHA256 certificate fingerprint and compares it
#   with any existing WatchGuard ProxyCA certificate.
#
#   Skips installation when the certificate fingerprints match.
#   Replaces the existing certificate when fingerprints differ.
#
#   Supports Debian-family systems using update-ca-certificates
#   and RHEL-family systems using update-ca-trust.
#
#   Uses temporary files under /tmp and removes them on exit.
#
#   SECURITY NOTE:
#   Certificate download uses unauthenticated HTTP.
#   Certificate parsing does not authenticate the issuing firewall.
#   Imported certificates receive system-wide root trust.
#
#   Existing functionality and exit behavior are preserved.
# ============================================================================

set -u

log() {
    echo "[WatchGuardCert] $1"
}

fail() {
    log "ERROR: $1"
    exit 1
}

# ---- Require root ----

if [[ $EUID -ne 0 ]]; then
    fail "Script must be run as root."
fi

# ---- Check dependencies ----

command -v ip >/dev/null 2>&1 ||
    fail "'ip' command not found."

command -v curl >/dev/null 2>&1 ||
    fail "'curl' command not found."

command -v openssl >/dev/null 2>&1 ||
    fail "'openssl' command not found."

# ---- Get default gateway ----

Gateway=$(
    ip -4 route get 1.1.1.1 2>/dev/null |
    awk '{
        for (i=1; i<=NF; i++) {
            if ($i == "via") {
                print $(i+1)
                exit
            }
        }
    }'
)

if [[ -z "${Gateway:-}" ]]; then
    fail "Could not determine default gateway."
fi

log "Gateway detected: $Gateway"

# ---- Build URL ----

Url="http://${Gateway}:4126/ProxyCA.cer"

log "Downloading: $Url"

TmpCert=$(mktemp /tmp/wg_proxyca.XXXXXX.cer) ||
    fail "Could not create temporary file."

TmpPem=$(mktemp /tmp/wg_proxyca.XXXXXX.crt) ||
    fail "Could not create temporary PEM file."

cleanup() {
    rm -f "$TmpCert" "$TmpPem"
}

trap cleanup EXIT

# ---- Download certificate ----

if ! curl \
    --fail \
    --silent \
    --show-error \
    --connect-timeout 10 \
    --max-time 30 \
    "$Url" \
    -o "$TmpCert"; then

    fail "Failed to download certificate."
fi

if [[ ! -s "$TmpCert" ]]; then
    fail "Downloaded certificate is empty."
fi

# ---- Parse / validate certificate ----
#
# WatchGuard may return either DER or PEM.
#

if openssl x509 \
    -in "$TmpCert" \
    -noout \
    >/dev/null 2>&1; then

    openssl x509 \
        -in "$TmpCert" \
        -out "$TmpPem" ||
        fail "Could not normalize PEM certificate."

elif openssl x509 \
    -inform DER \
    -in "$TmpCert" \
    -noout \
    >/dev/null 2>&1; then

    openssl x509 \
        -inform DER \
        -in "$TmpCert" \
        -out "$TmpPem" ||
        fail "Could not convert DER certificate."

else
    fail "Downloaded file is not a valid certificate."
fi

Thumbprint=$(
    openssl x509 \
        -in "$TmpPem" \
        -noout \
        -fingerprint \
        -sha256 |
    cut -d= -f2
)

log "SHA256 Thumbprint: $Thumbprint"

# ---- Determine Linux trust store ----

if command -v update-ca-certificates >/dev/null 2>&1; then

    #
    # Debian / Ubuntu / ZorinOS / Mint
    #

    CertPath="/usr/local/share/ca-certificates/watchguard-proxyca.crt"
    UpdateCommand="update-ca-certificates"

elif command -v update-ca-trust >/dev/null 2>&1; then

    #
    # RHEL / Rocky / Alma / CentOS / Fedora
    #

    CertPath="/etc/pki/ca-trust/source/anchors/watchguard-proxyca.crt"
    UpdateCommand="update-ca-trust extract"

else
    fail "Unsupported Linux certificate trust store."
fi

# ---- Check existing certificate ----

if [[ -f "$CertPath" ]]; then

    ExistingThumbprint=$(
        openssl x509 \
            -in "$CertPath" \
            -noout \
            -fingerprint \
            -sha256 \
            2>/dev/null |
        cut -d= -f2
    )

    if [[ "$ExistingThumbprint" == "$Thumbprint" ]]; then
        log "Certificate already installed."
        exit 0
    fi

    log "Existing WatchGuard certificate differs. Replacing it."
fi

# ---- Install certificate ----

if ! cp "$TmpPem" "$CertPath"; then
    fail "Could not copy certificate to trust store."
fi

chmod 0644 "$CertPath"

if ! $UpdateCommand >/dev/null 2>&1; then
    rm -f "$CertPath"
    fail "Failed to update system certificate trust store."
fi

log "Certificate imported successfully."
exit 0
