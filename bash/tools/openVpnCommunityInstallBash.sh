#!/bin/bash
# ============================================================================
# NAME: OpenVPN Connect - macOS Deployment
# AUTHORED BY: Cogan Goldwater
# TYPE: Deployment / Remediation
# SCOPE: macOS endpoints / NinjaOne automation
# VARIABLES:
#   LOG_DIR  = /Library/Logs/MME
#   LOG_FILE = /Library/Logs/MME/OpenVPN_Deploy.log
#   DMG_PATH = /tmp/OpenVPNConnect.dmg
#   ARCH     = Detected using uname -m
#   DOWNLOAD_URL = Architecture-specific OpenVPN Connect DMG
# OUTPUT TOKENS:
#   None; script emits descriptive progress and error messages.
#   No standardized RESULT / NO_ACTION / ERROR token.
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
#   DMG downloaded directly from OpenVPN.
# LOGGING PATH:
#   /Library/Logs/MME/OpenVPN_Deploy.log
# DESCRIPTION:
#   Performs a one-off OpenVPN Connect deployment on macOS.
#   Detects Apple Silicon (arm64) or Intel (x86_64) architecture
#   and selects the corresponding download URL.
#   Downloads the installer DMG, validates minimum file size,
#   mounts the disk image, locates an embedded PKG, and installs
#   the package using the macOS installer utility.
#   Unmounts the DMG and removes the downloaded installer after
#   successful deployment.
#   Exits 0 on success and 1 on failure.
#
# DEPLOYMENT NOTES:
#   Intel download URL contains an unresolved version placeholder.
#   Installer download URLs and package availability require
#   verification before production deployment.
# ============================================================================

# -------------------------------------
# OpenVPN Connect - macOS One-Off Deployment
# MME FINAL (ARCH-AWARE DOWNLOAD)
# -------------------------------------

LOG_DIR="/Library/Logs/MME"
LOG_FILE="$LOG_DIR/OpenVPN_Deploy.log"
DMG_PATH="/tmp/OpenVPNConnect.dmg"

mkdir -p "$LOG_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $1" | tee -a "$LOG_FILE"
}

log "===== OpenVPN Connect Deployment START ====="

# -------------------------------------
# Detect Architecture
# -------------------------------------
ARCH=$(uname -m)
log "Detected architecture: $ARCH"

if [[ "$ARCH" == "arm64" ]]; then
    DOWNLOAD_URL="https://openvpn.net/downloads/openvpn-connect-v3-macos.dmg"
elif [[ "$ARCH" == "x86_64" ]]; then
    # Intel fallback (must use different endpoint)
    DOWNLOAD_URL="https://swupdate.openvpn.net/downloads/openvpn-connect-3.3.7.XXXX_signed_x86.dmg"
    log "WARNING: Using Intel-specific fallback URL"
else
    log "ERROR: Unknown architecture"
    exit 1
fi

log "Using download URL: $DOWNLOAD_URL"

# -------------------------------------
# Download
# -------------------------------------
log "Downloading OpenVPN Connect..."

if ! curl -L \
    -H "User-Agent: Mozilla/5.0" \
    -H "Accept: application/octet-stream" \
    -o "$DMG_PATH" \
    "$DOWNLOAD_URL"; then
    log "ERROR: Download failed"
    exit 1
fi

# -------------------------------------
# Validate size
# -------------------------------------
FILE_SIZE=$(stat -f%z "$DMG_PATH" 2>/dev/null)
log "Downloaded file size: $FILE_SIZE bytes"

if [[ -z "$FILE_SIZE" || "$FILE_SIZE" -lt 50000000 ]]; then
    log "ERROR: File too small"
    rm -f "$DMG_PATH"
    exit 1
fi

# -------------------------------------
# Mount
# -------------------------------------
log "Mounting DMG..."

MOUNT_OUTPUT=$(hdiutil attach "$DMG_PATH" -nobrowse)
if [[ $? -ne 0 ]]; then
    log "ERROR: Failed to mount DMG"
    exit 1
fi

MOUNT_POINT=$(echo "$MOUNT_OUTPUT" | grep "/Volumes/" | sed 's/.*\/Volumes/\/Volumes/' | head -1)
log "Mounted at: $MOUNT_POINT"

# -------------------------------------
# Install (PKG)
# -------------------------------------
PKG_PATH=$(find "$MOUNT_POINT" -maxdepth 2 -name "*.pkg" | head -1)
log "Detected PKG: $PKG_PATH"

if [[ -z "$PKG_PATH" ]]; then
    log "ERROR: No PKG found"
    hdiutil detach "$MOUNT_POINT" -quiet
    exit 1
fi

log "Installing via PKG..."

if ! installer -pkg "$PKG_PATH" -target /; then
    log "ERROR: PKG install failed (likely arch mismatch)"
    hdiutil detach "$MOUNT_POINT" -quiet
    exit 1
fi

# -------------------------------------
# Cleanup
# -------------------------------------
log "Unmounting DMG..."
hdiutil detach "$MOUNT_POINT" -quiet
rm -f "$DMG_PATH"

log "OpenVPN Connect deployment completed successfully"

exit 0