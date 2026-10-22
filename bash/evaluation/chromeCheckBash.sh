#!/bin/bash
# ============================================================================
# NAME: Google Chrome - macOS Version Evaluation
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: macOS endpoints / NinjaOne evaluation automation
# VARIABLES:
#   LOG_DIR  = /Library/MME/AutoLogs
#   LOG_PATH = /Library/MME/AutoLogs/Chrome_Detect.log
#   PLATFORM = mac
#   CHANNEL  = stable
# OUTPUT TOKENS:
#   TRIGGER   | Chrome outdated
#   NO_ACTION | Chrome not installed or version is current
#   ERROR     | API failure or version parsing failure
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   /Library/MME/AutoLogs/Chrome_Detect.log
# DESCRIPTION:
#   Evaluates installed Google Chrome versions on macOS against the latest
#   Stable release using Google's Chrome VersionHistory API.
#   Uses fraction=1 to identify fully rolled-out releases.
#   Falls back to Chrome-for-Testing LATEST_RELEASE_STABLE if needed.
#   Checks system-wide and user-specific application directories.
#   Reports TRIGGER when Chrome is outdated.
#   Always exits 0.
# ============================================================================

set +e

LOG_DIR="/Library/MME/AutoLogs"
LOG_PATH="${LOG_DIR}/Chrome_Detect.log"
PLATFORM="mac"
CHANNEL="stable"

ensure_log_dir() {
  [[ -d "$LOG_DIR" ]] || mkdir -p "$LOG_DIR" >/dev/null 2>&1
}

log() {
  ensure_log_dir
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "${ts} [ChromeDetect] $*" >> "$LOG_PATH" 2>/dev/null || true
}

emit() {
  echo "$1"
  exit 0
}

get_installed_chrome_version() {
  local app="/Applications/Google Chrome.app"
  local plist="${app}/Contents/Info.plist"

  if [[ -f "$plist" ]]; then
    log "Found system Chrome at: $app"
    local v
    v="$(/usr/bin/defaults read "$plist" CFBundleShortVersionString 2>/dev/null | tr -d '[:space:]')"
    [[ -n "$v" ]] && { echo "$v"; return 0; }
  fi

  for userdir in /Users/*; do
    app="${userdir}/Applications/Google Chrome.app"
    plist="${app}/Contents/Info.plist"
    if [[ -f "$plist" ]]; then
      log "Found user Chrome at: $app"
      local v2
      v2="$(/usr/bin/defaults read "$plist" CFBundleShortVersionString 2>/dev/null | tr -d '[:space:]')"
      [[ -n "$v2" ]] && { echo "$v2"; return 0; }
    fi
  done

  echo ""
  return 1
}

get_latest_from_versionhistory() {
  local url="https://versionhistory.googleapis.com/v1/chrome/platforms/${PLATFORM}/channels/${CHANNEL}/versions/all/releases?filter=fraction=1&order_by=version%20desc&pageSize=1"

  log "Querying VersionHistory (fraction=1 ONLY)..."

  local body
  body="$(/usr/bin/curl -sS -L --connect-timeout 15 --max-time 60 "$url" 2>/dev/null)"

  if [[ -z "$body" ]]; then
    log "VersionHistory returned empty response."
    echo ""
    return 1
  fi

  local latest
  latest="$(echo "$body" | /usr/bin/grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | /usr/bin/head -n 1 | tr -d '[:space:]')"

  if [[ -z "$latest" ]]; then
    log "VersionHistory parse failed."
    echo ""
    return 1
  fi

  echo "$latest"
  return 0
}

get_latest_from_cft() {
  local url="https://googlechromelabs.github.io/chrome-for-testing/LATEST_RELEASE_STABLE"

  log "Fallback: Querying Chrome-for-Testing..."

  local v
  v="$(/usr/bin/curl -sS -L --connect-timeout 15 --max-time 60 "$url" 2>/dev/null | tr -d '[:space:]')"

  if [[ -z "$v" ]]; then
    log "CFT fallback empty."
    echo ""
    return 1
  fi

  if ! [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log "CFT fallback unexpected value: '$v'"
    echo ""
    return 1
  fi

  echo "$v"
  return 0
}

get_latest_stable() {
  local latest
  latest="$(get_latest_from_versionhistory)"
  if [[ -n "$latest" ]]; then
    log "Latest source: VersionHistory"
    echo "$latest"
    return 0
  fi

  latest="$(get_latest_from_cft)"
  if [[ -n "$latest" ]]; then
    log "Latest source: CFT fallback"
    echo "$latest"
    return 0
  fi

  echo ""
  return 1
}

version_lt() {
  local a="$1"
  local b="$2"

  [[ -z "$a" || -z "$b" ]] && return 2

  local first
  first="$(printf "%s\n%s\n" "$a" "$b" | /usr/bin/sort -V | /usr/bin/head -n 1)"
  [[ "$first" == "$a" && "$a" != "$b" ]]
}

# ---- MAIN ----
ensure_log_dir
log "============================================================"
log "Starting Chrome evaluation..."

installed="$(get_installed_chrome_version)"
if [[ -z "$installed" ]]; then
  log "Chrome not installed."
  emit "NO_ACTION | Chrome not installed"
fi

log "Installed Chrome version: $installed"

latest="$(get_latest_stable)"
if [[ -z "$latest" ]]; then
  log "ERROR: could not determine latest stable."
  emit "ERROR | Latest stable unknown (API failure)"
fi

log "Latest stable: $latest"

if ! [[ "$installed" =~ ^[0-9]+(\.[0-9]+){1,4}$ && "$latest" =~ ^[0-9]+(\.[0-9]+){1,4}$ ]]; then
  log "ERROR: version format unexpected."
  emit "ERROR | Version parse failure (Installed='$installed' Latest='$latest')"
fi

if version_lt "$installed" "$latest"; then
  log "VULNERABLE: Installed ($installed) < LatestStable ($latest)"
  emit "TRIGGER | Outdated Chrome ($installed < $latest)"
fi

log "NO_ACTION: Installed ($installed) >= LatestStable ($latest)"
emit "NO_ACTION | Up-to-date ($installed >= $latest)"