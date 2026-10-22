#!/bin/bash
# ============================================================================
# NAME: Google Chrome - macOS Update Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: macOS endpoints / NinjaOne remediation automation
# VARIABLES:
#   LOG_DIR    = /Library/MME/AutoLogs
#   LOG_FILE   = /Library/MME/AutoLogs/Chrome_Update.log
#   CHROME_APP = /Applications/Google Chrome.app
#   WORK_DIR   = /private/tmp/MME_ChromeUpdate
#   PKG_PATH   = /private/tmp/MME_ChromeUpdate/GoogleChrome.pkg
#   PKG_URL    = Official Google Chrome macOS PKG download URL
#   NINJA_CLI  = /Applications/NinjaRMMAgent/programdata/ninjarmm-cli
# OUTPUT TOKENS:
#   RESULT | UPDATED
#   RESULT | NO_ACTION
#   RESULT | ERROR
# CUSTOM FIELDS:
#   Reads:
#     remediationSummary (Multi-line)
#   Writes:
#     lastRemediationDate (Text)
#     remediationSummary (Multi-line)
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   /Library/MME/AutoLogs/Chrome_Update.log
# DESCRIPTION:
#   Updates an existing Google Chrome installation on macOS using the
#   official Google Chrome PKG downloaded directly from Google.
#   Closes running Chrome processes, installs the package, and compares
#   installed versions before and after remediation.
#   Does not install Chrome when absent.
#   Updates NinjaOne remediation fields on a best-effort basis.
#   Always exits 0.
# ============================================================================

set +e

LOG_DIR="/Library/MME/AutoLogs"
LOG_FILE="$LOG_DIR/Chrome_Update.log"

CHROME_APP="/Applications/Google Chrome.app"
CHROME_BIN="$CHROME_APP/Contents/MacOS/Google Chrome"

WORK_DIR="/private/tmp/MME_ChromeUpdate"
PKG_PATH="$WORK_DIR/GoogleChrome.pkg"
PKG_URL="https://dl.google.com/chrome/mac/universal/stable/gcem/GoogleChrome.pkg"

NINJA_CLI="/Applications/NinjaRMMAgent/programdata/ninjarmm-cli"

mkdir -p "$LOG_DIR" 2>/dev/null
mkdir -p "$WORK_DIR" 2>/dev/null

log() {
  local ts
  ts="$(date '+%F %T')"
  echo "$ts | [ChromeFix] $*" >> "$LOG_FILE"
}

get_installed_version() {
  if [[ -x "$CHROME_BIN" ]]; then
    "$CHROME_BIN" --version 2>/dev/null | /usr/bin/grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | /usr/bin/head -n 1
    return 0
  fi
  echo ""
  return 1
}

iso_now() {
  local iso
  iso="$(date '+%Y-%m-%dT%H:%M:%S%z')"          # 2026-02-06T10:30:00-0800
  echo "${iso:0:19}${iso:19:3}:${iso:22:2}"     # 2026-02-06T10:30:00-08:00
}

stamp_now() {
  date '+%Y-%m-%d %H:%M'
}

ninja_get() {
  # Usage: ninja_get fieldName
  [[ -x "$NINJA_CLI" ]] || return 1
  "$NINJA_CLI" get "$1" 2>/dev/null
}

ninja_set() {
  # Usage: ninja_set fieldName value
  [[ -x "$NINJA_CLI" ]] || return 1
  "$NINJA_CLI" set "$1" "$2" 2>/dev/null
}

append_remediation_summary() {
  # Usage: append_remediation_summary "one line entry"
  local entry="$1"
  local current new

  current="$(ninja_get remediationSummary)"
  [[ -z "$current" ]] && current=""

  if [[ -z "$current" ]]; then
    new="$entry"
  else
    # Append on new line
    new="${current%"${current##*[!$'\n']}"}"$'\n'"$entry"
  fi

  # Guardrails: keep last 200 lines
  local max_lines=200
  local lines_count
  lines_count="$(echo "$new" | /usr/bin/wc -l | tr -d ' ')"
  if [[ "$lines_count" -gt "$max_lines" ]]; then
    new="$(echo "$new" | /usr/bin/tail -n "$max_lines")"
  fi

  # Guardrail: cap chars ~15000
  local max_chars=15000
  local len
  len="${#new}"
  if [[ "$len" -gt "$max_chars" ]]; then
    new="${new:len-max_chars}"
  fi

  ninja_set remediationSummary "$new" >/dev/null 2>&1
}

update_ninja_fields() {
  # Usage: update_ninja_fields RESULT FROMVER TOVER NOTES
  local result="$1"
  local fromver="$2"
  local tover="$3"
  local notes="$4"

  local iso stamp entry
  iso="$(iso_now)"
  stamp="$(stamp_now)"

  entry="${stamp} | Chrome | ${result}"
  if [[ -n "$fromver" || -n "$tover" ]]; then
    entry="${entry} | ${fromver:-UNKNOWN} -> ${tover:-UNKNOWN}"
  fi
  [[ -n "$notes" ]] && entry="${entry} | $notes"

  if [[ ! -x "$NINJA_CLI" ]]; then
    log "INFO: ninjarmm-cli not found/executable at: $NINJA_CLI (fields not updated)"
    return 1
  fi

  ninja_set lastRemediationDate "$iso" >/dev/null 2>&1
  append_remediation_summary "$entry"
  log "Ninja fields updated: $entry"
  return 0
}

finish() {
  local result="$1"
  local reason="$2"
  local from="$3"
  local to="$4"

  [[ -n "$reason" ]] && log "REASON: $reason"

  # Global standard: always update fields (best effort)
  update_ninja_fields "$result" "$from" "$to" "$reason" >/dev/null 2>&1

  log "RESULT | $result"
  echo "RESULT | $result"
  exit 0
}

log "============================================================"
log "START remediation"
log "whoami=$(whoami) uid=$(id -u) arch=$(uname -m) macOS=$(sw_vers -productVersion 2>/dev/null)"
log "LogFile=$LOG_FILE"

if [[ ! -d "$CHROME_APP" ]]; then
  log "Chrome not installed. Exiting (update-only)."
  finish "NO_ACTION" "Chrome not installed" "" ""
fi

pre_ver="$(get_installed_version)"
log "Installed Chrome version (pre): ${pre_ver:-UNKNOWN}"

log "Downloading PKG: $PKG_URL"
/usr/bin/curl -fL --connect-timeout 15 --max-time 180 \
  -o "$PKG_PATH" "$PKG_URL" >> "$LOG_FILE" 2>&1
dl_rc=$?

if [[ $dl_rc -ne 0 || ! -s "$PKG_PATH" ]]; then
  log "ERROR: Download failed or pkg missing/empty. rc=$dl_rc path=$PKG_PATH"
  finish "ERROR" "Download failed (rc=$dl_rc)" "$pre_ver" ""
fi

pkg_size="$(/usr/bin/stat -f%z "$PKG_PATH" 2>/dev/null)"
log "Download OK. PKG size: ${pkg_size:-UNKNOWN} bytes"

log "Closing Chrome (if running)..."
/usr/bin/osascript -e 'tell application "Google Chrome" to quit' >> "$LOG_FILE" 2>&1
sleep 2
/usr/bin/pkill -x "Google Chrome" >> "$LOG_FILE" 2>&1

log "Running installer..."
/usr/sbin/installer -pkg "$PKG_PATH" -target / >> "$LOG_FILE" 2>&1
inst_rc=$?

if [[ $inst_rc -ne 0 ]]; then
  log "ERROR: installer failed. rc=$inst_rc"
  finish "ERROR" "installer failed (rc=$inst_rc)" "$pre_ver" ""
fi

sleep 2
post_ver="$(get_installed_version)"
log "Installed Chrome version (post): ${post_ver:-UNKNOWN}"

if [[ -n "$pre_ver" && -n "$post_ver" && "$post_ver" != "$pre_ver" ]]; then
  log "SUCCESS: Chrome updated from $pre_ver to $post_ver"
  finish "UPDATED" "Chrome updated" "$pre_ver" "$post_ver"
fi

log "NO CHANGE detected. pre='$pre_ver' post='$post_ver'"
finish "NO_ACTION" "No version change detected" "$pre_ver" "$post_ver"