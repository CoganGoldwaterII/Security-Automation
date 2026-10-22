#!/bin/bash
# ============================================================================
# NAME: NinjaOne Remediation Ledger - Clear (macOS)
# AUTHORED BY: Cogan Goldwater
# TYPE: Maintenance
# SCOPE: macOS endpoints / NinjaOne maintenance automation
# VARIABLES:
#   LOG_DIR   = /Library/MME/AutoLogs
#   LOG_FILE  = /Library/MME/AutoLogs/Clear_RemediationSummary.log
#   NINJA_CLI = /Applications/NinjaRMMAgent/programdata/ninjarmm-cli
# OUTPUT TOKENS:
#   RESULT | CLEARED
#   RESULT | ERROR
# CUSTOM FIELDS:
#   Reads: remediationSummary (Multi-line)
#   Writes: remediationSummary (Multi-line)
#   Unchanged: lastRemediationDate (Text)
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   /Library/MME/AutoLogs/Clear_RemediationSummary.log
# DESCRIPTION:
#   Manually clears the NinjaOne remediationSummary device custom field.
#   Intended for periodic maintenance of the running remediation ledger.
#   Logs the previous field length without exposing its contents.
#   Performs a best-effort readback verification after clearing.
#   Leaves lastRemediationDate unchanged.
#   Always exits 0.
# ============================================================================

set +e

LOG_DIR="/Library/MME/AutoLogs"
LOG_FILE="$LOG_DIR/Clear_RemediationSummary.log"
NINJA_CLI="/Applications/NinjaRMMAgent/programdata/ninjarmm-cli"

mkdir -p "$LOG_DIR" 2>/dev/null

log() {
  local ts
  ts="$(date '+%F %T')"
  echo "$ts | [ClearRemediationSummary] $*" >> "$LOG_FILE"
}

finish() {
  local result="$1"
  log "RESULT | $result"
  echo "RESULT | $result"
  exit 0
}

log "============================================================"
log "START remediationSummary clear"

if [[ ! -x "$NINJA_CLI" ]]; then
  log "ERROR: ninjarmm-cli not found at $NINJA_CLI"
  finish "ERROR"
fi

current="$("$NINJA_CLI" get remediationSummary 2>/dev/null)"

if [[ -z "${current//[[:space:]]/}" ]]; then
  log "remediationSummary already empty."
else
  log "remediationSummary current length: ${#current} chars"
fi

"$NINJA_CLI" set remediationSummary "" >/dev/null 2>&1
rc=$?

if [[ $rc -ne 0 ]]; then
  log "ERROR: Failed to clear remediationSummary (rc=$rc)"
  finish "ERROR"
fi

after="$("$NINJA_CLI" get remediationSummary 2>/dev/null)"

if [[ -n "${after//[[:space:]]/}" ]]; then
  log "WARNING: remediationSummary did not read back empty."
else
  log "remediationSummary cleared."
fi

finish "CLEARED"\]