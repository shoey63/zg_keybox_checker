#!/data/data/com.termux/files/usr/bin/bash

# Usage: ./zg.sh [-q] [-s] [-d] [directory_or_file]
#   -q: Quiet mode, suppresses terminal output (writes to files only)
#   -s: Silent mode, shows minimal terminal output, writes files only for compromised keyboxes
#   -d: Debug mode, enables detailed logging to /sdcard/Download/zg_debug.log.txt
#   - If no argument, processes *.xml in /sdcard/Download
#   - If directory, processes all *.xml in that directory
#   - If file, processes that specific XML file
# Dependencies: openssl-tool, wget
# Purpose: Processes keybox.xml files to check certificate expiration and revocation status
# Original code by zgfg@xda © Jan 2025 - All Rights Reserved
# Modified and extended by shoey63 (XDA) with Grok 3 (xAI) - March 2025
# Debug 1 version with logging - March 2025
# Updated to suppress redundant status messages - March 2025
# Added "close to expiry" warning feature - March 2025

# Initialize variables early to avoid unset variable errors
QUIET=0
SILENT=0
DEBUG=0
LOG_FILE="/sdcard/Download/zg_debug.log.txt"
WARNING_THRESHOLD_DAYS=30  # 30-day threshold for expiry warnings

# Arrays to track keyboxes by category
declare -a BANNED_KEYBOXES
declare -a EXPIRED_KEYBOXES
declare -a AOSP_KEYBOXES
declare -a WARNING_KEYBOXES  # For keyboxes with certificates nearing expiry

# --- Debug Logging Function ---
log_debug() {
    if [ $DEBUG -eq 1 ]; then
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$timestamp] $@" >> "$LOG_FILE" 2>/dev/null || echo "[$timestamp] Failed to write to log: $@" >&2
    fi
}

# --- File Permission Check ---
check_file_permissions() {
    DEFAULT_DIR="/sdcard/Download"
    TEST_FILE="${DEFAULT_DIR}/_zg_test_permission.txt"

    log_debug "Checking file permissions in $DEFAULT_DIR"
    mkdir -p "$DEFAULT_DIR" 2>/dev/null
    if ! touch "$TEST_FILE" 2>/dev/null; then
        printf "\033[1;31m!!!! ERROR: Termux requires file access permission. Please grant it in App Settings > Permissions > Files (not Storage) and try again. Cannot proceed.\033[0m\n"
        log_debug "Permission check failed: Cannot write to $DEFAULT_DIR"
        exit 1
    fi
    rm -f "$TEST_FILE" 2>/dev/null
    log_debug "Permission check passed"
}

check_file_permissions

# --- Dependency Check and Installation ---
if ! command -v pkg >/dev/null 2>&1; then
    echo "Error: 'pkg' (Termux package manager) not found. Cannot proceed." >&2
    log_debug "Dependency check failed: pkg not found"
    exit 1
fi

# ANSI color codes
GREEN='\033[1;32m'
YELLOW='\033[1;38;5;220m'        # Bold Gold for headers and other uses
LIGHT_YELLOW='\033[0;93m'        # Non-bold, light yellow for serial numbers
PINK='\033[1;95m'                # Bright pink for AOSP-related messages
RED='\033[31m'
BOLD_RED='\033[1;31m'            # Bold red for warnings and compromised keyboxes
ORANGE='\033[1;38;5;208m'        # Bold orange for warning header and category totals
BOLD='\033[1m'
NC='\033[0m'
BLUE='\033[1;34m'
BOLD_YELLOW='\033[1;33m'         # Bold yellow for less aggressive warnings (e.g., close to expiry)

# Function to install a package with colorized output
install_package() {
    local package_name="$1"
    local check_command="$2"
    local temp_file=$(mktemp)

    log_debug "Checking for $package_name"
    if ! $check_command >/dev/null 2>&1; then
        if [ $QUIET -eq 0 ] && [ $SILENT -eq 0 ]; then
            printf "\nInstalling %s...\n\n" "$package_name"
        fi
        log_debug "Installing $package_name"
        pkg install "$package_name" -y >"$temp_file" 2>&1
        cat "$temp_file" | tr -d '\r' | sed 's/\x1B\[[0-9;]*[mK]//g' | grep -v "Reading database" | while IFS= read -r line; do
            if echo "$line" | grep -q "No mirror or mirror group selected" || echo "$line" | grep -q "WARNING: apt does not have a stable CLI interface"; then
                continue
            fi
            if echo "$line" | grep -q -E "Installing|Reading package lists|Building dependency tree|Setting up|Preparing to unpack|Selecting previously"; then
                printf "${BLUE}%s${NC}\n" "$line"
            elif echo "$line" | grep -q -E "Error:|warning:|not found"; then
                printf "${RED}%s${NC}\n" "$line"
                log_debug "Installation error: $line"
            elif echo "$line" | grep -q -E "Checking availability|\[\*\]"; then
                printf "${GREEN}%s${NC}\n" "$line"
            else
                printf "${YELLOW}%s${NC}\n" "$line"
            fi
        done
        if [ $? -eq 0 ]; then
            if [ $QUIET -eq 0 ] && [ $SILENT -eq 0 ]; then
                printf "${GREEN}Successfully installed %s${NC}\n\n" "$package_name"
            fi
            log_debug "Successfully installed $package_name"
        fi
        rm -f "$temp_file"
    fi
}

install_package openssl-tool "openssl -v"
install_package wget "wget -V"

# --- Helper Functions ---

print() { printf "${GREEN}-- %s${NC}\n" "$@" 2>&1 || echo "-- $@" >&2; log_debug "PRINT: $@"; }
print_yellow() { printf "${YELLOW}-- %s${NC}\n" "$@" 2>&1 || echo "-- $@" >&2; log_debug "PRINT_YELLOW: $@"; }
print_light_yellow() { printf "${LIGHT_YELLOW}-- %s${NC}\n" "$@" 2>&1 || echo "-- $@" >&2; log_debug "PRINT_LIGHT_YELLOW: $@"; }
print_orange() { printf "${ORANGE}-- %s${NC}\n" "$@" 2>&1 || echo "-- $@" >&2; log_debug "PRINT_ORANGE: $@"; }
print_red() { printf "${BOLD_RED}-- %s${NC}\n" "$@" 2>&1 || echo "-- $@" >&2; log_debug "PRINT_RED: $@"; }
print_pink() { printf "${PINK}-- %s${NC}\n" "$@" 2>&1 || echo "-- $@" >&2; log_debug "PRINT_PINK: $@"; }
warn() { printf "${BOLD_RED}!!!! %s${NC}\n" "$@" 2>&1 || echo "!!!! $@" >&2; log_debug "WARN: $@"; }
warn_pink() { printf "${PINK}!!!! %s${NC}\n" "$@" 2>&1 || echo "!!!! $@" >&2; log_debug "WARN_PINK: $@"; }
error() { warn "ERROR: %s, cannot proceed" "$@" && log_debug "ERROR: $@" && exit 1; }

get_epoch() {
    local date_str="$1"
    local epoch=$(date -d "$date_str" +%s 2>/dev/null || date -d "$(echo "$date_str" | sed 's/_/ /g')" +%s 2>/dev/null)
    if [ -z "$epoch" ]; then
        echo "Error: Could not parse date: $date_str" >&2
        log_debug "Failed to parse date: $date_str"
        return 1
    fi
    echo "$epoch"
    log_debug "Parsed date '$date_str' to epoch: $epoch"
    return 0
}

# Function to generate detailed report file
generate_report() {
    local KB="$1"
    local TMP="$2"
    local P7B="$3"
    local CER="$4"
    local TXT="$5"
    local JSON="$6"
    local J="$7"
    local K="$8"
    local L="$9"
    local TOTAL_AOSP="$10"
    local TOTAL_EXPIRED="$11"
    local TOTAL_COMPROMISED="$12"
    local file_count="$13"

    log_debug "Generating report for $KB"
    sed 's!">-----BEGIN!">\n-----BEGIN!g' "$KB" | sed 's!CERTIFICATE-----</!CERTIFICATE-----\n</!g' | sed 's!^[ \t]*!!' > "$TMP" || error "Failed to reformat $KB"
    openssl crl2pkcs7 -nocrl -certfile "$TMP" -out "$P7B" 2>/dev/null || error "Failed to convert $KB to pkcs7"
    openssl pkcs7 -print_certs -text -in "$P7B" -out "$CER" 2>/dev/null || error "Failed to dump $KB"

    echo "KeyBox file: $KB" > "$TXT"

    # Preprocess the certificate file to extract relevant fields
    sed 's/^[ \t]*//;s/[[:space:]]*$//' "$CER" | sed '/^Serial Number/N;s/:[ \t]*\n/: /' | grep -E '^Certificate:|^Serial Number:|^Issuer:|^Not After|^Subject:|^Public Key Algorithm:|CA:' | sed 's/^Not After :/Not After:/' > "${CER}.filtered"

    # Number certificates and format output
    {
        echo ""
        awk '
            BEGIN {cert_count = 0}
            /^Certificate:/ {
                if (cert_count > 0) print ""
                cert_count++
                print "CERTIFICATE: " cert_count
                next
            }
            /^Serial Number:/ {print "    Serial Number: " substr($0, index($0, ":") + 2); next}
            /^Issuer:/ {print "    Issuer: " substr($0, index($0, ":") + 2); next}
            /^Not After:/ {print "    Not After: " substr($0, index($0, ":") + 2); next}
            /^Subject:/ {print "    Subject: " substr($0, index($0, ":") + 2); next}
            /^Public Key Algorithm:/ {print "    Public Key Algorithm: " substr($0, index($0, ":") + 2); next}
            /^CA:/ {print "    CA: " substr($0, index($0, ":") + 2); next}
        ' "${CER}.filtered"
        echo ""
    } >> "$TXT"

    rm -f "${CER}.filtered" 2>/dev/null

    local J_temp=0
    while IFS= read -r line; do
        if echo "$line" | grep -q "Subject:"; then
            Subject=$(echo "$line" | sed 's/^.*Subject://;s/^[ ]*//;s/ /_/g')
            CN=$(echo "$Subject" | grep 'CN=' | sed 's/^.*CN=//;s/_/ /g;s/^[ ]*//')
            AOSP=$(echo "$CN" | grep 'Android.*Software Attestation')
            if [ -n "$AOSP" ]; then
                J_temp=$((J_temp + 1))
                echo "!!!! Certificate $J_temp is AOSP type - COMMON NAME: $CN" >> "$TXT"
                log_debug "Found AOSP certificate $J_temp: $CN"
                echo "" >> "$TXT"
            fi
        fi
    done < "$TXT"
    [ $J_temp -gt 0 ] && echo "" >> "$TXT"

    # Deduplicate serial numbers and note duplicates
    echo "Serial Numbers:" >> "$TXT"
    declare -A seen_serials  # Associative array to track seen serial numbers
    declare -A serial_counts  # Associative array to count occurrences of each serial number
    while IFS= read -r line; do
        if echo "$line" | grep -q "Serial Number:"; then
            sn=$(echo "$line" | sed 's/^.*Serial Number://;s/(.*$//;s/[ :]//g')
            serial_counts[$sn]=$(( ${serial_counts[$sn]:-0} + 1 ))
            if [ -z "${seen_serials[$sn]}" ]; then
                seen_serials[$sn]=1
                echo "    $sn" >> "$TXT"
                log_debug "Extracted unique serial number: $sn"
            else
                log_debug "Skipped duplicate serial number: $sn"
            fi
        fi
    done < "$TXT"

    # Check for duplicates and add a note if any are found
    local has_duplicates=0
    for sn in "${!serial_counts[@]}"; do
        if [ "${serial_counts[$sn]}" -gt 1 ]; then
            has_duplicates=1
            echo "!!!! : Serial number $sn appears ${serial_counts[$sn]} times in the keybox file" >> "$TXT"
            log_debug "Found duplicate serial number $sn (${serial_counts[$sn]} occurrences)"
        fi
    done
    [ $has_duplicates -eq 1 ] && echo "" >> "$TXT"
    echo "" >> "$TXT"

    local K_temp=0
    local M_temp=0  # Counter for certificates nearing expiry
    while IFS= read -r line; do
        if echo "$line" | grep -q "Not After:"; then
            NA=$(echo "$line" | sed 's/^.*Not After://;s/^[ ]*//;s/ /_/g')
            NA_clean=$(echo "$NA" | sed 's/_/ /g')
            NAEpoch=$(get_epoch "$NA_clean")
            if [ $? -ne 0 ]; then
                if [ $QUIET -eq 0 ] && [ $SILENT -eq 0 ]; then
                    warn "Could not parse date: $NA_clean, skipping expiration check"
                fi
                echo "Could not parse date: $NA_clean, skipping expiration check" >> "$TXT"
                echo "" >> "$TXT"
                continue
            fi
            days_remaining=$(( (NAEpoch - currentEpoch) / 86400 ))
            if [ "$currentEpoch" -gt "$NAEpoch" ]; then
                K_temp=$((K_temp + 1))
                echo "!!!! Certificate $K_temp has expired - NOT AFTER: $NA_clean" >> "$TXT"
                log_debug "Certificate $K_temp expired: $NA_clean"
                echo "" >> "$TXT"
            elif [ $days_remaining -le $WARNING_THRESHOLD_DAYS ] && [ $days_remaining -gt 0 ] && [ $K_temp -eq 0 ]; then
                M_temp=$((M_temp + 1))
                echo "!!!! Certificate $M_temp nearing expiry - NOT AFTER: $NA_clean ($days_remaining days remaining)" >> "$TXT"
                log_debug "Certificate $M_temp nearing expiry in $KB: $NA_clean ($days_remaining days remaining)"
                echo "" >> "$TXT"
            fi
        fi
    done < "$TXT"
    [ $K_temp -gt 0 ] && echo "" >> "$TXT"
    [ $M_temp -gt 0 ] && echo "" >> "$TXT"

    # Fix for compromised certificates: Track actual certificate number
    local cert_num=0
    local L_temp=0
    while IFS= read -r line; do
        if echo "$line" | grep -q "^CERTIFICATE:"; then
            cert_num=$(echo "$line" | sed 's/^CERTIFICATE: //')
        elif echo "$line" | grep -q "Serial Number:"; then
            SN=$(echo "$line" | sed 's/^.*Serial Number://;s/(.*$//;s/[ :]//g')
            if grep -w "\"$SN\":" "$JSON" >/dev/null 2>&1; then
                L_temp=$((L_temp + 1))
                echo "!!!! Certificate $cert_num is compromised - SERIAL NUMBER: $SN" >> "$TXT"
                log_debug "Certificate $cert_num compromised: $SN"
                echo "" >> "$TXT"
            fi
        fi
    done < "$TXT"
    [ $L_temp -gt 0 ] && echo "" >> "$TXT"

    # Report expiration status
    if [ $K -gt 0 ]; then
        printf "${BOLD_RED}!!!! KeyBox has EXPIRED${NC}\n" >> "$TXT"
    elif [ $L -eq 0 ]; then
        # Only report "not expired" if the keybox is not compromised
        echo "-- KeyBox has not expired" >> "$TXT"
    fi

    # Report nearing expiry status (only if not expired)
    if [ $M -gt 0 ] && [ $K -eq 0 ]; then
        printf "${BOLD_YELLOW}-- KeyBox has certificates nearing expiry${NC}\n" >> "$TXT"
    fi

    # Report compromised/AOSP status
    if [ $L -gt 0 ]; then
        echo "!!!! KeyBox is COMPROMISED" >> "$TXT"
        echo "" >> "$TXT"
    elif [ $K -eq 0 ]; then
        # Only report "not compromised" or AOSP status if the keybox is not expired
        if [ $J -gt 0 ]; then
            echo "-- KeyBox is AOSP type" >> "$TXT"  # Changed from !!!! to --
        else
            echo "-- KeyBox is not compromised" >> "$TXT"
        fi
    fi

    echo "" >> "$TXT"
    log_debug "Report generated for $KB"
}

# --- Argument Parsing ---
while getopts "qsd" opt; do
    case $opt in
        q) QUIET=1 ;;
        s) SILENT=1 ;;
        d) DEBUG=1 ;;
        ?) echo "Usage: $0 [-q] [-s] [-d] [directory_or_file]" >&2; exit 1 ;;
    esac
done
shift $((OPTIND-1))

# Initialize debug log if -d is set
if [ $DEBUG -eq 1 ]; then
    echo "Debug log started: $(date)" > "$LOG_FILE" 2>/dev/null || error "Cannot write to debug log file $LOG_FILE"
    log_debug "Script started with arguments: $@"
fi

# Process command-line argument
if [ $# -eq 1 ]; then
    if [ -d "$1" ]; then
        XML_FILES=("$1"/*.xml)
        if [ ! -e "${XML_FILES[0]}" ]; then
            error "No .xml files found in directory '$1'"
        fi
    elif [ -f "$1" ] && [ -r "$1" ] && echo "$1" | grep -q '\.xml$'; then
        XML_FILES=("$1")
    else
        error "Specified path '$1' is not a directory or readable XML file"
    fi
else
    DEFAULT_DIR="/sdcard/Download"
    if [ ! -d "$DEFAULT_DIR" ]; then
        error "Default directory '$DEFAULT_DIR' not found. Ensure storage is accessible with 'termux-setup-storage'."
    fi
    XML_FILES=("$DEFAULT_DIR"/*.xml)
    if [ ! -e "${XML_FILES[0]}" ]; then
        error "No .xml files found in default directory '$DEFAULT_DIR'"
    fi
fi
log_debug "Processing files: ${XML_FILES[*]}"

# --- Download Compromised Certificates List Once ---
JSON_TEMP=$(mktemp)
[ $QUIET -eq 0 ] && print "Downloading compromised certificates list..."
log_debug "Downloading compromised certificates list from https://android.googleapis.com/attestation/status"
wget -q -O "$JSON_TEMP" --no-check-certificate https://android.googleapis.com/attestation/status 2>wget_err.log
if [ $? -ne 0 ]; then
    error "Failed to download compromised certificates list. See wget_err.log for details."
fi
if [ ! -s "$JSON_TEMP" ]; then
    error "Downloaded file is empty"
elif ! grep -q '"status": *"REVOKED"' "$JSON_TEMP"; then
    error "Invalid compromised certificates list - no revoked status found"
fi
log_debug "Compromised certificates list downloaded successfully"

# --- Main Processing ---
TOTAL_FILES=0
TOTAL_EXPIRED=0
TOTAL_COMPROMISED=0
TOTAL_AOSP=0
TOTAL_VALID=0
FILE_COUNT=0
INTERMEDIATE_FILES=()
trap 'for file in "${INTERMEDIATE_FILES[@]}" "$JSON_TEMP" "wget_err.log"; do rm -f "$file" 2>/dev/null || true; done' EXIT INT TERM

for KB in "${XML_FILES[@]}"; do
    TMP="${KB##*/}.tmp.txt"
    P7B="${KB##*/}.p7b"
    CER="${KB##*/}.cer.txt"
    TXT="${KB##*/}.txt"
    JSON="_CompromisedCerts.json.txt"

    if [ $QUIET -eq 0 ] && [ $SILENT -eq 0 ]; then
        print_yellow "Processing KeyBox file: $KB"
    fi
    log_debug "Processing file: $KB"
    TOTAL_FILES=$((TOTAL_FILES + 1))
    FILE_COUNT=$((FILE_COUNT + 1))

    if ! grep -q "BEGIN CERTIFICATE" "$KB"; then
        if [ $QUIET -eq 0 ] && [ $SILENT -eq 0 ]; then
            warn "No certificates found in $KB, skipping"
        fi
        log_debug "No certificates found in $KB, skipping"
        continue
    fi

    OUTPUT_DIR=$(dirname "$KB")
    RESULTS_DIR="${OUTPUT_DIR}/results"
    mkdir -p "$RESULTS_DIR" || error "Cannot create results directory '$RESULTS_DIR'"
    TMP="${RESULTS_DIR}/_$TMP"
    P7B="${RESULTS_DIR}/_$P7B"
    CER="${RESULTS_DIR}/_$CER"
    TXT="${RESULTS_DIR}/${TXT##*/}"
    JSON="${OUTPUT_DIR}/_$JSON"
    INTERMEDIATE_FILES+=("$TMP" "$P7B" "$CER")

    UTC=$(date --utc)
    currentEpoch=$(get_epoch "$UTC") || error "Failed to parse current date/time"
    K=0
    M=0  # Counter for certificates nearing expiry
    TMP_TEMP=$(mktemp)
    P7B_TEMP=$(mktemp)
    CER_TEMP=$(mktemp)
    sed 's!">-----BEGIN!">\n-----BEGIN!g' "$KB" | sed 's!CERTIFICATE-----</!CERTIFICATE-----\n</!g' | sed 's!^[ \t]*!!' > "$TMP_TEMP" || error "Failed to reformat $KB"
    openssl crl2pkcs7 -nocrl -certfile "$TMP_TEMP" -out "$P7B_TEMP" 2>/dev/null || error "Failed to convert $KB to pkcs7"
    openssl pkcs7 -print_certs -text -in "$P7B_TEMP" -out "$CER_TEMP" 2>/dev/null || error "Failed to dump $KB"
    
    while IFS= read -r line; do
        if echo "$line" | grep -q "Not After:"; then
            NA=$(echo "$line" | sed 's/^.*Not After://;s/^[ ]*//;s/ /_/g')
            NA_clean=$(echo "$NA" | sed 's/_/ /g')
            NAEpoch=$(get_epoch "$NA_clean")
            if [ $? -ne 0 ]; then
                continue
            fi
            days_remaining=$(( (NAEpoch - currentEpoch) / 86400 ))
            if [ "$currentEpoch" -gt "$NAEpoch" ]; then
                K=$((K + 1))
                TOTAL_EXPIRED=$((TOTAL_EXPIRED + 1))
                log_debug "Found expired certificate in $KB: $NA_clean"
            elif [ $days_remaining -le $WARNING_THRESHOLD_DAYS ] && [ $days_remaining -gt 0 ] && [ $K -eq 0 ]; then
                M=$((M + 1))
                log_debug "Found certificate nearing expiry in $KB: $NA_clean ($days_remaining days remaining)"
            fi
        fi
    done < <(sed 's/^[ \t]*//;s/[[:space:]]*$//' "$CER_TEMP" | sed '/^Serial Number/N;s/:[ \t]*\n/: /' | grep -E '^Certificate:|^Serial Number:|^Issuer:|^Not After|^Subject:|^Public Key Algorithm:|CA:' | sed 's/^Not After :/Not After:/')

    J=0
    while IFS= read -r line; do
        if echo "$line" | grep -q "Subject:"; then
            Subject=$(echo "$line" | sed 's/^.*Subject://;s/^[ ]*//;s/ /_/g')
            CN=$(echo "$Subject" | grep 'CN=' | sed 's/^.*CN=//;s/_/ /g;s/^[ ]*//')
            AOSP=$(echo "$CN" | grep 'Android.*Software Attestation')
            if [ -n "$AOSP" ]; then
                J=$((J + 1))
                TOTAL_AOSP=$((TOTAL_AOSP + 1))
                log_debug "Found AOSP certificate in $KB: $CN"
            fi
        fi
    done < <(sed 's/^[ \t]*//;s/[[:space:]]*$//' "$CER_TEMP" | sed '/^Serial Number/N;s/:[ \t]*\n/: /' | grep -E '^Certificate:|^Serial Number:|^Issuer:|^Not After|^Subject:|^Public Key Algorithm:|CA:' | sed 's/^Not After :/Not After:/')

    L=0
    while IFS= read -r line; do
        if echo "$line" | grep -q "Serial Number:"; then
            SN=$(echo "$line" | sed 's/^.*Serial Number://;s/(.*$//;s/[ :]//g')
            if grep -w "\"$SN\":" "$JSON_TEMP" >/dev/null 2>&1; then
                L=$((L + 1))
                TOTAL_COMPROMISED=$((TOTAL_COMPROMISED + 1))
                log_debug "Found compromised certificate in $KB: $SN"
            fi
        fi
    done < <(sed 's/^[ \t]*//;s/[[:space:]]*$//' "$CER_TEMP" | sed '/^Serial Number/N;s/:[ \t]*\n/: /' | grep -E '^Certificate:|^Serial Number:|^Issuer:|^Not After|^Subject:|^Public Key Algorithm:|CA:' | sed 's/^Not After :/Not After:/')

    # Categorize the keybox based on findings and count valid keyboxes
    if [ $L -gt 0 ]; then
        BANNED_KEYBOXES+=("${KB##*/}")
        log_debug "Added $KB to banned keyboxes (compromised)"
    fi
    if [ $K -gt 0 ]; then
        EXPIRED_KEYBOXES+=("${KB##*/}")
        log_debug "Added $KB to expired keyboxes"
    elif [ $M -gt 0 ]; then
        WARNING_KEYBOXES+=("${KB##*/}")
        log_debug "Added $KB to warning keyboxes (nearing expiry)"
    fi
    if [ $J -gt 0 ]; then
        AOSP_KEYBOXES+=("${KB##*/}")
        log_debug "Added $KB to AOSP keyboxes"
    fi
    # Valid keyboxes are those not expired, not compromised, and not AOSP
    if [ $K -eq 0 ] && [ $L -eq 0 ] && [ $J -eq 0 ]; then
        TOTAL_VALID=$((TOTAL_VALID + 1))
        log_debug "Added $KB to valid keyboxes"
    fi

    rm -f "$TMP_TEMP" "$P7B_TEMP" "$CER_TEMP" 2>/dev/null || true

    if [ $SILENT -eq 1 ]; then
        echo "Results for: $KB"
        if [ $K -gt 0 ]; then
            warn "KeyBox has expired"  # Changed from print_red to warn
            if [ $L -gt 0 ]; then
                warn "KeyBox is compromised"
            fi
        elif [ $L -gt 0 ]; then
            warn "KeyBox is compromised"
        else
            print "KeyBox has not expired"
            print "KeyBox is not compromised"
        fi
        if [ $M -gt 0 ] && [ $K -eq 0 ]; then
            print_orange "KeyBox has certificates nearing expiry"
        fi
        if [ $J -gt 0 ]; then
            print_pink "KeyBox is AOSP type"  # Changed from warn_pink to print_pink
        fi
        if [ $L -gt 0 ]; then
            generate_report "$KB" "$TMP" "$P7B" "$CER" "$TXT" "$JSON_TEMP" "$J" "$K" "$L" "$TOTAL_AOSP" "$TOTAL_EXPIRED" "$TOTAL_COMPROMISED" "$FILE_COUNT"
        fi
    else
        generate_report "$KB" "$TMP" "$P7B" "$CER" "$TXT" "$JSON_TEMP" "$J" "$K" "$L" "$TOTAL_AOSP" "$TOTAL_EXPIRED" "$TOTAL_COMPROMISED" "$FILE_COUNT"
        if [ $QUIET -eq 0 ]; then
            echo "Results for: $KB"
            print "Checking against compromised certificates list..."
            grep -v 'KeyBox file:' "$TXT" | while IFS= read -r line; do
                if echo "$line" | grep -q "^--"; then
                    if echo "$line" | grep -q "Processing KeyBox file"; then
                        print_yellow "$line"
                    elif echo "$line" | grep -q "KeyBox has EXPIRED"; then
                        warn "${line#-- }"  # Changed to warn to match silent mode
                    elif echo "$line" | grep -q "KeyBox has certificates nearing expiry"; then
                        print_orange "${line#-- }"
                    elif echo "$line" | grep -q "KeyBox is AOSP type"; then
                        print_pink "${line#-- }"  # Changed to print_pink to match silent mode
                    else
                        print "${line#-- }"
                    fi
                elif echo "$line" | grep -q "^!!!!"; then
                    if echo "$line" | grep -q "KeyBox is COMPROMISED"; then
                        warn "${line#!!!! }"
                    elif echo "$line" | grep -q "Certificate [0-9]\+ is compromised"; then
                        warning=$(echo "$line" | sed "s/ - SERIAL NUMBER: .*//;s/^!!!! Certificate //;s/ is compromised$//")
                        serial=$(echo "$line" | sed "s/^!!!! Certificate [0-9]\+ is compromised - SERIAL NUMBER: //")
                        printf "${BOLD_RED}!!!! Certificate %s is compromised${NC} ${RED}- SERIAL NUMBER: %s${NC}\n" "$warning" "$serial"
                    elif echo "$line" | grep -q "Certificate [0-9]\+ has expired"; then
                        warning=$(echo "$line" | sed "s/ - NOT AFTER: .*//;s/^!!!! Certificate //;s/ has expired$//")
                        not_after=$(echo "$line" | sed "s/^!!!! Certificate [0-9]\+ has expired - NOT AFTER: //")
                        printf "${BOLD_RED}!!!! Certificate %s has expired${NC} - NOT AFTER: %s\n" "$warning" "$not_after"
                    elif echo "$line" | grep -q "Certificate [0-9]\+ nearing expiry"; then
                        warning=$(echo "$line" | sed "s/ - NOT AFTER: .*//;s/^!!!! Certificate //;s/ nearing expiry$//")
                        not_after=$(echo "$line" | sed "s/^!!!! Certificate [0-9]\+ nearing expiry - NOT AFTER: //;s/ (.*//")
                        days=$(echo "$line" | sed "s/^.*(\([0-9]\+\) days remaining)/\1/")
                        printf "${BOLD_YELLOW}!!!! Certificate %s nearing expiry${NC} - NOT AFTER: %s (%s days remaining)\n" "$warning" "$not_after" "$days"
                    elif echo "$line" | grep -q "Certificate [0-9]\+ is AOSP type"; then
                        warning=$(echo "$line" | sed "s/ - COMMON NAME: .*//;s/^!!!! Certificate //;s/ is AOSP type$//")
                        common_name=$(echo "$line" | sed 's/^!!!! Certificate [0-9][0-9]* is AOSP type - COMMON NAME: //')
                        printf "${PINK}!!!! Certificate %s is AOSP type${NC} - COMMON NAME: %s\n" "$warning" "$common_name"
                    elif echo "$line" | grep -q "KeyBox is AOSP type"; then
                        printf "${PINK}-- %s${NC}\n" "${line#!!!! }"  # Changed to -- to match silent mode
                    elif echo "$line" | grep -q ": Serial number"; then
                        sn=$(echo "$line" | sed "s/^!!!! : Serial number //;s/ appears.*$//")
                        count=$(echo "$line" | sed "s/^!!!! : Serial number [^ ]* appears //;s/ times in the keybox file$//")
                        printf "${BOLD_YELLOW}!!!! : Serial number %s appears %s times in the keybox file${NC}\n" "$sn" "$count"
                    else
                        warn "${line#!!!! }"
                    fi
                else
                    if echo "$line" | grep -q "^CERTIFICATE:"; then
                        echo ""
                        cert_num=$(echo "$line" | sed 's/^CERTIFICATE: //')
                        printf "${BLUE}CERTIFICATE: %s${NC}\n" "$cert_num"
                    elif echo "$line" | grep -q "^    Serial Number:"; then
                        printf "    ${LIGHT_YELLOW}%s${NC}\n" "$(echo "$line" | sed 's/^    Serial Number: //')"
                    elif echo "$line" | grep -q "^    Issuer:"; then
                        printf "    %s\n" "$(echo "$line" | sed 's/^    //')"
                    elif echo "$line" | grep -q "^    Not After:"; then
                        printf "    %s\n" "$(echo "$line" | sed 's/^    //')"
                    elif echo "$line" | grep -q "^    Subject:"; then
                        printf "    %s\n" "$(echo "$line" | sed 's/^    //')"
                    elif echo "$line" | grep -q "^    Public Key Algorithm:"; then
                        printf "    %s\n" "$(echo "$line" | sed 's/^    //')"
                    elif echo "$line" | grep -q "^    CA:"; then
                        printf "    %s\n" "$(echo "$line" | sed 's/^    //')"
                    elif echo "$line" | grep -q "^Serial Numbers:"; then
                        echo ""
                        printf "${YELLOW}%s${NC}\n" "$line"
                    elif echo "$line" | grep -q "^    [0-9a-fA-F]\+"; then
                        printf "    ${LIGHT_YELLOW}%s${NC}\n" "$line"
                    else
                        echo "$line"
                    fi
                fi
            done
            echo "----------------------------------------"
        fi
    fi

    rm -f "$TMP" "$P7B" "$CER" "$JSON" 2>/dev/null || true
    log_debug "Cleaned up temporary files for $KB"
    [ $SILENT -eq 1 ] && echo ""
done

# --- Cleanup and Summary ---
rm -f "$JSON_TEMP" "wget_err.log" 2>/dev/null || true
if [ $QUIET -eq 0 ]; then
    if [ $SILENT -eq 0 ]; then
        echo ""
        # Summary header remains green
        print "Summary:"

        if [ $TOTAL_FILES -gt 0 ]; then
            print "  Total files processed: $TOTAL_FILES"
        else
            print "  No files processed"
        fi

        # Banned Keyboxes (contains compromised certificates)
        if [ ${#BANNED_KEYBOXES[@]} -gt 0 ]; then
            print_orange "  Total banned keyboxes (compromised): ${#BANNED_KEYBOXES[@]}"
            for kb in "${BANNED_KEYBOXES[@]}"; do
                print_red "    $kb"
            done
        else
            print "  No banned keyboxes found"
        fi

        # Expired Keyboxes (contains expired certificates)
        if [ ${#EXPIRED_KEYBOXES[@]} -gt 0 ]; then
            print_orange "  Total expired keyboxes: ${#EXPIRED_KEYBOXES[@]}"
            for kb in "${EXPIRED_KEYBOXES[@]}"; do
                print_red "    $kb"
            done
        else
            print "  No expired keyboxes found"
        fi

        # AOSP Keyboxes (assumed to be Google's Software AOSP keybox)
        if [ ${#AOSP_KEYBOXES[@]} -gt 0 ]; then
            print_orange "  Total AOSP type keyboxes: ${#AOSP_KEYBOXES[@]}"
            for kb in "${AOSP_KEYBOXES[@]}"; do
                print_pink "    $kb"
            done
        else
            print "  No AOSP type keyboxes found"
        fi

        # Keyboxes with certificates nearing expiry
        if [ ${#WARNING_KEYBOXES[@]} -gt 0 ]; then
            print_orange "  Total keyboxes nearing expiry: ${#WARNING_KEYBOXES[@]}"
            for kb in "${WARNING_KEYBOXES[@]}"; do
                print_light_yellow "    $kb"
            done
        else
            print "  No keyboxes nearing expiry"
        fi

        # Valid Keyboxes (not expired, not compromised, not AOSP)
        if [ $TOTAL_VALID -gt 0 ]; then
            print "  Total valid keyboxes: $TOTAL_VALID"
        else
            print "  No valid keyboxes found"
        fi

        echo ""
        print "Check complete"
    else
        # Summary for silent mode
        if [ $TOTAL_FILES -gt 0 ]; then
            echo ""
            print "Summary:"
            print "  Total files processed: $TOTAL_FILES"
            if [ ${#BANNED_KEYBOXES[@]} -gt 0 ]; then
                print_red "  Total banned keyboxes (compromised): ${#BANNED_KEYBOXES[@]}"
            fi
            if [ ${#EXPIRED_KEYBOXES[@]} -gt 0 ]; then
                print_red "  Total expired keyboxes: ${#EXPIRED_KEYBOXES[@]}"
            fi
            if [ ${#AOSP_KEYBOXES[@]} -gt 0 ]; then
                print_pink "  Total AOSP type keyboxes: ${#AOSP_KEYBOXES[@]}"
            fi
            if [ ${#WARNING_KEYBOXES[@]} -gt 0 ]; then
                print_orange "  Total keyboxes nearing expiry: ${#WARNING_KEYBOXES[@]}"
            fi
            if [ $TOTAL_VALID -gt 0 ]; then
                print "  Total valid keyboxes: $TOTAL_VALID"
            fi
            print "Check complete"
        fi
    fi
fi

if [ $DEBUG -eq 1 ]; then
    log_debug "Script completed"
    echo "Debug log saved to $LOG_FILE"
fi
