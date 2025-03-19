#!/data/data/com.termux/files/usr/bin/bash

# zg.sh v2.1 - Updated March 2025
# Usage: ./zg.sh [-q] [-s] [-d] [directory_or_file]
# Dependencies: openssl-tool, wget
# Purpose: Processes keybox.xml files to check certificate expiration and revocation status
# Original code by zgfg@xda © Jan 2025 - All Rights Reserved
# Modified and extended by shoey63 (XDA) with Grok 3 (xAI) - March 2025

# Initialize variables
QUIET=0 SILENT=0 DEBUG=0
LOG_FILE="/sdcard/Download/zg_debug.log.txt"
WARNING_THRESHOLD_DAYS=30
declare -i TOTAL_FILES=0 TOTAL_INVALID=0 TOTAL_AOSP=0 TOTAL_VALID=0 TOTAL_WARNING=0 TOTAL_TAMPERED=0 TOTAL_SKIPPED=0
declare -a INVALID_KEYBOXES AOSP_KEYBOXES WARNING_KEYBOXES TAMPERED_KEYBOXES SKIPPED_KEYBOXES VALID_KEYBOXES

# ANSI color codes
GREEN='\033[1;32m' YELLOW='\033[1;38;5;220m' LIGHT_YELLOW='\033[0;93m' PINK='\033[1;95m'
RED='\033[31m' BOLD_RED='\033[1;31m' ORANGE='\033[1;38;5;208m' NC='\033[0m' BLUE='\033[1;34m'
BOLD_YELLOW='\033[1;33m' PURPLE='\033[1;35m'

# Debug Logging
# Log debug messages to a file with a timestamp if DEBUG is enabled
log_debug() {
    if [ $DEBUG -eq 1 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $@" >> "$LOG_FILE" || {
            printf "${BOLD_RED}!!!! ERROR: Failed to write to debug log $LOG_FILE${NC}\n" >&2
            exit 1
        }
    fi
}

# File Permission Check
# Ensure Termux has file access permissions
check_file_permissions() {
    DEFAULT_DIR="/sdcard/Download"
    if ! mkdir -p "$DEFAULT_DIR" 2>/dev/null || \
       ! touch "$DEFAULT_DIR/_zg_test_permission.txt" 2>/dev/null; then
        # This is an error case, so we allow output even in quiet mode to inform the user
        printf "${BOLD_RED}!!!! ERROR: Termux requires file access permission. Grant it in App Settings > Permissions > Files and retry.${NC}\n"
        exit 1
    fi
    rm -f "$DEFAULT_DIR/_zg_test_permission.txt" 2>/dev/null
}
check_file_permissions

# Helper Functions
# Print a message in green with a "--" prefix
print() {
    log_debug "PRINT: $@"
    [ $QUIET -eq 0 ] && printf "${GREEN}-- %s${NC}\n" "$@" 2>&1
}

# Print a message in yellow with a "--" prefix
print_yellow() {
    log_debug "PRINT_YELLOW: $@"
    [ $QUIET -eq 0 ] && printf "${YELLOW}-- %s${NC}\n" "$@" 2>&1
}

# Print a message in light yellow
print_light_yellow() {
    log_debug "PRINT_LIGHT_YELLOW: $@"
    [ $QUIET -eq 0 ] && printf "${LIGHT_YELLOW}%s${NC}\n" "$@" 2>&1
}

# Print a message in orange with a "--" prefix
print_orange() {
    log_debug "PRINT_ORANGE: $@"
    [ $QUIET -eq 0 ] && printf "${ORANGE}-- %s${NC}\n" "$@" 2>&1
}

# Print a message in bold red with a "--" prefix
print_red() {
    log_debug "PRINT_RED: $@"
    [ $QUIET -eq 0 ] && printf "${BOLD_RED}-- %s${NC}\n" "$@" 2>&1
}

# Print a message in pink with a "--" prefix
print_pink() {
    log_debug "PRINT_PINK: $@"
    [ $QUIET -eq 0 ] && printf "${PINK}-- %s${NC}\n" "$@" 2>&1
}

# Print a message in blue
print_blue() {
    log_debug "PRINT_BLUE: $@"
    [ $QUIET -eq 0 ] && printf "${BLUE}%s${NC}\n" "$@" 2>&1
}

# Print a message in bold yellow with a "--" prefix
print_bold_yellow() {
    log_debug "PRINT_BOLD_YELLOW: $@"
    [ $QUIET -eq 0 ] && printf "${BOLD_YELLOW}-- %s${NC}\n" "$@" 2>&1
}

# Print a message in purple with a "--" prefix
print_purple() {
    log_debug "PRINT_PURPLE: $@"
    [ $QUIET -eq 0 ] && printf "${PURPLE}-- %s${NC}\n" "$@" 2>&1
}

# Print a warning message in bold red with a "!!!!" prefix
warn() {
    log_debug "WARN: $@"
    [ $QUIET -eq 0 ] && [ $SILENT -eq 0 ] && printf "${BOLD_RED}!!!! %s${NC}\n" "$@" 2>&1
}

# Print an error message in bold red and exit
error() {
    log_debug "ERROR: $@"
    # This is an error case, so we allow output even in quiet mode to inform the user
    printf "${BOLD_RED}!!!! ERROR: %s, cannot proceed${NC}\n" "$@" 2>&1
    exit 1
}

# Dependency Check
# Install a package if it's not already installed
install_package() {
    local pkg="$1" check="$2"
    local temp_file=$(mktemp)
    log_debug "Checking for $pkg"
    if ! $check >/dev/null 2>&1; then
        [ $QUIET -eq 0 ] && [ $SILENT -eq 0 ] && printf "\n${BLUE}Installing ${YELLOW}$pkg${BLUE}...${NC}\n\n"
        log_debug "Installing $pkg"
        pkg install "$pkg" -y >"$temp_file" 2>&1
        local install_status=$?
        cat "$temp_file" | tr -d '\r' | sed 's/\x1B\[[0-9;]*[mK]//g' | grep -v "Reading database" | while IFS= read -r line; do
            if echo "$line" | grep -q "No mirror or mirror group selected" || \
               echo "$line" | grep -q "WARNING: apt does not have a stable CLI interface"; then
                continue
            fi
            if echo "$line" | grep -q -E "Installing|Reading package lists|Building dependency tree|\
                                          Setting up|Preparing to unpack|Selecting previously"; then
                [ $QUIET -eq 0 ] && printf "${BLUE}%s${NC}\n" "$line"
            elif echo "$line" | grep -q -E "Error:|warning:|not found"; then
                [ $QUIET -eq 0 ] && printf "${RED}%s${NC}\n" "$line"
                log_debug "Installation error: $line"
            elif echo "$line" | grep -q -E "Checking availability|\[\*\]"; then
                [ $QUIET -eq 0 ] && printf "${GREEN}%s${NC}\n" "$line"
            else
                [ $QUIET -eq 0 ] && printf "${YELLOW}%s${NC}\n" "$line"
            fi
        done
        if [ $install_status -eq 0 ]; then
            [ $QUIET -eq 0 ] && [ $SILENT -eq 0 ] && printf "\n${GREEN}Successfully installed ${YELLOW}$pkg${NC}\n\n"
            log_debug "Successfully installed $pkg"
        else
            printf "${RED}Failed to install $pkg${NC}\n" >&2
            log_debug "Failed to install $pkg"
            exit 1
        fi
        rm -f "$temp_file"
    fi
}

install_package openssl-tool "openssl -v"
install_package wget "wget -V"

# Convert a date string to epoch time
get_epoch() {
    local date_str="$1"
    local epoch=$(date -d "$date_str" +%s 2>/dev/null)
    [ -z "$epoch" ] && { log_debug "Failed to parse date: $date_str"; return 1; }
    echo "$epoch"
    return 0
}

# Validate XML Structure
# Check if the XML file contains required tags: <AndroidAttestation>, <Keybox>, and <Certificate>
validate_xml() {
    local KB="$1"
    if ! grep -q -E "<AndroidAttestation>|<Keybox |<Certificate " "$KB"; then
        return 1
    fi
    return 0
}

# Generate a detailed report for a keybox file
# Process certificates, check for expiration, compromised status, AOSP type, and tampering
generate_report() {
    local KB="$1" TXT="$2" JSON="$3"
    local TMP=$(mktemp) P7B=$(mktemp) CER=$(mktemp) TMP_CERT=$(mktemp)
    local tampering_detected=0
    trap 'rm -f "$TMP" "$P7B" "$CER" "$TMP_CERT" 2>/dev/null' RETURN
    if ! validate_xml "$KB"; then
        if [ $SILENT -eq 1 ]; then
            print_bold_yellow "Results for: $KB"
            print_red "Invalid XML structure - possible tampering detected"
        else
            warn "Invalid XML structure in $KB - possible tampering detected"
        fi
        echo "!!!! ERROR: Invalid XML structure in $KB - possible tampering detected" >> "$TXT"
        TOTAL_TAMPERED=$((TOTAL_TAMPERED + 1))
        TAMPERED_KEYBOXES+=("${KB##*/}")
        return 1
    fi

    if ! sed 's!">-----BEGIN!">\n-----BEGIN!g;s!CERTIFICATE-----</!CERTIFICATE-----\n</!g;s!^[ \t]*!!' \
             "$KB" > "$TMP"; then
        if [ $SILENT -eq 1 ]; then
            print_bold_yellow "Results for: $KB"
            print_red "Failed to reformat - possible tampering or corruption"
        else
            warn "Failed to reformat $KB - possible tampering or corruption"
        fi
        echo "!!!! ERROR: Failed to reformat $KB - possible tampering or corruption" >> "$TXT"
        TOTAL_TAMPERED=$((TOTAL_TAMPERED + 1))
        TAMPERED_KEYBOXES+=("${KB##*/}")
        return 1
    fi

    if ! openssl crl2pkcs7 -nocrl -certfile "$TMP" -out "$P7B" 2>/dev/null; then
        if [ $SILENT -eq 1 ]; then
            print_bold_yellow "Results for: $KB"
            print_red "Failed to convert to pkcs7 - invalid certificate data, possible tampering (e.g., invalid title)"
        else
            warn "Failed to convert $KB to pkcs7 - invalid certificate data, possible tampering (e.g., invalid title)"
        fi
        echo "!!!! ERROR: Failed to convert $KB to pkcs7 - invalid certificate data, possible tampering (e.g., invalid title)" >> "$TXT"
        TOTAL_TAMPERED=$((TOTAL_TAMPERED + 1))
        TAMPERED_KEYBOXES+=("${KB##*/}")
        return 1
    fi

    if ! openssl pkcs7 -print_certs -text -in "$P7B" -out "$CER" 2>/dev/null; then
        if [ $SILENT -eq 1 ]; then
            print_bold_yellow "Results for: $KB"
            print_red "Failed to dump certificates - invalid pkcs7 data, possible tampering"
        else
            warn "Failed to dump certificates from $KB - invalid pkcs7 data, possible tampering"
        fi
        echo "!!!! ERROR: Failed to dump certificates from $KB - invalid pkcs7 data, possible tampering" >> "$TXT"
        TOTAL_TAMPERED=$((TOTAL_TAMPERED + 1))
        TAMPERED_KEYBOXES+=("${KB##*/}")
        return 1
    fi

    echo "KeyBox file: $KB" > "$TXT"
    echo "" >> "$TXT"
    if [ $SILENT -eq 1 ]; then
        print_bold_yellow "Results for: $KB"
    else
        print_yellow "Processing KeyBox file: $KB"
    fi

    local cert_num=0 K=0 M=0 J=0 L=0 sn na na_epoch days_remaining issuer subject cn pk_algorithm
    local compromised_printed=0 has_duplicates=0
    declare -A serial_counts
    currentEpoch=$(get_epoch "$(date --utc)") || error "Failed to get current epoch"
    log_debug "Current epoch: $currentEpoch"

    sed 's/^[ \t]*//' "$CER" | awk '
        BEGIN {cert_num = 0}
        /^Certificate:/ {if (cert_num > 0) print ""; cert_num++; print "CERTIFICATE: " cert_num; next}
        /^Serial Number:/ {
            getline sn;
            sub(/^[ \t]*/, "", sn);
            gsub(/[ :]/, "", sn);
            if (sn ~ /^[0-9a-fA-F]+$/) {
                print "32:" sn;
            } else {
                print "32:missing";
            }
            next
        }
        /^Issuer:/ {sub(/^Issuer: /, ""); print "Issuer: " $0; next}
        /^Not After :/ {sub(/^Not After : /, ""); print "Not After: " $0; next}
        /^Subject:/ {sub(/^Subject: /, ""); print "Subject: " $0; next}
        /^Public Key Algorithm:/ {sub(/^Public Key Algorithm: /, ""); print "Public Key Algorithm: " $0; next}
    ' > "$TMP_CERT" || {
        warn "Failed to process certificate data with awk"
        echo "!!!! ERROR: Failed to process certificate data with awk" >> "$TXT"
        TOTAL_TAMPERED=$((TOTAL_TAMPERED + 1))
        TAMPERED_KEYBOXES+=("${KB##*/}")
        return 1
    }

    while IFS= read -r line; do
        log_debug "Line read: $line"
        if [[ "$line" =~ ^CERTIFICATE:\ ([0-9]+) ]]; then
            cert_num="${BASH_REMATCH[1]}"
            log_debug "Set cert_num to '$cert_num'"
            if [ $SILENT -eq 0 ]; then
                [ $cert_num -gt 1 ] && [ $QUIET -eq 0 ] && echo ""
                # Unindent CERTIFICATE line
                print_blue "$line"
            fi
            # No indent in file output
            echo "$line" >> "$TXT"
            sn="" na="" na_epoch="" days_remaining="" issuer="" subject="" cn="" pk_algorithm=""
            compromised_printed=0
        elif [[ "$line" =~ ^32:([0-9a-fA-F]+) ]]; then
            sn="${BASH_REMATCH[1]}"
            if [ -z "$sn" ]; then
                warn "Certificate $cert_num missing Serial Number - possible tampering"
                echo "!!!! Certificate $cert_num missing Serial Number - possible tampering" >> "$TXT"
                tampering_detected=1
            else
                serial_counts["$sn"]=$(( ${serial_counts["$sn"]:-0} + 1 ))
                # Indent Serial Number
                [ $SILENT -eq 0 ] && print_light_yellow "    $sn"
                # No indent in file output
                echo "$sn" >> "$TXT"
                log_debug "Processing SN: $sn for cert $cert_num"
            fi
        elif [[ "$line" =~ ^32:missing ]]; then
            sn=""
            if [ -n "$cn" ] && [[ ! "$cn" =~ Android.*Software\ Attestation ]]; then
                warn "Certificate $cert_num missing Serial Number - possible tampering"
                echo "!!!! Certificate $cert_num missing Serial Number - possible tampering" >> "$TXT"
                tampering_detected=1
            fi
        elif [[ "$line" =~ ^Issuer:\ (.+) ]]; then
            issuer="${BASH_REMATCH[1]}"
            # Indent Issuer
            [ $SILENT -eq 0 ] && [ $QUIET -eq 0 ] && printf "    Issuer: %s\n" "$issuer"
            # No indent in file output
            echo "Issuer: $issuer" >> "$TXT"
        elif [[ "$line" =~ ^Not\ After:\ (.+) ]]; then
            na="${BASH_REMATCH[1]}"
            if [ -z "$na" ]; then
                warn "Certificate $cert_num missing Not After date - possible tampering"
                echo "!!!! Certificate $cert_num missing Not After date - possible tampering" >> "$TXT"
                tampering_detected=1
            else
                na_epoch=$(get_epoch "$na") || { warn "Could not parse date: $na"; echo "!!!! Could not parse date: $na" >> "$TXT"; continue; }
                days_remaining=$(( (na_epoch - currentEpoch) / 86400 ))
                # Indent Not After
                [ $SILENT -eq 0 ] && [ $QUIET -eq 0 ] && printf "    Not After: %s\n" "$na"
                # No indent in file output
                echo "Not After: $na" >> "$TXT"
                log_debug "Cert $cert_num: Not After $na, na_epoch: $na_epoch, days_remaining: $days_remaining $([ $days_remaining -le 0 ] && echo "(expired)")"
            fi
        elif [[ "$line" =~ ^Subject:\ (.+) ]]; then
            subject="${BASH_REMATCH[1]}"
            if [ -z "$subject" ]; then
                warn "Certificate $cert_num missing Subject - possible tampering"
                echo "!!!! Certificate $cert_num missing Subject - possible tampering" >> "$TXT"
                tampering_detected=1
            else
                cn=$(echo "$subject" | grep -o 'CN=[^,]*' | sed 's/CN=//' | head -n1)
                # Indent Subject
                [ $SILENT -eq 0 ] && [ $QUIET -eq 0 ] && printf "    Subject: %s\n" "$subject"
                # No indent in file output
                echo "Subject: $subject" >> "$TXT"
                log_debug "Cert $cert_num: Subject $subject, CN $cn"
            fi
        elif [[ "$line" =~ ^Public\ Key\ Algorithm:\ (.+) ]]; then
            pk_algorithm="${BASH_REMATCH[1]}"
            # Indent Public Key Algorithm
            [ $SILENT -eq 0 ] && [ $QUIET -eq 0 ] && printf "    Public Key Algorithm: %s\n" "$pk_algorithm"
            # No indent in file output
            echo "Public Key Algorithm: $pk_algorithm" >> "$TXT"
            log_debug "Cert $cert_num: Public Key Algorithm $pk_algorithm"

            # Check if the certificate is compromised
            if [ -n "$sn" ] && [ $compromised_printed -eq 0 ] && grep -w "\"$sn\":" "$JSON" >/dev/null 2>&1; then
                L=$((L + 1))
                [ $SILENT -eq 0 ] && warn "Certificate $cert_num is compromised"
                echo "!!!! Certificate $cert_num is compromised" >> "$TXT"
                compromised_printed=1
            fi

            if [ -n "$na_epoch" ]; then
                if [ "$currentEpoch" -gt "$na_epoch" ]; then
                    K=$((K + 1))
                    [ $SILENT -eq 0 ] && warn "Certificate $cert_num has expired"
                    echo "!!!! Certificate $cert_num has expired" >> "$TXT"
                elif [ $days_remaining -le $WARNING_THRESHOLD_DAYS ] && [ $days_remaining -gt 0 ] && [ $L -eq 0 ]; then
                    M=$((M + 1))
                    # Keep warning unindented
                    [ $SILENT -eq 0 ] && [ $QUIET -eq 0 ] && printf "${YELLOW}!!!! Certificate %s nearing expiry (%d days remaining)${NC}\n" "$cert_num" "$days_remaining"
                    echo "!!!! Certificate $cert_num nearing expiry ($days_remaining days remaining)" >> "$TXT"
                fi
            fi

            # Check if the certificate is AOSP type based on subject or CN
            if [[ "$subject" =~ Android.*(Software|Keystore).*(Attestation|Key) ]] || \
               [[ "$cn" =~ Android.*(Software|Keystore).*(Attestation|Key) ]]; then
                J=$((J + 1))
                [ $SILENT -eq 0 ] && print_pink "Certificate $cert_num is AOSP type"
                echo "!!!! Certificate $cert_num is AOSP type" >> "$TXT"
            fi
        fi
    done < "$TMP_CERT"

    echo "" >> "$TXT"
    echo "Serial Numbers:" >> "$TXT"
    for sn in "${!serial_counts[@]}"; do
        echo "    $sn" >> "$TXT"
        if [ "${serial_counts["$sn"]}" -gt 1 ]; then
            has_duplicates=1
            # Indent duplicate note
            [ $SILENT -eq 0 ] && print_light_yellow "    !!!! Note: Serial number $sn appears ${serial_counts["$sn"]} times in the keybox file"
            echo "!!!! Note: Serial number $sn appears ${serial_counts["$sn"]} times in the keybox file" >> "$TXT"
        fi
    done
    echo "" >> "$TXT"

    if [ $tampering_detected -eq 1 ]; then
        TOTAL_TAMPERED=$((TOTAL_TAMPERED + 1))
        TAMPERED_KEYBOXES+=("${KB##*/}")
        return 1
    fi

    local added_to_invalid=0
    if [ $K -gt 0 ]; then
        [ $SILENT -eq 0 ] && [ $QUIET -eq 0 ] && echo ""
        if [ $SILENT -eq 1 ]; then
            print_red "KeyBox has EXPIRED"
        else
            warn "KeyBox has EXPIRED"
        fi
        echo "!!!! KeyBox has EXPIRED" >> "$TXT"
        if [ $L -gt 0 ]; then
            if [ $SILENT -eq 1 ]; then
                print_red "KeyBox is COMPROMISED"
            else
                warn "KeyBox is COMPROMISED"
            fi
            echo "!!!! KeyBox is COMPROMISED" >> "$TXT"
            [ $SILENT -eq 0 ] && [ $QUIET -eq 0 ] && echo ""
            if [ $added_to_invalid -eq 0 ]; then
                TOTAL_INVALID=$((TOTAL_INVALID + 1))
                INVALID_KEYBOXES+=("${KB##*/}")
            fi
        else
            [ $SILENT -eq 0 ] && [ $QUIET -eq 0 ] && echo ""
            if [ $L -eq 0 ]; then
                TOTAL_INVALID=$((TOTAL_INVALID + 1))
                INVALID_KEYBOXES+=("${KB##*/}")
                added_to_invalid=1
            fi
        fi
    elif [ $L -gt 0 ]; then
        [ $SILENT -eq 0 ] && [ $QUIET -eq 0 ] && echo ""
        if [ $SILENT -eq 1 ]; then
            print_red "KeyBox is COMPROMISED"
        else
            warn "KeyBox is COMPROMISED"
        fi
        echo "!!!! KeyBox is COMPROMISED" >> "$TXT"
        [ $SILENT -eq 0 ] && [ $QUIET -eq 0 ] && echo ""
        if [ $added_to_invalid -eq 0 ]; then
            TOTAL_INVALID=$((TOTAL_INVALID + 1))
            INVALID_KEYBOXES+=("${KB##*/}")
        fi
    fi

    if [ $K -eq 0 ]; then
        if [ $M -gt 0 ] && [ $L -eq 0 ]; then
            [ $SILENT -eq 0 ] && [ $QUIET -eq 0 ] && echo ""
            print_orange "KeyBox has certificates nearing expiry"
            echo "!!!! KeyBox has certificates nearing expiry" >> "$TXT"
            TOTAL_WARNING=$((TOTAL_WARNING + 1))
            WARNING_KEYBOXES+=("${KB##*/}")
        fi
        if [ $J -gt 0 ]; then
            [ $SILENT -eq 0 ] && [ $QUIET -eq 0 ] && echo ""
            if [ $SILENT -eq 1 ]; then
                print_pink "KeyBox is AOSP type"
            else
                print_pink "KeyBox is AOSP type"
            fi
            echo "!!!! KeyBox is AOSP type" >> "$TXT"
            AOSP_KEYBOXES+=("${KB##*/}")
        fi
    fi

    if [ $K -eq 0 ] && [ $L -eq 0 ]; then
        [ $SILENT -eq 0 ] && [ $QUIET -eq 0 ] && echo ""
        print "KeyBox is not compromised or expired"
        echo "-- KeyBox is not compromised or expired" >> "$TXT"
        [ $SILENT -eq 0 ] && [ $QUIET -eq 0 ] && echo ""
        if [ $J -eq 0 ]; then
            TOTAL_VALID=$((TOTAL_VALID + 1))
            VALID_KEYBOXES+=("${KB##*/}")
        fi
    fi

    echo "" >> "$TXT"
}

# Argument Parsing
while getopts "qsd" opt; do
    case $opt in
        q) QUIET=1 ;;
        s) SILENT=1 ;;
        d) DEBUG=1 ;;
        ?) echo "Usage: $0 [-q] [-s] [-d] [directory_or_file]" >&2; exit 1 ;;
    esac
done
shift $((OPTIND-1))
[ $DEBUG -eq 1 ] && echo "Debug log started: $(date)" > "$LOG_FILE" 2>/dev/null

# File Selection
if [ $# -eq 1 ]; then
    [ -d "$1" ] && XML_FILES=("$1"/*.xml) || { [ -f "$1" ] && [[ "$1" =~ \.xml$ ]] && XML_FILES=("$1") || error "Invalid path: $1"; }
    [ ! -e "${XML_FILES[0]}" ] && error "No .xml files found in $1"
else
    XML_FILES=("/sdcard/Download"/*.xml)
    [ ! -e "${XML_FILES[0]}" ] && error "No .xml files in /sdcard/Download"
fi

# Download Revocation List
JSON_TEMP=$(mktemp)
[ $QUIET -eq 0 ] && print "Checking against compromised certificates list..."
wget -q -O "$JSON_TEMP" --no-check-certificate https://android.googleapis.com/attestation/status 2>/dev/null || \
    error "Failed to download revocation list"
[ ! -s "$JSON_TEMP" ] && error "Revocation list is empty"

# Main Loop
trap 'rm -f "$JSON_TEMP" 2>/dev/null' EXIT INT TERM
for KB in "${XML_FILES[@]}"; do
    if [[ ! $(grep "BEGIN CERTIFICATE" "$KB") ]]; then
        if [ $SILENT -eq 1 ]; then
            print_bold_yellow "Results for: $KB"
            print_red "No certificates found, skipped"
        else
            warn "No certificates in $KB, skipping"
        fi
        TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
        SKIPPED_KEYBOXES+=("${KB##*/}")
    else
        RESULTS_DIR="$(dirname "$KB")/results"
        mkdir -p "$RESULTS_DIR" || error "Cannot create $RESULTS_DIR"
        TXT="$RESULTS_DIR/${KB##*/}.txt"
        TOTAL_FILES=$((TOTAL_FILES + 1))
        generate_report "$KB" "$TXT" "$JSON_TEMP"
    fi
    # Print separator unless in quiet or silent mode
    [ $QUIET -eq 0 ] && [ $SILENT -eq 0 ] && echo "----------------------------------------"
    [ $SILENT -eq 1 ] && [ $QUIET -eq 0 ] && echo ""
done

# Summary
if [ $QUIET -eq 0 ]; then
    echo ""
    print "Summary:"
    print "  Total files processed: $TOTAL_FILES"
    if [ ${#SKIPPED_KEYBOXES[@]} -gt 0 ]; then
        print_purple "  Total skipped keyboxes: $TOTAL_SKIPPED"
        for kb in "${SKIPPED_KEYBOXES[@]}"; do print_red "    $kb"; done
    else
        print_purple "  Total skipped keyboxes: 0"
    fi
    if [ ${#TAMPERED_KEYBOXES[@]} -gt 0 ]; then
        print_purple "  Total keyboxes with suspected tampering: ${#TAMPERED_KEYBOXES[@]}"
        for kb in "${TAMPERED_KEYBOXES[@]}"; do print_red "    $kb"; done
    else
        print "  No keyboxes with suspected tampering"
    fi
    if [ ${#INVALID_KEYBOXES[@]} -gt 0 ]; then
        print_orange "  Total compromised and/or expired keyboxes: ${#INVALID_KEYBOXES[@]}"
        for kb in "${INVALID_KEYBOXES[@]}"; do print_red "    $kb"; done
    else
        print "  No compromised or expired keyboxes found"
    fi
    if [ ${#AOSP_KEYBOXES[@]} -gt 0 ]; then
        print_bold_yellow "  Total AOSP type keyboxes: ${#AOSP_KEYBOXES[@]}"
        for kb in "${AOSP_KEYBOXES[@]}"; do print_pink "    $kb"; done
    else
        print "  No AOSP type keyboxes found"
    fi
    if [ ${#WARNING_KEYBOXES[@]} -gt 0 ]; then
        print_orange "  Total keyboxes nearing expiry: ${#WARNING_KEYBOXES[@]}"
        for kb in "${WARNING_KEYBOXES[@]}"; do print_bold_yellow "    $kb"; done
    else
        print "  No keyboxes nearing expiry"
    fi
    if [ ${#VALID_KEYBOXES[@]} -gt 0 ]; then
        print_blue "--   Total valid keyboxes: ${#VALID_KEYBOXES[@]}"
        for kb in "${VALID_KEYBOXES[@]}"; do print "    $kb"; done
    else
        print "  No valid keyboxes found"
    fi
    print "Check complete"
fi
[ $DEBUG -eq 1 ] && [ $QUIET -eq 0 ] && echo "Debug log saved to $LOG_FILE"
