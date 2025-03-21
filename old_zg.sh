#!/system/bin/sh
# zgfg@xda © Jan 2025- All Rights Reserved

# Helper functions
print() { echo "-- $@"; }
warn() { echo "!!!! $@"; }
error() { warn "ERROR: $@, cannot proceed"; exit 1; }
date() { busybox date "$@"; }
wget() { busybox wget "$@"; }

# Check for working directory
DIR=${0%/*};
if [ -z "$DIR" -o "$DIR" == "/" ]; then
  DIR="/sdcard/Download";
fi;

# Debug logging
#LogFile="$DIR/_dump-keybox.log";
if [ -n "$LogFile" ]; then
  exec 3>&1 4>&2 2>$LogFile 1>&2;
  set -x;
fi;

cd "$DIR";
print "Working directory: $(pwd)";

# Check for root permissions
if [ "$USER" != "root" -a "$(whoami 2>/dev/null)" != "root" ]; then
  error "root permissions missing";
fi;

# Check for openssl binary
if [ -z $(which openssl) ]; then
  error "openssl executable not found";
fi;

# Check for KB file to dump
if [ -n "$1" ]; then
  KB="$1";
else
  KB="/data/adb/tricky_store/keybox.xml";
#  KB="$DIR/kb.xml";  # toDo, testing, remove
fi;
if [ ! -f "$KB" ]; then
  KB="$DIR/keybox.xml";
fi;

print "KeyBox file: $KB";
if [ ! -f "$KB" ]; then
  error "$KB file to dump not found";
fi;

# Reformat KB
TMP="_keybox.tmp.txt";
rm -f "$TMP";
cat "$KB" | \
  sed 's!">-----BEGIN!">\n-----BEGIN!g' | \
  sed 's!CERTIFICATE-----</!CERTIFICATE-----\n</!g' | \
  sed 's!^[ \t]*!!' >> "$TMP";

if [ ! -f "$TMP" ]; then
  error "failed to reformat $KB";
fi;

# Convert KB to P7B format
P7B="_keybox.p7b";
rm -f "$P7B";
openssl crl2pkcs7 -nocrl -certfile "$TMP" -out "$P7B";

if [ ! -f "$P7B" ]; then
  error "failed to convert $KB to pkcs7";
fi;

# Dump KB to CER format
CER="_keybox.cer.txt";
rm -f "$CER";
openssl pkcs7 -print_certs -text -in "$P7B" -out "$CER";

if [ ! -f "$CER" ]; then
  error "failed to dump $KB";
fi;

# Extract info from KB to text file
TXT="_keybox.txt";
rm -f "$TXT";
print "KeyBox file: $KB" >> "$TXT";

cat "$CER" | sed 's/^[ \t]*//' | \
  sed '/^Serial Number/N;s/:[ \t]*\n/: /' | \
  grep -Es '^Certificate:|^Serial Number:|^Issuer:|^Not After|^Subject:|^Public Key Algorithm:|CA:' | \
  sed 's/^Not After :/Not After:/' | \
  sed 's/^/  /' | sed 's/^[ ]*Certificate:/\nCERTIFICATE:/' >> "$TXT";
echo "" >> "$TXT";

# Extract Subjects
SubjectList=$(cat "$TXT" | grep 'Subject:' | \
  sed 's/^.*Subject://' | sed 's/^[ ]*//' | sed 's/ /_/g');

if [ -z "$SubjectList" ]; then
  warn "Subjects not extracted" >> "$TXT";
  echo "" >> "$TXT";
fi;

# Check Common Names in Subjects
(( i = 0 )); (( J = i ));
for Subject in $SubjectList; do
  (( i++ ));
  CN=$(echo "$Subject" | grep 'CN=' | \
    sed 's/^.*CN=//' | sed 's/_/ /g' | sed 's/^[ ]*//');
  AOSP=$(echo "$CN" | grep 'Android.*Software Attestation');
  if [ -n "$AOSP" ]; then
    (( J = i ));
    warn "Certificate $J is AOSP type - COMMON NAME: $CN" >> "$TXT";
  fi;
done;
if (( J > 0 )); then
  echo "" >> "$TXT";
fi;

# Extract Serial Numbers
SNList=$(cat "$TXT" | grep 'Serial Number:' | \
  sed 's/^.*Serial Number://' | sed 's/(.*$//' | \
  sed 's/[ :]//g' | sed 's/0x//' | sed 's/^[0]*//');
echo "Serial Numbers:\n$SNList" >> "$TXT";
echo "" >> "$TXT";

if [ -z "$SNList" ]; then
  error "Serial Numbers not extracted";
fi;

# Check for busybox binary
if [ -z $(which busybox) ]; then
  error "busybox executable not found";
fi;

# Extract Not After dates
UTC=$(date --utc);
Epoch=$(date -D "$UTC" +"%s");
Year=$(date -D "$UTC" +"%Y");
NAList=$(cat "$TXT" | grep 'Not After:' | \
  sed 's/^.*Not After://' | sed 's/^[ ]*//' | \
  sed 's/ G.*$//' | sed 's/ /_/g');

if [ -z "$NAList" ]; then
  error "Not After dates not extracted";
fi;

# Check Not After dates
(( i = 0 )); (( K = i ));
for NA in $NAList; do
  (( i++ ));
  NA=$(echo "$NA" | sed 's/_/ /g');
  NAEpoch=$(date -d "$NA" +"%s");
  NAYear=$(date -d "$NA" +"%Y");
  if (( Year >= NAYear )) && (( Epoch > NAEpoch )); then
    (( K = i ));
    warn "Certificate $K has expired - NOT AFTER: $NA" >> "$TXT";
  fi;
done;
if (( K > 0 )); then
  echo "" >> "$TXT";
fi;

# Check Serial Numbers
JSON="_CompromisedCerts.json.txt";
rm -f "$JSON";
wget -q -O "$JSON" --no-check-certificate https://android.googleapis.com/attestation/status 2>&1 || error "failed to downolad compromised certificates list";

(( i = 0 )); (( L = i ));
for SN in $SNList; do
  (( i++ ));
  Compromised=$(cat "$JSON" | grep -w "$SN");
  if [ -n "$Compromised" ]; then
    (( L = i ));
    warn "Certificate $L is compromised - SERIAL NUMBER: $SN" >> "$TXT";
  fi;
done;
if (( L > 0 )); then
  echo "" >> "$TXT";
fi;

if (( K > 0 )); then
  warn "KeyBox has EXPIRED" >> "$TXT";
else
  print "KeyBox has not expired" >> "$TXT";
fi;

if (( L > 0 )); then
  warn "KeyBox is COMPROMISED" >> "$TXT";
elif (( J > 0 )); then
  warn "KeyBox is AOSP type" >> "$TXT";
else
  print "KeyBox is not compromised" >> "$TXT";
fi;
echo "" >> "$TXT";

# Print results
cat "$TXT" | grep -v 'KeyBox file:';

# Remove temporary files
rm -f "$TMP";
rm -f "$P7B";
rm -f "$CER";
rm -f "$JSON";
#rm -f "$TXT";

# Finish debug logging
if [ -n "$LogFile" ]; then
  set +x;
  exec 1>&3 2>&4 3>&- 4>&-;
fi;
