#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

usage() {
    echo "Usage: $0 -u <domain> | -l <domain_list>"
    echo "Examples:"
    echo "  $0 -u example.com"
    echo "  $0 -l domains.txt"
    echo "  $0 -l domains.txt -o custom_output_dir"
    echo ""
    echo "Options:"
    echo "  -u Single domain to enumerate"
    echo "  -l File containing list of domains (one per line)"
    echo "  -o Custom output directory name (optional)"
    echo "  -t Threads for httpx (default: 50)"
    exit 1
}

print_status() { echo -e "${GREEN}[+]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }
print_info() { echo -e "${YELLOW}[*]${NC} $1"; }
print_domain() { echo -e "${CYAN}[>]${NC} $1"; }

# Strip protocol and trailing slashes from input
sanitize_domain() {
    echo "$1" | sed -E 's|^https?://||; s|/.*$||; s|:.*$||'
}

# Enumerate single domain - outputs to stdout for flexibility
enumerate_domain() {
    local domain=$(sanitize_domain "$1")
    local temp_dir="$2"
    print_domain "Enumerating: $domain"
    
    # Subfinder
    subfinder -d "$domain" -silent > "$temp_dir/${domain}_subfinder.txt" 2>/dev/null
    
    # crt.sh with timeout and error handling
    curl -s --max-time 30 "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | \
        sed 's/\*\.//g' | \
        sort -u > "$temp_dir/${domain}_crtsh.txt" 2>/dev/null
    
    # Combine for this domain
    cat "$temp_dir/${domain}_subfinder.txt" "$temp_dir/${domain}_crtsh.txt" 2>/dev/null | sort -u
}

# Default values
THREADS=50
OUTPUT_DIR=""

# Parse arguments
while getopts "u:l:o:t:" opt; do
    case $opt in
        u) DOMAIN="$OPTARG" ;;
        l) DOMAIN_LIST="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        *) usage ;;
    esac
done

# Validate input
if [ -z "$DOMAIN" ] && [ -z "$DOMAIN_LIST" ]; then
    print_error "Must specify either -u <domain> or -l <domain_list>"
    usage
fi
if [ -n "$DOMAIN" ] && [ -n "$DOMAIN_LIST" ]; then
    print_error "Cannot use both -u and -l together"
    usage
fi
if [ -n "$DOMAIN_LIST" ] && [ ! -f "$DOMAIN_LIST" ]; then
    print_error "Domain list file not found: $DOMAIN_LIST"
    exit 1
fi

# Check dependencies
for tool in subfinder httpx curl jq; do
    command -v "$tool" >/dev/null 2>&1 || { print_error "$tool is not installed. Aborting."; exit 1; }
done

# Banner
cat << "EOF"
                ___====-_  _-====___
         _--^^^#####//      \\#####^^^--_
      _-^###$######// (    ) \\#####$####^-_
     -############//  |\^^/|  \\############-
   _/#######$####//   (@::@)   \\###$########\_
  /#############((     \\//     ))#############\
  -##############\\    (oo)    //##########$####-
   -###$##########\\  / VV \  //###############-
    -##############\\/      \//#####$#########-
     _-#######$#####\\ ____ //##############-_
       -#############\\____//##########$###-
           --#$########====#####$####--

 passive subdomain enumeration w/ subfinder • crt.sh • httpx
 mashed together for ease of use by 9mmPterodactyl
EOF

# Setup output directory
if [ -n "$DOMAIN" ]; then
    TARGET_NAME="$DOMAIN"
else
    TARGET_NAME=$(basename "$DOMAIN_LIST" .txt)
fi
if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="recon_${TARGET_NAME}_$(date +%m%d%Y)"
fi
mkdir -p "$OUTPUT_DIR"
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT
print_info "Output directory: $OUTPUT_DIR"
echo ""

# Build domain list (sanitize all inputs)
if [ -n "$DOMAIN" ]; then
    sanitize_domain "$DOMAIN" > "$TEMP_DIR/targets.txt"
    DOMAIN_COUNT=1
else
    # Clean the input file - remove empty lines, whitespace, comments, and sanitize
    grep -v '^#' "$DOMAIN_LIST" | grep -v '^\s*$' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
        while read -r d; do sanitize_domain "$d"; done > "$TEMP_DIR/targets.txt"
    DOMAIN_COUNT=$(wc -l < "$TEMP_DIR/targets.txt")
fi

# Also sanitize TARGET_NAME for output directory
TARGET_NAME=$(sanitize_domain "$TARGET_NAME")
print_info "Targets: $DOMAIN_COUNT domain(s)"
echo ""

# Enumerate all domains
print_status "Running subdomain enumeration..."
> "$OUTPUT_DIR/all_subdomains.txt"
while IFS= read -r domain; do
    [ -z "$domain" ] && continue
    enumerate_domain "$domain" "$TEMP_DIR" >> "$OUTPUT_DIR/all_subdomains.txt"
done < "$TEMP_DIR/targets.txt"

# Deduplicate
sort -u "$OUTPUT_DIR/all_subdomains.txt" -o "$OUTPUT_DIR/all_subdomains.txt"
TOTAL_SUBS=$(wc -l < "$OUTPUT_DIR/all_subdomains.txt")
print_info "Total unique subdomains: $TOTAL_SUBS"
echo ""

# Live host detection
print_status "Checking for live hosts with httpx..."
httpx -l "$OUTPUT_DIR/all_subdomains.txt" -silent -threads "$THREADS" -o "$OUTPUT_DIR/live_hosts.txt"
LIVE_COUNT=$(wc -l < "$OUTPUT_DIR/live_hosts.txt" 2>/dev/null || echo 0)
print_info "Live hosts: $LIVE_COUNT"

# Detailed scan
print_status "Running detailed httpx scan..."
httpx -l "$OUTPUT_DIR/all_subdomains.txt" -silent -threads "$THREADS" \
    -title -status-code -tech-detect -content-length -web-server \
    -follow-redirects -o "$OUTPUT_DIR/live_hosts_detailed.txt"

# Per-domain breakdown (for multi-domain runs)
if [ "$DOMAIN_COUNT" -gt 1 ]; then
    print_status "Generating per-domain breakdown..."
    mkdir -p "$OUTPUT_DIR/by_domain"
    while IFS= read -r domain; do
        [ -z "$domain" ] && continue
        grep -E "(^|\.)?${domain}$" "$OUTPUT_DIR/all_subdomains.txt" > "$OUTPUT_DIR/by_domain/${domain}_subs.txt" 2>/dev/null
        grep -E "https?://[^/]*${domain}" "$OUTPUT_DIR/live_hosts.txt" > "$OUTPUT_DIR/by_domain/${domain}_live.txt" 2>/dev/null
    done < "$TEMP_DIR/targets.txt"
fi

# Summary
echo ""
print_status "Enumeration complete!"
echo "======================================"
echo "Targets scanned: $DOMAIN_COUNT"
echo "Unique subdomains: $TOTAL_SUBS"
echo "Live hosts: $LIVE_COUNT"
echo "======================================"
echo "Results saved in: $OUTPUT_DIR/"
echo " - all_subdomains.txt (combined unique list)"
echo " - live_hosts.txt (live URLs)"
echo " - live_hosts_detailed.txt (with titles, status, tech)"
[ "$DOMAIN_COUNT" -gt 1 ] && echo " - by_domain/ (per-domain breakdown)"
echo ""
