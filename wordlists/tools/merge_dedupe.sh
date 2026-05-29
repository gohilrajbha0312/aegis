#!/bin/bash
# merge_dedupe.sh - Merge multiple wordlists and deduplicate
#
# Usage:
#   bash tools/merge_dedupe.sh -o output.txt file1.txt file2.txt ...
#   bash tools/merge_dedupe.sh -o output.txt passwords/*.txt
#   bash tools/merge_dedupe.sh -o output.txt --min-len 4 --max-len 32 passwords/*.txt
#
# Features:
#   - Merge multiple wordlists into one
#   - Remove duplicates
#   - Remove empty lines
#   - Remove comment lines (starting with #)
#   - Filter by min/max line length
#   - Sort output alphabetically
#   - Show statistics

set -euo pipefail

# Defaults
OUTPUT=""
MIN_LEN=1
MAX_LEN=0
NO_CONTROL=false
SHOW_STATS=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    cat <<EOF
Usage: bash tools/merge_dedupe.sh [OPTIONS] -o OUTPUT INPUT...

Options:
  -o, --output FILE      Output file (required)
  --min-len N            Minimum password length (default: 1)
  --max-len N            Maximum password length (0=no limit, default: 0)
  --no-control           Remove lines with control characters
  --quiet                Suppress progress output
  -h, --help             Show this help

Examples:
  bash tools/merge_dedupe.sh -o merged.txt passwords/ssh.txt passwords/web.txt
  bash tools/merge_dedupe.sh -o merged.txt --min-len 4 passwords/*.txt
EOF
    exit 0
}

# Parse arguments
INPUT_FILES=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        --min-len)
            MIN_LEN="$2"
            shift 2
            ;;
        --max-len)
            MAX_LEN="$2"
            shift 2
            ;;
        --no-control)
            NO_CONTROL=true
            shift
            ;;
        --quiet)
            SHOW_STATS=false
            shift
            ;;
        -h|--help)
            usage
            ;;
        -*)
            echo -e "${RED}Error: Unknown option $1${NC}" >&2
            exit 1
            ;;
        *)
            INPUT_FILES+=("$1")
            shift
            ;;
    esac
done

# Validate
if [ -z "$OUTPUT" ]; then
    echo -e "${RED}Error: --output is required${NC}" >&2
    exit 1
fi

if [ ${#INPUT_FILES[@]} -eq 0 ]; then
    echo -e "${RED}Error: No input files specified${NC}" >&2
    exit 1
fi

# Check all input files exist
for f in "${INPUT_FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo -e "${RED}Error: Input file '$f' not found${NC}" >&2
        exit 1
    fi
done

# Create temp file
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

# Build awk filter for min/max length and control chars
AWK_FILTER='{
    # Skip empty lines
    if (NF == 0) next;
    # Skip comment lines
    if ($0 ~ /^[[:space:]]*#/) next;
    # Strip leading/trailing whitespace
    val = $0;
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", val);
    # Min length check
    if (length(val) < '"$MIN_LEN"') next;
'
if [ "$MAX_LEN" -gt 0 ]; then
    AWK_FILTER="$AWK_FILTER"'    # Max length check
    if (length(val) > '"$MAX_LEN"') next;'
fi
if [ "$NO_CONTROL" = true ]; then
    AWK_FILTER="$AWK_FILTER"'    # Skip control characters (allow space)
    if (val ~ /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/) next;'
fi
AWK_FILTER="$AWK_FILTER"'    print val;
}'

# Process
TOTAL_LINES=0
for f in "${INPUT_FILES[@]}"; do
    COUNT=$(wc -l < "$f" | tr -d ' ')
    TOTAL_LINES=$((TOTAL_LINES + COUNT))
    if [ "$SHOW_STATS" = true ]; then
        echo -e "  ${YELLOW}+${NC} $f ($COUNT lines)"
    fi
done

# Cat all files, filter with awk, sort, and unique
cat "${INPUT_FILES[@]}" | awk "$AWK_FILTER" | LC_ALL=C sort -u > "$TMPFILE"
UNIQUE_COUNT=$(wc -l < "$TMPFILE" | tr -d ' ')

# Create output directory if needed
OUTDIR=$(dirname "$OUTPUT")
if [ -n "$OUTDIR" ] && [ "$OUTDIR" != "." ]; then
    mkdir -p "$OUTDIR"
fi

# Move temp to output
mv "$TMPFILE" "$OUTPUT"

if [ "$SHOW_STATS" = true ]; then
    echo ""
    echo -e "${GREEN}Done!${NC}"
    echo "  Input files:    ${#INPUT_FILES[@]}"
    echo "  Total lines:    $TOTAL_LINES"
    echo "  Unique output:  $UNIQUE_COUNT"
    echo "  Duplicates:     $((TOTAL_LINES - UNIQUE_COUNT))"
    echo "  Output:         $OUTPUT"
fi
