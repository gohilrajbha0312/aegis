#!/usr/bin/env python3
"""
wordlist_cleaner.py - Clean and validate password wordlists.

Features:
  - Remove empty lines
  - Remove lines with HTML/XML tags
  - Remove lines with non-printable/control characters
  - Filter by min/max length
  - Remove duplicates (sort + unique)
  - UTF-8 encoding normalization
  - Strip whitespace (leading/trailing)
  - Statistics report

Usage:
  python3 tools/clean.py -i input.txt -o output.txt
  python3 tools/clean.py -i input.txt -o output.txt --min-len 1 --max-len 64
  python3 tools/clean.py -i input.txt -o output.txt --allow-empty  # preserve empty lines
  python3 tools/clean.py -i input.txt -o output.txt --encoding latin-1  # specify input encoding
"""

import argparse
import sys
import os
import codecs


def is_valid_line(line, args):
    """Check if a line is valid according to rules."""
    # Skip empty lines unless --allow-empty
    if not line.strip() and not args.allow_empty:
        return False

    # Skip comment lines (starting with #)
    if line.strip().startswith('#'):
        return False

    # Skip lines with HTML/XML tags
    stripped = line.strip()
    if '<' in stripped and '>' in stripped:
        return False

    # Check for control characters (allow tab, newline, space)
    if args.no_control:
        for ch in stripped:
            if ord(ch) < 32 and ch not in ('\t', '\n', '\r'):
                return False
            if ord(ch) == 127:
                return False

    # Length check (on stripped content)
    content = stripped
    if len(content) < args.min_len:
        return False
    if args.max_len > 0 and len(content) > args.max_len:
        return False

    return True


def clean_wordlist(input_path, output_path, args):
    """Clean a wordlist file."""
    # Determine input encoding
    if args.encoding:
        encodings = [args.encoding]
    else:
        encodings = ['utf-8', 'latin-1', 'cp1252', 'gbk', 'gb2312', 'gb18030']

    # Try to read with different encodings
    lines = None
    for enc in encodings:
        try:
            with open(input_path, 'r', encoding=enc, errors='replace') as f:
                raw_lines = f.readlines()
            # Verify no mojibake by re-encoding
            lines = []
            for line in raw_lines:
                cleaned = line.strip()
                if cleaned:
                    try:
                        cleaned.encode('utf-8')
                        lines.append(line)
                    except UnicodeEncodeError:
                        continue
                elif args.allow_empty:
                    lines.append(line)
            break
        except (UnicodeDecodeError, LookupError):
            continue

    if lines is None:
        print(f"Error: Could not decode {input_path} with any supported encoding.", file=sys.stderr)
        return False

    # Filter valid lines and strip whitespace
    valid_lines = []
    for line in lines:
        stripped = line.rstrip('\r\n')
        stripped_clean = stripped.strip()
        if is_valid_line(stripped_clean + '\n', args):
            valid_lines.append(stripped_clean)

    # Deduplicate
    seen = set()
    unique_lines = []
    dupes = 0
    for line in valid_lines:
        if line not in seen:
            seen.add(line)
            unique_lines.append(line)
        else:
            dupes += 1

    # Write output
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        for line in unique_lines:
            f.write(line + '\n')

    # Report
    print(f"Input:  {input_path} ({len(lines)} lines)")
    print(f"Output: {output_path} ({len(unique_lines)} lines)")
    print(f"Removed: {len(lines) - len(unique_lines)} lines (duplicates: {dupes})")

    return True


def main():
    parser = argparse.ArgumentParser(
        description='Clean and validate password wordlists.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i dirty.txt -o clean.txt
  %(prog)s -i dirty.txt -o clean.txt --min-len 4 --max-len 32
  %(prog)s -i dirty.txt -o clean.txt --encoding latin-1 --no-control
        """
    )
    parser.add_argument('-i', '--input', required=True, help='Input wordlist file')
    parser.add_argument('-o', '--output', required=True, help='Output cleaned file')
    parser.add_argument('--min-len', type=int, default=1, help='Minimum password length (default: 1)')
    parser.add_argument('--max-len', type=int, default=0, help='Maximum password length (0=no limit, default: 0)')
    parser.add_argument('--encoding', help='Force input encoding (auto-detect by default)')
    parser.add_argument('--allow-empty', action='store_true', help='Preserve empty lines')
    parser.add_argument('--no-control', action='store_true', help='Remove lines with control characters')
    parser.add_argument('--dry-run', action='store_true', help='Show stats without writing output')

    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: Input file '{args.input}' not found.", file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        encodings = [args.encoding] if args.encoding else ['utf-8', 'latin-1']
        lines = []
        for enc in encodings:
            try:
                with open(args.input, 'r', encoding=enc, errors='replace') as f:
                    lines = f.readlines()
                break
            except (UnicodeDecodeError, LookupError):
                continue

        valid = sum(1 for l in lines if is_valid_line(l.strip() + '\n', args))
        unique = len(set(l.strip() for l in lines if is_valid_line(l.strip() + '\n', args)))
        print(f"Total: {len(lines)}, Valid: {valid}, Unique: {unique}")
        sys.exit(0)

    success = clean_wordlist(args.input, args.output, args)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
