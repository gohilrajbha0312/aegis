#!/usr/bin/env python3
"""
wordlist_stats.py - Analyze and report statistics on wordlist files.

Usage:
  python3 tools/wordlist_stats.py passwords/ssh.txt
  python3 tools/wordlist_stats.py passwords/*.txt
  python3 tools/wordlist_stats.py --all
"""

import argparse
import sys
import os
import json


def analyze_file(filepath):
    """Analyze a single wordlist file and return stats."""
    stats = {
        'file': filepath,
        'size_bytes': os.path.getsize(filepath),
        'total_lines': 0,
        'empty_lines': 0,
        'comment_lines': 0,
        'unique_entries': 0,
        'duplicates': 0,
        'min_length': float('inf'),
        'max_length': 0,
        'avg_length': 0,
        'length_distribution': {},
        'has_encoding_issues': False,
    }

    lengths = []
    entries = set()
    seen = set()
    dupes = 0

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                stats['total_lines'] += 1
                stripped = line.strip()

                if not stripped:
                    stats['empty_lines'] += 1
                    continue

                if stripped.startswith('#'):
                    stats['comment_lines'] += 1
                    continue

                length = len(stripped)
                lengths.append(length)

                if length < stats['min_length']:
                    stats['min_length'] = length
                if length > stats['max_length']:
                    stats['max_length'] = length

                # Length distribution in buckets
                bucket = (length // 4) * 4  # 0-3, 4-7, 8-11, etc.
                bucket_label = f"{bucket}-{bucket+3}"
                stats['length_distribution'][bucket_label] = \
                    stats['length_distribution'].get(bucket_label, 0) + 1

                if stripped in seen:
                    dupes += 1
                else:
                    seen.add(stripped)
                    entries.add(stripped)

    except Exception as e:
        stats['error'] = str(e)
        return stats

    stats['unique_entries'] = len(entries)
    stats['duplicates'] = dupes

    if lengths:
        stats['min_length'] = min(lengths)
        stats['max_length'] = max(lengths)
        stats['avg_length'] = round(sum(lengths) / len(lengths), 1)
    else:
        stats['min_length'] = 0
        stats['avg_length'] = 0

    # Format size
    size = stats['size_bytes']
    if size < 1024:
        stats['size_human'] = f"{size} B"
    elif size < 1024 * 1024:
        stats['size_human'] = f"{size / 1024:.1f} KB"
    else:
        stats['size_human'] = f"{size / (1024 * 1024):.1f} MB"

    return stats


def print_stats(stats):
    """Print stats for a file in a readable format."""
    print(f"\n{'='*60}")
    print(f"  {stats['file']}")
    print(f"{'='*60}")
    print(f"  Size:           {stats['size_human']} ({stats['size_bytes']:,} bytes)")
    print(f"  Total lines:    {stats['total_lines']:,}")
    print(f"  Empty lines:    {stats['empty_lines']:,}")
    print(f"  Comment lines:  {stats['comment_lines']:,}")
    print(f"  Unique entries: {stats['unique_entries']:,}")
    print(f"  Duplicates:     {stats['duplicates']:,}")
    print(f"  Min length:     {stats['min_length']}")
    print(f"  Max length:     {stats['max_length']}")
    print(f"  Avg length:     {stats['avg_length']}")
    print(f"  Length dist:")
    for bucket, count in sorted(stats['length_distribution'].items()):
        bar = '#' * min(count // max(1, stats['unique_entries'] // 40), 50)
        print(f"    {bucket:>8s}: {count:>8,}  {bar}")
    if 'error' in stats:
        print(f"  Error: {stats['error']}")


def main():
    parser = argparse.ArgumentParser(description='Analyze wordlist statistics.')
    parser.add_argument('files', nargs='*', help='Wordlist files to analyze')
    parser.add_argument('--all', action='store_true', help='Analyze all .txt files in passwords/ and usernames/')
    parser.add_argument('--json', action='store_true', help='Output as JSON')

    args = parser.parse_args()

    files = args.files or []

    if args.all:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for subdir in ['passwords', 'usernames', 'leaked']:
            dir_path = os.path.join(base_dir, subdir)
            if os.path.isdir(dir_path):
                for f in sorted(os.listdir(dir_path)):
                    if f.endswith('.txt'):
                        files.append(os.path.join(dir_path, f))

    if not files:
        parser.print_help()
        sys.exit(1)

    all_stats = []
    for filepath in files:
        if not os.path.isfile(filepath):
            print(f"Warning: {filepath} not found, skipping.", file=sys.stderr)
            continue
        stats = analyze_file(filepath)
        all_stats.append(stats)
        if not args.json:
            print_stats(stats)

    if args.json:
        print(json.dumps(all_stats, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
