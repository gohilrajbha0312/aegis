#!/usr/bin/env python3
"""
wordlist_mangler.py - Generate password variants from a base wordlist.

Applies common password mutation rules:
  - Case variations (upper, lower, capitalize, swap, toggle)
  - Leet speak substitutions (a->@, e->3, i->1, o->0, s->$, t->7)
  - Append/prepend numbers (0-9999)
  - Append/prepend special characters (!@#$%^&* etc.)
  - Append years (2000-2030)
  - Append keyboard patterns (123, 1234, !@#, etc.)
  - Combine multiple rules
  - Reverse passwords

Usage:
  python3 tools/mangler.py -i passwords.txt -o output.txt
  python3 tools/mangler.py -i passwords.txt -o output.txt --rules case,leet,numbers
  python3 tools/mangler.py -i passwords.txt -o output.txt --max-len 20 --limit 100000
"""

import argparse
import sys
import os


# Leet speak substitution map
LEET_MAP = {
    'a': ['@', '4'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['$', '5'],
    't': ['7'],
    'l': ['1'],
    'b': ['8'],
    'g': ['9'],
}

# Common suffixes to append
NUMBER_SUFFIXES = [str(i) for i in range(100)] + [str(i) for i in range(2000, 2031)]
SPECIAL_SUFFIXES = ['!', '@', '#', '$', '!!', '!@#', '!@#$', '!1', '123', '1234', '!@',
                    '!@#', '123!', '!123', '!@#$', '000', '007', '666', '888', '520',
                    '1314', '521', '111', '321', '321321', '123123']
YEAR_SUFFIXES = [str(y) for y in range(2000, 2031)]
PREFIXES = ['!', '@', '#', '$', '1', '123', 'my', 'my_', 'the', 'The', 'THE', 'i', 'I']


def apply_case_variants(word):
    """Generate case variations."""
    variants = set()
    variants.add(word.lower())
    variants.add(word.upper())
    variants.add(word.capitalize())
    variants.add(word.swapcase())
    # Toggle case: alternate upper/lower
    toggled = ''
    for i, c in enumerate(word):
        toggled += c.upper() if i % 2 == 0 else c.lower()
    variants.add(toggled)
    return variants


def apply_leet_speak(word):
    """Generate leet speak variants."""
    variants = set()
    # Apply each substitution individually (single substitution)
    lower_word = word.lower()
    for i, ch in enumerate(lower_word):
        if ch in LEET_MAP:
            for replacement in LEET_MAP[ch]:
                variant = lower_word[:i] + replacement + lower_word[i+1:]
                variants.add(variant)

    # Apply all substitutions at once
    full_leet = lower_word
    for i, ch in enumerate(full_leet):
        if ch in LEET_MAP:
            full_leet = full_leet[:i] + LEET_MAP[ch][0] + full_leet[i+1:]
    variants.add(full_leet)

    return variants


def apply_number_suffix(word):
    """Append common numbers."""
    variants = set()
    for suffix in NUMBER_SUFFIXES:
        variants.add(word + suffix)
    return variants


def apply_special_suffix(word):
    """Append special character patterns."""
    variants = set()
    for suffix in SPECIAL_SUFFIXES:
        variants.add(word + suffix)
    return variants


def apply_year_suffix(word):
    """Append year suffixes."""
    variants = set()
    for suffix in YEAR_SUFFIXES:
        variants.add(word + suffix)
    return variants


def apply_reverse(word):
    """Reverse the password."""
    return {word[::-1]}


def apply_prefix(word):
    """Prepend common prefixes."""
    variants = set()
    for prefix in PREFIXES:
        variants.add(prefix + word)
    return variants


def mangle(input_path, output_path, args):
    """Read input, apply rules, write output."""
    # Read input
    with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
        base_words = set(line.strip() for line in f if line.strip() and not line.startswith('#'))

    print(f"Base words: {len(base_words)}")

    # Apply rules
    all_variants = set(base_words)  # Always include original

    rule_map = {
        'case': apply_case_variants,
        'leet': apply_leet_speak,
        'numbers': apply_number_suffix,
        'special': apply_special_suffix,
        'years': apply_year_suffix,
        'reverse': apply_reverse,
        'prefix': apply_prefix,
    }

    active_rules = [r.strip() for r in args.rules.split(',')]

    for rule_name in active_rules:
        if rule_name not in rule_map:
            print(f"Warning: Unknown rule '{rule_name}', skipping.", file=sys.stderr)
            continue
        func = rule_map[rule_name]
        new_variants = set()
        for word in base_words:
            new_variants.update(func(word))
        added = len(new_variants - all_variants)
        all_variants.update(new_variants)
        print(f"  Rule '{rule_name}': +{added} variants")

    # Filter by max length
    if args.max_len > 0:
        before = len(all_variants)
        all_variants = {v for v in all_variants if 0 < len(v) <= args.max_len}
        print(f"  Max length filter ({args.max_len}): {before} -> {len(all_variants)}")

    # Sort output
    sorted_variants = sorted(all_variants)

    # Apply limit
    if args.limit > 0 and len(sorted_variants) > args.limit:
        sorted_variants = sorted_variants[:args.limit]
        print(f"  Limited to {args.limit} entries")

    # Write output
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        for variant in sorted_variants:
            f.write(variant + '\n')

    print(f"Output: {output_path} ({len(sorted_variants)} entries)")
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Generate password variants from a base wordlist.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available rules:
  case     - Case variations (upper, lower, capitalize, swap, toggle)
  leet     - Leet speak substitutions (a->@, e->3, i->1, o->0, s->$, t->7)
  numbers  - Append numbers (0-99, 2000-2030)
  special  - Append special chars (!, @, #, 123, etc.)
  years    - Append years (2000-2030)
  reverse  - Reverse the password
  prefix   - Prepend common prefixes (!, @, 123, my, the, etc.)

Examples:
  %(prog)s -i common.txt -o mangled.txt --rules case,leet,numbers
  %(prog)s -i common.txt -o mangled.txt --rules all --max-len 16 --limit 500000
        """
    )
    parser.add_argument('-i', '--input', required=True, help='Input wordlist file')
    parser.add_argument('-o', '--output', required=True, help='Output file')
    parser.add_argument('--rules', default='case,leet,numbers,special',
                        help='Comma-separated rules to apply (or "all"). Default: case,leet,numbers,special')
    parser.add_argument('--max-len', type=int, default=0, help='Maximum output password length (0=no limit)')
    parser.add_argument('--limit', type=int, default=0, help='Limit output entries (0=no limit)')

    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: Input file '{args.input}' not found.", file=sys.stderr)
        sys.exit(1)

    # Expand 'all' rules
    if args.rules.strip().lower() == 'all':
        args.rules = 'case,leet,numbers,special,years,reverse,prefix'

    success = mangle(args.input, args.output, args)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
