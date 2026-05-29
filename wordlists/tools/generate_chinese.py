#!/usr/bin/env python3
"""
generate_chinese.py - Generate Chinese-context weak password wordlist.

Generates common Chinese weak password patterns:
  - Pinyin words with numeric suffixes
  - Lucky number patterns
  - Phone number patterns
  - ID card number patterns (partial)
  - Common Chinese names as pinyin
  - QQ number patterns

Usage:
  python3 tools/generate_chinese.py -o passwords/chinese_weak_generated.txt
  python3 tools/generate_chinese.py -o passwords/chinese_weak_generated.txt --count 50000
  python3 tools/generate_chinese.py -o passwords/chinese_weak_generated.txt --compact
"""

import argparse
import sys
import os
import random


# Common Chinese pinyin words used as passwords
PINGYIN_WORDS = [
    'woaini', 'nihao', 'woshishui', 'wode', 'mima', 'denglu', 'guanli',
    'fuwuqi', 'zhongguo', 'beijing', 'shanghai', 'shenzhen', 'tianqi',
    'jiaru', 'kaifang', 'wangluo', 'anquan', 'xuexiao', 'gongsi',
    'xiaoming', 'xiaohong', 'xiaoli', 'xiaowang', 'zhangsan', 'lisi',
    'wangwu', 'zhaoliu', 'qianqi', 'sunba', 'zhoujiu', 'wushi',
    'aimeinv', 'shuaige', 'haoren', 'huaidan', 'dashuai', 'daniu',
    'laopo', 'qinai', 'baobei', 'tianshi', 'gongzhu', 'wangzi',
    'longwang', 'tiger', 'miao', 'gou', 'zhu', 'niu', 'yang', 'ma',
    'ji', 'xiongmao', 'huli', 'shizi', 'laohu', 'daxiang', 'houzi',
]

# Chinese lucky numbers and patterns
LUCKY_NUMBERS = [
    '1314', '520', '521', '1314520', '5201314', '520520', '5211314',
    '7758521', '7758', '3344520', '1314521', '2099', '9958', '518',
    '168', '51888', '16888', '666888', '888666', '6688', '8866',
    '666', '888', '999', '168168', '518518', '5201314520',
    '123456789', '987654321', '147258369', '123321', '321321',
    '112233', 'aabbcc', 'abcabc', '121212', '123123', '12341234',
]

# Common numeric suffixes for pinyin passwords
NUM_SUFFIXES = [
    '1', '12', '123', '1234', '12345', '123456', '0', '00', '000',
    '1314', '520', '521', '666', '888', '999', '000', '111', '222',
    '2016', '2017', '2018', '2019', '2020', '2021', '2022', '2023',
    '2024', '2025', '2026', '11', '22', '33', '44', '55', '66', '77',
    '88', '99', '01', '02', '03', '04', '05', '06', '07', '08', '09',
]

# Common Chinese surnames as pinyin (top 50)
SURNAMES = [
    'wang', 'li', 'zhang', 'liu', 'chen', 'yang', 'huang', 'zhao',
    'wu', 'zhou', 'xu', 'sun', 'ma', 'zhu', 'hu', 'guo', 'he',
    'lin', 'luo', 'gao', 'zheng', 'liang', 'xie', 'song', 'tang',
    'han', 'feng', 'deng', 'cao', 'peng', 'zeng', 'xiao', 'tian',
    'dong', 'pan', 'yuan', 'cai', 'jiang', 'yu', 'yu', 'li',
]

# Common Chinese given names as pinyin
GIVEN_NAMES = [
    'wei', 'fang', 'na', 'min', 'jing', 'lei', 'jie', 'ying',
    'xin', 'hui', 'yan', 'bin', 'bo', 'tao', 'hua', 'jian',
    'ping', 'jun', 'ying', 'chao', 'ming', 'long', 'xiao', 'hao',
    'liang', 'yun', 'fei', 'chen', 'yang', 'wen', 'yu', 'lin',
    'zhi', 'qiang', 'guo', 'hua', 'hua', 'mei', 'lan', 'zhen',
]


def generate(args):
    """Generate Chinese-context weak passwords."""
    passwords = set()

    # 1. Pinyin words + numeric suffixes
    for word in PINGYIN_WORDS:
        passwords.add(word)
        passwords.add(word.upper())
        passwords.add(word.capitalize())
        for suffix in NUM_SUFFIXES:
            passwords.add(word + suffix)

    # 2. Lucky numbers
    passwords.update(LUCKY_NUMBERS)

    # 3. Common name patterns: surname + given_name + optional number
    for surname in SURNAMES:
        passwords.add(surname)
        for name in GIVEN_NAMES:
            full = surname + name
            passwords.add(full)
            for suffix in ['123', '123456', '520', '1314', '666', '888', '1', '01']:
                passwords.add(full + suffix)

    # 4. Platform-specific patterns
    platform_prefixes = ['qq', 'ww', 'pp', 'mm', 'dd', 'wx', 'wb', 'tb']
    for prefix in platform_prefixes:
        for suffix in NUM_SUFFIXES[:15]:
            passwords.add(prefix + suffix)

    # 5. Keyboard patterns
    keyboard_patterns = [
        'qwerty', 'qwer1234', 'asdfgh', 'zxcvbn', 'qazwsx', '1qaz2wsx',
        '1q2w3e4r', 'q1w2e3r4', 'qweasd', 'asdf1234', 'zxc123',
        'poiuytr', 'lkjhgf', 'mnbvcx',
    ]
    passwords.update(keyboard_patterns)

    # 6. Common word patterns
    common_patterns = [
        'password', 'admin', 'root', 'test', 'login', 'welcome',
        'hello', 'dragon', 'master', 'shadow', 'monkey', 'letmein',
        'football', 'baseball', 'soccer', 'hockey', 'batman', 'superman',
    ]
    for word in common_patterns:
        passwords.add(word)
        for suffix in ['666', '888', '123', '1234', '520', '1314', '!']:
            passwords.add(word + suffix)

    # Limit if requested
    if args.limit > 0:
        passwords = set(random.sample(list(passwords), min(args.limit, len(passwords))))

    # Sort and deduplicate
    sorted_passwords = sorted(passwords)

    # Write output
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        for pw in sorted_passwords:
            f.write(pw + '\n')

    print(f"Generated: {len(sorted_passwords)} passwords -> {args.output}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Generate Chinese-context weak password wordlist.'
    )
    parser.add_argument('-o', '--output', default='passwords/chinese_weak_generated.txt',
                        help='Output file path (default: passwords/chinese_weak_generated.txt)')
    parser.add_argument('--limit', type=int, default=0,
                        help='Limit output entries (0=unlimited, default: 0)')
    parser.add_argument('--seed', type=int, default=42,
                        help='Random seed for reproducible results (default: 42)')

    args = parser.parse_args()
    if args.seed >= 0:
        random.seed(args.seed)

    success = generate(args)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
