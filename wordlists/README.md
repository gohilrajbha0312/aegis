# Wordlist Collection

A curated collection of password wordlists, username lists, and default credentials for **authorized security testing and penetration testing**.

> ⚠️ **Legal Disclaimer**: These wordlists are provided strictly for security research, authorized penetration testing, and educational purposes. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing any system.

## 📁 Directory Structure

```
wordlist/
├── README.md
├── LICENSE
├── .gitignore
│
├── passwords/              # Password wordlists (one password per line)
│   ├── common.txt           # General weak passwords (1.3M+ entries)
│   ├── common_small.txt     # Top 1000+ most common weak passwords
│   ├── web.txt              # Web application common passwords (450+)
│   ├── ssh.txt              # SSH brute force passwords (79K+)
│   ├── rdp.txt              # RDP common passwords (209K+)
│   ├── ftp.txt              # FTP default/common passwords (410+)
│   ├── databases.txt        # Database default passwords (430+)
│   ├── iot.txt              # IoT/smart home/industrial default passwords (430+)
│   └── chinese_weak.txt     # Chinese-context weak passwords (530+)
│
├── usernames/               # Username lists
│   ├── common.txt           # General username list (82K+ entries)
│   └── admin.txt            # Admin/common service account usernames (78)
│
├── defaults/                # Default credentials (structured JSON)
│   ├── ip_cameras.json      # IP camera/NVR default credentials
│   ├── databases.json       # Database default credentials with ports
│   ├── nas.json             # NAS device default credentials
│   └── iot.json             # IoT/router/networking default credentials
│
├── leaked/                  # Passwords from public data breaches
│   ├── adobe_top100.txt     # Top 100 from Adobe 2013 breach
│   └── README.md            # Data source descriptions
│
└── tools/                   # Utility scripts
    ├── clean.py             # Wordlist cleaner (remove junk, dedupe, normalize)
    ├── mangler.py           # Password variant generator (leet, case, suffixes)
    ├── generate_chinese.py  # Chinese weak password generator
    ├── merge_dedupe.sh      # Merge and deduplicate wordlists
    └── wordlist_stats.py    # Analyze and report wordlist statistics
```

## 🔧 Tools

### clean.py - Wordlist Cleaner

Clean and validate password wordlists by removing junk data.

```bash
# Basic cleaning
python3 tools/clean.py -i dirty.txt -o clean.txt

# With length filter and control character removal
python3 tools/clean.py -i dirty.txt -o clean.txt --min-len 4 --max-len 64 --no-control

# Specify encoding
python3 tools/clean.py -i dirty.txt -o clean.txt --encoding latin-1

# Dry run (stats only)
python3 tools/clean.py -i dirty.txt -o /dev/null --dry-run
```

### mangler.py - Password Variant Generator

Generate password variants from a base wordlist.

```bash
# Apply case + leet speak rules
python3 tools/mangler.py -i passwords/common_small.txt -o mangled.txt --rules case,leet

# Apply all rules with length limit
python3 tools/mangler.py -i passwords/common_small.txt -o mangled.txt --rules all --max-len 16

# Limit output size
python3 tools/mangler.py -i passwords/common_small.txt -o mangled.txt --rules all --limit 100000
```

Available rules: `case`, `leet`, `numbers`, `special`, `years`, `reverse`, `prefix`, `all`

### generate_chinese.py - Chinese Password Generator

Generate Chinese-context weak passwords (pinyin, lucky numbers, names).

```bash
# Generate to default path
python3 tools/generate_chinese.py -o passwords/chinese_weak_generated.txt

# Limit output size
python3 tools/generate_chinese.py -o passwords/chinese_weak_generated.txt --limit 50000
```

### merge_dedupe.sh - Merge & Deduplicate

Merge multiple wordlists into one sorted, deduplicated file.

```bash
# Merge multiple files
bash tools/merge_dedupe.sh -o merged.txt passwords/ssh.txt passwords/web.txt

# With length filter
bash tools/merge_dedupe.sh -o merged.txt --min-len 6 --max-len 32 passwords/*.txt
```

### wordlist_stats.py - Wordlist Analyzer

Analyze wordlist files and show statistics.

```bash
# Analyze specific files
python3 tools/wordlist_stats.py passwords/ssh.txt passwords/web.txt

# Analyze all wordlists
python3 tools/wordlist_stats.py --all

# JSON output
python3 tools/wordlist_stats.py passwords/*.txt --json
```

## 📊 Wordlist Statistics

| File | Entries | Description |
|------|---------|-------------|
| passwords/common.txt | 1,310,522 | General weak passwords (comprehensive) |
| passwords/common_small.txt | 1,316 | Top 1000+ most common |
| passwords/ssh.txt | 79215 | SSH brute force passwords |
| passwords/rdp.txt | 209,335 | RDP common passwords |
| passwords/web.txt | 453 | Web application passwords |
| passwords/ftp.txt | 413 | FTP default/common passwords |
| passwords/databases.txt | 429 | Database default passwords |
| passwords/iot.txt | 426 | IoT/smart device passwords |
| passwords/chinese_weak.txt | 530 | Chinese-context weak passwords |
| usernames/common.txt | 82,484 | General usernames |
| usernames/admin.txt | 78 | Admin account names |
| leaked/adobe_top100.txt | 100 | Adobe 2013 breach top 100 |

## 🔄 Workflow

### Quick Start
```bash
# 1. Use a pre-built wordlist directly
hydra -l admin -P passwords/web.txt target http-post-form "/login:user=^USER^&pass=^PASS^"

# 2. Generate custom variants
python3 tools/mangler.py -i passwords/common_small.txt -o my_custom.txt --rules case,leet,numbers

# 3. Merge multiple sources
bash tools/merge_dedupe.sh -o custom.txt --min-len 4 passwords/web.txt passwords/ftp.txt passwords/databases.txt

# 4. Check stats
python3 tools/wordlist_stats.py custom.txt
```

### Adding New Wordlists
1. Place new `.txt` files in the appropriate directory (`passwords/`, `usernames/`)
2. Run `python3 tools/clean.py -i new_file.txt -o new_file.txt` to normalize
3. Update this README with the new entry

## 📝 Data Sources

### Password Dictionaries
- **common.txt**: Curated from multiple public sources (rockyou derivatives), 1.3M+ entries
- **common_small.txt**: SecLists Pwdb_top-1000 + 2025-2026 breach data (NordPass, Cybernews, Specops)
- **web.txt**: SecLists Pwdb_top-1000 + Cybernews 2025/2026 common passwords + Paul Reynolds 2026 top 150 + lucidar.me top 299 + NordPass 2025 top 200
- **ssh.txt**: SecLists Pwdb_top-1000 + SecLists xato-net-10-million-usernames (common passwords) + default service credentials
- **rdp.txt**: RDP-specific weak passwords from original repository
- **ftp.txt**: SecLists Pwdb_top-1000 + FTP-specific default credentials
- **databases.txt**: SecLists Pwdb_top-1000 + official default credentials (MySQL, PostgreSQL, Redis, MongoDB, MSSQL, Oracle, Elasticsearch)
- **iot.txt**: SecLists Pwdb_top-1000 + SecLists default-passwords.csv + public device databases
- **chinese_weak.txt**: SecLists Pwdb_top-1000 + generated Chinese weak passwords (pinyin patterns, lucky numbers, common surnames, brand passwords, gaming passwords)

### Username Lists
- **common.txt**: Original names list + SecLists Usernames/Names/names.txt + SecLists xato-net-10-million-usernames (top 2700+ common usernames)
- **admin.txt**: Common admin/service account variants

### Default Credentials
- **routers.json**: SecLists Discovery/Web-Content/default-passwords.csv
- **ip_cameras.json**: SecLists + public IP camera databases
- **databases.json**: Official vendor documentation
- **nas.json**: SecLists + manufacturer defaults
- **iot.json**: SecLists + public IoT databases

### Leaked Passwords
- **adobe_top100.txt**: Top 100 from the Adobe 2013 data breach (130M accounts)

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Add new wordlists in the appropriate directory
3. Run `python3 tools/clean.py` to normalize your additions
4. Run `python3 tools/wordlist_stats.py --all` to verify quality
5. Update this README
6. Submit a pull request

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

## ⚖️ Responsible Use

This toolkit is designed for:
- ✅ Authorized penetration testing
- ✅ Security research and education
- ✅ Password policy auditing
- ✅ CTF competitions and training
- ❌ Unauthorized system access
- ❌ Any illegal activity
