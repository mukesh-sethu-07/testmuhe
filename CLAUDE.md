# CLAUDE.md - AI Assistant Guide for testmuhe Repository

## Repository Overview

**Purpose**: Domain monitoring and tracking repository
**Type**: Data repository containing lists of domains for monitoring purposes
**Primary Language**: Plain text data files
**Last Updated**: 2025-11-14

---

## Repository Structure

```
testmuhe/
├── README.md           # Basic repository description
├── monitor_14.txt      # Primary domain list (24,543 entries)
└── CLAUDE.md          # This file - AI assistant documentation
```

### File Descriptions

#### `monitor_14.txt`
- **Purpose**: Master list of domains to monitor
- **Format**: Plain text, one domain per line
- **Total Entries**: 24,543 domains
- **Sorting**: Alphabetically sorted (case-sensitive)
- **Encoding**: UTF-8
- **Line Endings**: Unix-style (LF)
- **Size**: ~434 KB

The file contains domains from various TLDs including .com, .co.uk, .co.in, .org, .net, and many country-specific extensions.

---

## Data Format Conventions

### Domain List Format

1. **One domain per line**
   - No protocols (http://, https://)
   - No paths or query parameters
   - No trailing slashes
   - Format: `example.com` or `subdomain.example.com`

2. **Alphabetical Sorting**
   - Sorted case-sensitively
   - Numeric prefixes sorted before alphabetic
   - Example order: `010tel.com`, `01ingstar.co.nl`, `02iya777.org`

3. **No Empty Lines**
   - File may have one trailing newline at the end
   - No blank lines between entries

4. **Character Encoding**
   - UTF-8 encoding required
   - Support for international domain names (IDN)

### Example Entries
```
010tel.com
clinicasalbanoo.com
zoxclo.com
zzhengy.com.cn
```

---

## Development Workflows

### Adding New Domains

When adding new domains to the monitoring list:

1. **Validation Steps**
   ```bash
   # Verify domain format (no protocols, paths, or invalid characters)
   # Check for duplicates
   grep -F "newdomain.com" monitor_14.txt

   # Add domain and re-sort the file
   echo "newdomain.com" >> monitor_14.txt
   sort -u monitor_14.txt -o monitor_14.txt

   # Verify line count increased
   wc -l monitor_14.txt
   ```

2. **Batch Additions**
   ```bash
   # Add multiple domains from a file
   cat new_domains.txt >> monitor_14.txt
   sort -u monitor_14.txt -o monitor_14.txt
   ```

3. **Deduplication**
   ```bash
   # Remove duplicates while preserving order
   sort -u monitor_14.txt -o monitor_14.txt
   ```

### Removing Domains

```bash
# Remove a specific domain
grep -v "domain-to-remove.com" monitor_14.txt > temp.txt
mv temp.txt monitor_14.txt

# Remove multiple domains using a pattern
grep -v -E "(pattern1|pattern2)" monitor_14.txt > temp.txt
mv temp.txt monitor_14.txt
```

### Data Validation

```bash
# Check for empty lines
grep -n "^$" monitor_14.txt

# Verify all entries are valid domain format
grep -vE "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$" monitor_14.txt

# Check for duplicates
sort monitor_14.txt | uniq -d

# Verify sorting
sort -c monitor_14.txt 2>&1 | head
```

### Search and Analysis

```bash
# Search for specific TLD
grep "\.co\.uk$" monitor_14.txt | wc -l

# Find domains containing specific keywords
grep -i "clinic" monitor_14.txt

# Statistical analysis
# Count unique TLDs
awk -F. '{print $NF}' monitor_14.txt | sort | uniq -c | sort -rn

# Find shortest/longest domains
awk '{ print length, $0 }' monitor_14.txt | sort -n
```

---

## AI Assistant Guidelines

### When Working with Domain Lists

1. **Maintain Data Integrity**
   - Always preserve alphabetical sorting after modifications
   - Validate domain format before adding entries
   - Check for duplicates before committing
   - Preserve UTF-8 encoding

2. **Be Careful with Large Files**
   - `monitor_14.txt` has 24,543+ lines
   - Use `grep`, `awk`, `sed` for operations instead of loading entire file
   - When reading, use `offset` and `limit` parameters
   - Consider memory usage when processing

3. **Domain Validation**
   - Check for valid domain format (no protocols, paths, spaces)
   - Verify TLD is valid
   - Ensure no duplicate entries
   - Watch for typos or malformed entries

4. **Batch Operations**
   - For bulk operations, always create backups
   - Test operations on small samples first
   - Verify results before committing
   - Document significant changes in commit messages

### Common Tasks

#### Task: Add a new domain
```bash
# 1. Check if domain already exists
grep -F "example.com" monitor_14.txt

# 2. Add and sort
echo "example.com" >> monitor_14.txt
sort -u monitor_14.txt -o monitor_14.txt

# 3. Verify
grep -F "example.com" monitor_14.txt
```

#### Task: Analyze domain patterns
```bash
# Find all domains with numeric prefixes
grep "^[0-9]" monitor_14.txt

# Find all .co.uk domains
grep "\.co\.uk$" monitor_14.txt

# Count domains by TLD
awk -F. '{print $NF}' monitor_14.txt | sort | uniq -c | sort -rn | head -20
```

#### Task: Clean and validate
```bash
# Remove empty lines and sort
grep -v "^$" monitor_14.txt | sort -u -o monitor_14.txt

# Validate all entries are proper domains
grep -vE "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$" monitor_14.txt
```

---

## Git Workflows

### Branch Strategy

- **Main Branch**: Primary development branch (not set in this repo)
- **Feature Branches**: Named with `claude/` prefix for AI-assisted development
- **Current Branch**: `claude/claude-md-mhyh4lbt4c7jap75-01MNtYinCP5vND3sPgDssFaL`

### Commit Message Conventions

Use clear, descriptive commit messages:

```
Good examples:
- "Add 150 new domains to monitoring list"
- "Remove duplicate entries from monitor_14.txt"
- "Update monitoring list with Q4 2025 domains"
- "Fix: Remove invalid domain entries"

Bad examples:
- "Update file"
- "Changes"
- "Fix"
```

### Git Commands Reference

```bash
# Check current status
git status

# Stage changes
git add monitor_14.txt

# Commit with descriptive message
git commit -m "Add new domains from security feed"

# Push to remote (with retry logic for network issues)
git push -u origin claude/claude-md-mhyh4lbt4c7jap75-01MNtYinCP5vND3sPgDssFaL
```

---

## Data Quality Standards

### Before Committing Changes

1. **Validate Format**
   - All entries are valid domain names
   - No protocols (http://, https://)
   - No paths or query strings
   - No whitespace or special characters (except hyphens and dots)

2. **Check Sorting**
   ```bash
   sort -c monitor_14.txt
   # If not sorted, run:
   sort -u monitor_14.txt -o monitor_14.txt
   ```

3. **Remove Duplicates**
   ```bash
   # Check for duplicates
   sort monitor_14.txt | uniq -d

   # Remove if found
   sort -u monitor_14.txt -o monitor_14.txt
   ```

4. **Verify Line Endings**
   ```bash
   # Check line endings (should be LF only)
   file monitor_14.txt

   # Convert if needed
   dos2unix monitor_14.txt  # or
   sed -i 's/\r$//' monitor_14.txt
   ```

---

## Performance Considerations

### Working with Large Files

1. **Reading**
   - Use `Read` tool with `offset` and `limit` for large files
   - Use `grep` or `awk` for searching instead of loading entire file
   - Sample reading: read first 100, middle section, last 100 lines

2. **Processing**
   - Stream processing preferred over loading into memory
   - Use Unix tools (grep, sed, awk) for filtering
   - Process in chunks for very large operations

3. **Analysis**
   ```bash
   # Fast statistics
   wc -l monitor_14.txt                    # Line count
   head -n 100 monitor_14.txt              # First 100
   tail -n 100 monitor_14.txt              # Last 100
   grep -c "pattern" monitor_14.txt        # Count matches
   ```

---

## Common Patterns and Use Cases

### Pattern: Finding Suspicious Domains

```bash
# Domains with multiple hyphens (often suspicious)
grep -E ".*-.*-.*-" monitor_14.txt

# Very short domains (3 chars or less before TLD)
awk -F. 'length($1) <= 3' monitor_14.txt

# Domains with numbers and letters mixed
grep -E "^[0-9]+[a-z]|[a-z]+[0-9]" monitor_14.txt
```

### Pattern: TLD Analysis

```bash
# Count by country TLD
grep -E "\.(co\.uk|co\.in|co\.nz|co\.za|co\.ke|co\.jp)$" monitor_14.txt | \
  sed 's/.*\.\(.*\)$/\1/' | sort | uniq -c

# Generic TLDs
grep -E "\.(com|net|org|info|biz)$" monitor_14.txt | wc -l

# New TLDs (.shop, .online, .site, etc.)
grep -E "\.(shop|online|site|store|app|link|click)$" monitor_14.txt
```

### Pattern: Bulk Updates

```bash
# Add domains from external source
curl -s https://example.com/domains.txt | \
  grep -v "^#" | \
  grep -v "^$" >> monitor_14.txt

# Clean and deduplicate
sort -u monitor_14.txt -o monitor_14.txt

# Verify
wc -l monitor_14.txt
```

---

## Security and Privacy Notes

1. **Data Sensitivity**
   - This list contains domain names that may be monitored for security purposes
   - Treat the data as potentially sensitive
   - Do not share or expose the list without authorization

2. **Domain Privacy**
   - Domain names are public information
   - The list itself may indicate monitoring priorities
   - Be mindful when discussing specific entries

3. **Validation**
   - Always validate domains before adding
   - Check for typosquatting or lookalike domains
   - Document the source of bulk additions

---

## Troubleshooting

### Issue: File Not Sorted

```bash
# Solution: Re-sort the file
sort -u monitor_14.txt -o monitor_14.txt
git add monitor_14.txt
git commit -m "Fix: Re-sort domain list alphabetically"
```

### Issue: Duplicate Entries

```bash
# Find duplicates
sort monitor_14.txt | uniq -d

# Remove duplicates
sort -u monitor_14.txt -o monitor_14.txt
```

### Issue: Invalid Domain Format

```bash
# Find potentially invalid entries (with spaces, protocols, etc.)
grep -E "(https?://|[[:space:]]|/)" monitor_14.txt

# Find entries with invalid characters
grep -vE "^[a-zA-Z0-9.-]+$" monitor_14.txt
```

### Issue: Encoding Problems

```bash
# Check file encoding
file -i monitor_14.txt

# Convert to UTF-8 if needed
iconv -f ISO-8859-1 -t UTF-8 monitor_14.txt > monitor_14_utf8.txt
mv monitor_14_utf8.txt monitor_14.txt
```

---

## Quick Reference

### Essential Commands

```bash
# Count domains
wc -l monitor_14.txt

# Search for domain
grep "example.com" monitor_14.txt

# Add domain
echo "newdomain.com" >> monitor_14.txt && sort -u monitor_14.txt -o monitor_14.txt

# Remove domain
grep -v "domain.com" monitor_14.txt > temp && mv temp monitor_14.txt

# Validate sorting
sort -c monitor_14.txt

# Check duplicates
sort monitor_14.txt | uniq -d

# Count by TLD
awk -F. '{print $NF}' monitor_14.txt | sort | uniq -c | sort -rn
```

### File Statistics

```bash
# Total domains: 24,543
# File size: ~434 KB
# Format: Plain text, UTF-8
# Sorting: Alphabetical (case-sensitive)
```

---

## Change Log

### 2025-11-14
- Created CLAUDE.md with comprehensive documentation
- Documented current repository state (24,543 domains)
- Established data format conventions and workflows
- Added AI assistant guidelines and best practices

---

## Additional Resources

### Tools for Domain Analysis

- `whois`: Domain registration lookup
- `dig`: DNS queries
- `host`: DNS hostname lookup
- `nslookup`: DNS query tool

### Validation Resources

- ICANN TLD list: https://data.iana.org/TLD/tlds-alpha-by-domain.txt
- Domain regex validation
- DNS checking tools

### Related Documentation

- README.md: Basic repository information
- Git commit history: Track changes over time

---

## Questions or Issues?

When working with this repository:
- Always validate changes before committing
- Test bulk operations on samples first
- Document significant modifications
- Maintain alphabetical sorting
- Keep the domain list clean and deduplicated

---

**Last Updated**: 2025-11-14
**Repository**: mukesh-sethu-07/testmuhe
**Branch**: claude/claude-md-mhyh4lbt4c7jap75-01MNtYinCP5vND3sPgDssFaL
