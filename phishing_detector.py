#!/usr/bin/env python3
"""
Phishing Domain Detector
Identifies suspicious domains that may be impersonating legitimate organizations
"""

import re
from typing import List, Dict, Set, Tuple
from difflib import SequenceMatcher
import json

# Organization whitelisted domains
ORGANIZATIONS = {
    "State Bank of India (SBI)": {
        "keywords": ["sbi", "statebank"],
        "whitelisted": [
            "onlinesbi.sbi", "sbi.co.in", "sbicard.com",
            "yonobusiness.sbi", "sbiepay.sbi", "sbilife.co.in"
        ]
    },
    "ICICI Bank": {
        "keywords": ["icici"],
        "whitelisted": [
            "icicibank.com", "icicicareers.com", "icicidirect.com",
            "icicilombard.com", "iciciprulife.com"
        ]
    },
    "HDFC Bank": {
        "keywords": ["hdfc"],
        "whitelisted": [
            "hdfcbank.com", "hdfc.com", "hdfcergo.com", "hdfclife.com"
        ]
    },
    "Punjab National Bank (PNB)": {
        "keywords": ["pnb", "punjab", "national", "pnbindia"],
        "whitelisted": ["pnbindia.in", "netpnb.com"]
    },
    "Bank of Baroda (BoB)": {
        "keywords": ["baroda", "bob", "bankofbaroda"],
        "whitelisted": ["bankofbaroda.in", "bobibanking.com"]
    },
    "National Informatics Centre (NIC)": {
        "keywords": ["nic", "gov"],
        "whitelisted": [
            "nic.gov.in", "email.gov.in", "kavach.mail.gov.in",
            "accounts.mgovcloud.in"
        ]
    },
    "RGCCI": {
        "keywords": ["crsorgi", "census", "rgcci"],
        "whitelisted": ["dc.crsorgi.gov.in"]
    },
    "IRCTC": {
        "keywords": ["irctc", "railway"],
        "whitelisted": ["irctc.co.in", "irctc.com"]
    },
    "Airtel": {
        "keywords": ["airtel"],
        "whitelisted": ["airtel.in", "airtel.com"]
    },
    "IOCL": {
        "keywords": ["iocl", "indianoil"],
        "whitelisted": ["iocl.com"]
    }
}

# Common homoglyphs (lookalike characters)
HOMOGLYPHS = {
    'a': ['а', 'ą', 'ǎ', 'à', 'á', 'â', 'ã', 'ä', 'å'],
    'b': ['ḃ', 'ḅ', 'ḇ', 'ɓ'],
    'c': ['с', 'ċ', 'ç', 'ć', 'č'],
    'd': ['ď', 'ḋ', 'ḍ', 'ḏ', 'đ'],
    'e': ['е', 'ė', 'ę', 'è', 'é', 'ê', 'ë', 'ē', 'ĕ', 'ě'],
    'f': ['ḟ'],
    'g': ['ġ', 'ģ', 'ǧ', 'ḡ'],
    'h': ['һ', 'ḣ', 'ḥ', 'ḧ', 'ḩ', 'ḫ', 'ħ'],
    'i': ['і', 'ı', 'ì', 'í', 'î', 'ï', 'ī', 'ĩ', 'ĭ', 'ǐ', 'į'],
    'j': ['ј', 'ĵ'],
    'k': ['ķ', 'ǩ', 'ḱ', 'ḳ', 'ḵ'],
    'l': ['ļ', 'ľ', 'ḷ', 'ḹ', 'ḻ', 'ḽ', 'ł', '1'],
    'm': ['ṁ', 'ṃ'],
    'n': ['ń', 'ņ', 'ň', 'ṅ', 'ṇ', 'ṉ', 'ṋ', 'ñ'],
    'o': ['о', 'ò', 'ó', 'ô', 'õ', 'ö', 'ø', 'ō', 'ŏ', 'ő', '0'],
    'p': ['р', 'ṗ', 'ṕ'],
    'q': ['ʠ'],
    'r': ['ŕ', 'ŗ', 'ř', 'ṙ', 'ṛ', 'ṝ', 'ṟ'],
    's': ['ś', 'ŝ', 'ş', 'š', 'ṡ', 'ṣ', 'ṥ', 'ṧ', 'ṩ'],
    't': ['ţ', 'ť', 'ṫ', 'ṭ', 'ṯ', 'ṱ'],
    'u': ['ù', 'ú', 'û', 'ü', 'ũ', 'ū', 'ŭ', 'ů', 'ű', 'ų', 'ǔ', 'ǖ', 'ǘ', 'ǚ', 'ǜ'],
    'v': ['ṽ', 'ṿ'],
    'w': ['ŵ', 'ẁ', 'ẃ', 'ẅ', 'ẇ', 'ẉ'],
    'x': ['х', 'ẋ', 'ẍ'],
    'y': ['у', 'ý', 'ÿ', 'ŷ', 'ẏ', 'ỳ', 'ỹ'],
    'z': ['ź', 'ż', 'ž', 'ẑ', 'ẓ', 'ẕ']
}

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = [
    'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs
    'xyz', 'top', 'site', 'online', 'club',  # Cheap TLDs
    'info', 'biz', 'ws', 'cc',  # Often abused
    'bond', 'sbs'  # Recently seen in phishing
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def extract_domain_parts(domain: str) -> Tuple[str, str]:
    """Extract domain name and TLD"""
    parts = domain.split('.')
    if len(parts) >= 2:
        tld = parts[-1]
        name = '.'.join(parts[:-1])
        return name, tld
    return domain, ''


def contains_homoglyphs(domain: str) -> bool:
    """Check if domain contains homoglyph characters"""
    for char in domain:
        for normal_char, homoglyph_list in HOMOGLYPHS.items():
            if char in homoglyph_list:
                return True
    return False


def is_typosquat(domain: str, legitimate: str, threshold: int = 2) -> bool:
    """Check if domain is a typosquatting variant"""
    domain_name, _ = extract_domain_parts(domain)
    legit_name, _ = extract_domain_parts(legitimate)

    distance = levenshtein_distance(domain_name.lower(), legit_name.lower())
    return 0 < distance <= threshold


def check_keyword_similarity(domain: str, keywords: List[str]) -> Tuple[bool, str]:
    """Check if domain contains or is similar to keywords"""
    domain_lower = domain.lower()

    # Exact substring match
    for keyword in keywords:
        if keyword in domain_lower:
            return True, keyword

    # Fuzzy match for typosquatting
    domain_name, _ = extract_domain_parts(domain)
    for keyword in keywords:
        if len(keyword) >= 3:  # Only check for keywords with 3+ chars
            similarity = SequenceMatcher(None, domain_name.lower(), keyword.lower()).ratio()
            if similarity > 0.8:  # 80% similar
                return True, keyword

    return False, ''


def has_suspicious_tld(domain: str) -> bool:
    """Check if domain uses a suspicious TLD"""
    _, tld = extract_domain_parts(domain)
    return tld in SUSPICIOUS_TLDS


def is_whitelisted(domain: str, whitelisted_domains: List[str]) -> bool:
    """Check if domain is in whitelist"""
    domain_lower = domain.lower()
    for whitelist in whitelisted_domains:
        if domain_lower == whitelist.lower():
            return True
    return False


def analyze_domain(domain: str) -> List[Dict]:
    """Analyze a single domain against all organizations"""
    findings = []

    for org_name, org_data in ORGANIZATIONS.items():
        # Skip if whitelisted
        if is_whitelisted(domain, org_data['whitelisted']):
            continue

        # Check for keyword matches
        has_keyword, matched_keyword = check_keyword_similarity(domain, org_data['keywords'])

        if has_keyword:
            reasons = []
            risk_score = 0

            # Check various suspicious patterns
            if contains_homoglyphs(domain):
                reasons.append("Contains homoglyph characters")
                risk_score += 30

            if has_suspicious_tld(domain):
                reasons.append(f"Uses suspicious TLD (.{extract_domain_parts(domain)[1]})")
                risk_score += 20

            # Check typosquatting against whitelisted domains
            for whitelist in org_data['whitelisted']:
                if is_typosquat(domain, whitelist):
                    reasons.append(f"Typosquatting variant of {whitelist}")
                    risk_score += 40
                    break

            # Check for keyword-based impersonation
            if matched_keyword:
                reasons.append(f"Contains brand keyword: '{matched_keyword}'")
                risk_score += 25

            # Additional suspicious patterns
            domain_lower = domain.lower()
            suspicious_patterns = [
                'login', 'signin', 'verify', 'secure', 'account',
                'update', 'confirm', 'support', 'help', 'bank',
                'password', 'wallet', 'pay', 'payment'
            ]
            found_patterns = [p for p in suspicious_patterns if p in domain_lower]
            if found_patterns:
                reasons.append(f"Contains suspicious keywords: {', '.join(found_patterns)}")
                risk_score += 15 * len(found_patterns)

            if reasons:
                risk_level = "CRITICAL" if risk_score >= 60 else "HIGH" if risk_score >= 40 else "MEDIUM"
                findings.append({
                    'domain': domain,
                    'organization': org_name,
                    'risk_level': risk_level,
                    'risk_score': min(risk_score, 100),
                    'reasons': reasons,
                    'matched_keyword': matched_keyword
                })

    return findings


def main():
    """Main function to process domains and detect phishing"""
    print("=" * 80)
    print("PHISHING DOMAIN DETECTOR")
    print("=" * 80)
    print()

    # Read domains from file
    print("[+] Reading domains from monitor_14.txt...")
    try:
        with open('monitor_14.txt', 'r', encoding='utf-8', errors='ignore') as f:
            domains = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        return

    print(f"[+] Total domains to analyze: {len(domains)}")
    print()

    # Analyze all domains
    print("[+] Analyzing domains for phishing patterns...")
    all_findings = []

    for i, domain in enumerate(domains, 1):
        if i % 1000 == 0:
            print(f"    Progress: {i}/{len(domains)} domains analyzed...")

        findings = analyze_domain(domain)
        all_findings.extend(findings)

    print()
    print(f"[+] Analysis complete!")
    print(f"[+] Found {len(all_findings)} suspicious domains")
    print()

    # Sort findings by risk score
    all_findings.sort(key=lambda x: x['risk_score'], reverse=True)

    # Group by organization
    by_org = {}
    for finding in all_findings:
        org = finding['organization']
        if org not in by_org:
            by_org[org] = []
        by_org[org].append(finding)

    # Print summary
    print("=" * 80)
    print("SUMMARY BY ORGANIZATION")
    print("=" * 80)
    print()

    for org_name in ORGANIZATIONS.keys():
        count = len(by_org.get(org_name, []))
        if count > 0:
            print(f"{org_name}: {count} suspicious domains")

    print()
    print("=" * 80)
    print("DETAILED FINDINGS")
    print("=" * 80)
    print()

    # Print detailed findings
    for org_name in ORGANIZATIONS.keys():
        findings = by_org.get(org_name, [])
        if not findings:
            continue

        print(f"\n{'=' * 80}")
        print(f"{org_name}")
        print(f"{'=' * 80}\n")

        for i, finding in enumerate(findings, 1):
            print(f"{i}. Domain: {finding['domain']}")
            print(f"   Risk Level: {finding['risk_level']} (Score: {finding['risk_score']}/100)")
            print(f"   Matched Keyword: {finding['matched_keyword']}")
            print(f"   Reasons:")
            for reason in finding['reasons']:
                print(f"      - {reason}")
            print()

    # Save to JSON
    print("\n[+] Saving results to phishing_report.json...")
    with open('phishing_report.json', 'w', encoding='utf-8') as f:
        json.dump({
            'total_domains_analyzed': len(domains),
            'suspicious_domains_found': len(all_findings),
            'findings': all_findings,
            'summary_by_organization': {
                org: len(by_org.get(org, []))
                for org in ORGANIZATIONS.keys()
            }
        }, f, indent=2, ensure_ascii=False)

    # Save to CSV
    print("[+] Saving results to phishing_report.csv...")
    with open('phishing_report.csv', 'w', encoding='utf-8') as f:
        f.write("Domain,Organization,Risk Level,Risk Score,Matched Keyword,Reasons\n")
        for finding in all_findings:
            reasons = '; '.join(finding['reasons'])
            f.write(f'"{finding["domain"]}","{finding["organization"]}","{finding["risk_level"]}",{finding["risk_score"]},"{finding["matched_keyword"]}","{reasons}"\n')

    print("\n[+] Detection complete!")
    print(f"[+] Results saved to:")
    print(f"    - phishing_report.json")
    print(f"    - phishing_report.csv")
    print()


if __name__ == "__main__":
    main()
