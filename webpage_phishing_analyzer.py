#!/usr/bin/env python3
"""
Webpage Content Phishing Analyzer
Fetches and analyzes actual webpage content to identify phishing sites
"""

import requests
import re
import json
import csv
from urllib.parse import urlparse
from typing import Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Configuration
TIMEOUT = 10
MAX_WORKERS = 20
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

# Phishing indicators
PHISHING_KEYWORDS = {
    'high_risk': [
        'verify your account', 'account suspended', 'urgent action required',
        'confirm your identity', 'unusual activity', 'security alert',
        'click here immediately', 'account will be closed', 'limited time',
        'verify now', 'suspended account', 'restore access', 'confirm identity',
        'unusual sign-in', 'locked account', 'update payment', 'billing problem',
        'action required', 'expire', 'suspended', 'locked', 'blocked',
        'reactivate', 'validate', 'authenticate'
    ],
    'credential_harvesting': [
        'enter password', 'confirm password', 'login credentials', 'username and password',
        'sign in to continue', 'enter your email', 'verify email', 'update password',
        'password reset', 'security question', 'credit card', 'cvv', 'card number',
        'social security', 'ssn', 'date of birth', 'mother maiden name'
    ],
    'brand_impersonation': [
        'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'instagram',
        'netflix', 'spotify', 'adobe', 'dropbox', 'linkedin', 'twitter', 'ebay',
        'bank of america', 'chase', 'wells fargo', 'citibank', 'usaa',
        'irs', 'dhl', 'fedex', 'ups', 'usps', 'coinbase', 'binance', 'metamask',
        'blockchain', 'crypto', 'bitcoin', 'ethereum'
    ],
    'urgency_scarcity': [
        'act now', 'limited offer', 'expires today', 'last chance', 'urgent',
        'immediately', 'don\'t miss out', 'hurry', 'time sensitive', 'deadline',
        'instant', 'right now', 'final notice', 'last warning'
    ],
    'financial': [
        'tax refund', 'prize', 'winner', 'lottery', 'inheritance', 'fund transfer',
        'claim reward', 'bonus', 'free money', 'cash prize', 'unclaimed funds',
        'compensation', 'reimbursement'
    ],
    'gambling': [
        'casino', 'betting', 'slots', 'poker', 'roulette', 'jackpot', 'win big',
        'bet now', 'deposit bonus', 'free spins', 'odds', 'wager', 'gamble'
    ]
}

# Suspicious patterns
SUSPICIOUS_PATTERNS = {
    'login_form': r'<form[^>]*>.*?(password|username|email|login).*?</form>',
    'input_password': r'<input[^>]*type=["\']password["\'][^>]*>',
    'input_email': r'<input[^>]*type=["\']email["\'][^>]*>',
    'input_credit_card': r'<input[^>]*(card|cvv|credit)[^>]*>',
    'hidden_redirect': r'window\.location\s*=|document\.location\s*=|location\.href\s*=',
    'iframe': r'<iframe[^>]*src=["\']([^"\']+)["\'][^>]*>',
    'base64_encoded': r'data:text/html;base64,',
    'obfuscated_js': r'eval\s*\(|unescape\s*\(|fromCharCode',
}

# Legitimate brand domains (to detect impersonation)
LEGITIMATE_BRANDS = {
    'paypal.com', 'amazon.com', 'microsoft.com', 'apple.com', 'google.com',
    'facebook.com', 'instagram.com', 'netflix.com', 'spotify.com', 'adobe.com',
    'dropbox.com', 'linkedin.com', 'twitter.com', 'ebay.com', 'coinbase.com',
    'binance.com', 'blockchain.com', 'metamask.io'
}


def fetch_webpage(domain: str) -> Dict:
    """Fetch webpage content and metadata"""
    result = {
        'domain': domain,
        'accessible': False,
        'status_code': None,
        'content': '',
        'headers': {},
        'final_url': '',
        'ssl_valid': False,
        'error': None
    }

    protocols = ['https://', 'http://']

    for protocol in protocols:
        url = f"{protocol}{domain}"
        try:
            response = requests.get(
                url,
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=False,  # We'll note SSL issues separately
                headers={'User-Agent': USER_AGENT}
            )

            result['accessible'] = True
            result['status_code'] = response.status_code
            result['content'] = response.text[:100000]  # Limit content size
            result['headers'] = dict(response.headers)
            result['final_url'] = response.url
            result['ssl_valid'] = protocol == 'https://' and response.url.startswith('https://')

            break  # Success, exit loop

        except requests.exceptions.SSLError:
            result['error'] = 'SSL Error'
            if protocol == 'https://':
                continue  # Try HTTP
        except requests.exceptions.Timeout:
            result['error'] = 'Timeout'
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection Error'
        except Exception as e:
            result['error'] = str(e)[:100]

    return result


def analyze_content(webpage_data: Dict) -> Dict:
    """Analyze webpage content for phishing indicators"""
    domain = webpage_data['domain']
    content = webpage_data['content'].lower() if webpage_data['content'] else ''

    analysis = {
        'domain': domain,
        'is_phishing': False,
        'risk_score': 0,
        'risk_level': 'UNKNOWN',
        'indicators': [],
        'matched_keywords': [],
        'status': 'analyzed'
    }

    # If not accessible, mark as unknown
    if not webpage_data['accessible']:
        analysis['status'] = f"inaccessible: {webpage_data.get('error', 'unknown error')}"
        return analysis

    # Check for login forms
    if re.search(SUSPICIOUS_PATTERNS['login_form'], content, re.DOTALL | re.IGNORECASE):
        analysis['indicators'].append('Contains login form')
        analysis['risk_score'] += 15

    # Check for password inputs
    password_inputs = len(re.findall(SUSPICIOUS_PATTERNS['input_password'], content, re.IGNORECASE))
    if password_inputs > 0:
        analysis['indicators'].append(f'Contains {password_inputs} password input field(s)')
        analysis['risk_score'] += 20

    # Check for email inputs
    email_inputs = len(re.findall(SUSPICIOUS_PATTERNS['input_email'], content, re.IGNORECASE))
    if email_inputs > 0:
        analysis['indicators'].append(f'Contains {email_inputs} email input field(s)')
        analysis['risk_score'] += 10

    # Check for credit card inputs
    if re.search(SUSPICIOUS_PATTERNS['input_credit_card'], content, re.IGNORECASE):
        analysis['indicators'].append('Requests credit card information')
        analysis['risk_score'] += 30

    # Check for hidden redirects
    if re.search(SUSPICIOUS_PATTERNS['hidden_redirect'], content, re.IGNORECASE):
        analysis['indicators'].append('Contains JavaScript redirects')
        analysis['risk_score'] += 15

    # Check for iframes
    iframes = re.findall(SUSPICIOUS_PATTERNS['iframe'], content, re.IGNORECASE)
    if iframes:
        analysis['indicators'].append(f'Contains {len(iframes)} iframe(s)')
        analysis['risk_score'] += 10

    # Check for obfuscated JavaScript
    if re.search(SUSPICIOUS_PATTERNS['obfuscated_js'], content, re.IGNORECASE):
        analysis['indicators'].append('Contains obfuscated JavaScript')
        analysis['risk_score'] += 20

    # Check for base64 encoding
    if re.search(SUSPICIOUS_PATTERNS['base64_encoded'], content, re.IGNORECASE):
        analysis['indicators'].append('Contains base64 encoded content')
        analysis['risk_score'] += 15

    # Check phishing keywords
    for category, keywords in PHISHING_KEYWORDS.items():
        matched = [kw for kw in keywords if kw in content]
        if matched:
            analysis['matched_keywords'].extend([(category, kw) for kw in matched])

            if category == 'high_risk':
                analysis['risk_score'] += 25
                analysis['indicators'].append(f'Contains high-risk phishing phrases: {len(matched)} found')
            elif category == 'credential_harvesting':
                analysis['risk_score'] += 30
                analysis['indicators'].append(f'Contains credential harvesting phrases: {len(matched)} found')
            elif category == 'brand_impersonation':
                analysis['risk_score'] += 35
                analysis['indicators'].append(f'Mentions well-known brands: {len(matched)} found')
            elif category == 'urgency_scarcity':
                analysis['risk_score'] += 15
                analysis['indicators'].append(f'Uses urgency/scarcity tactics: {len(matched)} found')
            elif category == 'financial':
                analysis['risk_score'] += 20
                analysis['indicators'].append(f'Contains financial scam keywords: {len(matched)} found')
            elif category == 'gambling':
                analysis['risk_score'] += 25
                analysis['indicators'].append(f'Online gambling/casino content: {len(matched)} found')

    # Check if domain impersonates legitimate brands
    for brand in LEGITIMATE_BRANDS:
        brand_name = brand.split('.')[0]
        if brand_name in domain and domain != brand:
            analysis['indicators'].append(f'Domain may impersonate {brand}')
            analysis['risk_score'] += 40

    # Check for URL redirects to different domain
    if webpage_data.get('final_url'):
        final_domain = urlparse(webpage_data['final_url']).netloc
        if final_domain and final_domain != domain and not final_domain.endswith(domain):
            analysis['indicators'].append(f'Redirects to different domain: {final_domain}')
            analysis['risk_score'] += 20

    # Check for missing/invalid SSL
    if not webpage_data.get('ssl_valid'):
        analysis['indicators'].append('No valid SSL certificate')
        analysis['risk_score'] += 10

    # Suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.site',
                      '.online', '.club', '.info', '.biz', '.sbs', '.live', '.casino',
                      '.ink', '.store', '.space', '.fun', '.rest', '.shop', '.icu',
                      '.pro', '.art', '.blog', '.best']

    for tld in suspicious_tlds:
        if domain.endswith(tld):
            analysis['indicators'].append(f'Uses suspicious TLD: {tld}')
            analysis['risk_score'] += 15
            break

    # Determine risk level
    if analysis['risk_score'] >= 80:
        analysis['risk_level'] = 'CRITICAL'
        analysis['is_phishing'] = True
    elif analysis['risk_score'] >= 60:
        analysis['risk_level'] = 'HIGH'
        analysis['is_phishing'] = True
    elif analysis['risk_score'] >= 40:
        analysis['risk_level'] = 'MEDIUM'
        analysis['is_phishing'] = True
    elif analysis['risk_score'] >= 20:
        analysis['risk_level'] = 'LOW'
    else:
        analysis['risk_level'] = 'SAFE'

    return analysis


def process_domain(domain: str) -> Dict:
    """Process a single domain"""
    print(f"[*] Checking: {domain}")

    # Fetch webpage
    webpage_data = fetch_webpage(domain)

    # Analyze content
    analysis = analyze_content(webpage_data)

    return analysis


def main():
    """Main function"""
    print("=" * 100)
    print("WEBPAGE CONTENT PHISHING ANALYZER")
    print("=" * 100)
    print()

    # Read domains
    print("[+] Reading domains from domains_to_check.txt...")
    try:
        with open('domains_to_check.txt', 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        return

    print(f"[+] Total domains to analyze: {len(domains)}")
    print(f"[+] Using {MAX_WORKERS} concurrent workers")
    print()

    # Process domains concurrently
    print("[+] Fetching and analyzing webpages...")
    results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_domain, domain): domain for domain in domains}

        completed = 0
        for future in as_completed(futures):
            completed += 1
            try:
                result = future.result()
                results.append(result)

                if result['is_phishing']:
                    print(f"    [{completed}/{len(domains)}] {result['domain']} - {result['risk_level']} ({result['risk_score']})")
                elif completed % 10 == 0:
                    print(f"    Progress: {completed}/{len(domains)} domains analyzed...")

            except Exception as e:
                print(f"    [!] Error processing domain: {e}")

    print()
    print("[+] Analysis complete!")

    # Filter phishing domains
    phishing_domains = [r for r in results if r['is_phishing']]
    inaccessible_domains = [r for r in results if r['status'] != 'analyzed']
    safe_domains = [r for r in results if not r['is_phishing'] and r['status'] == 'analyzed']

    print(f"[+] Phishing domains found: {len(phishing_domains)}")
    print(f"[+] Inaccessible domains: {len(inaccessible_domains)}")
    print(f"[+] Safe/Low risk domains: {len(safe_domains)}")
    print()

    # Sort by risk score
    phishing_domains.sort(key=lambda x: x['risk_score'], reverse=True)

    # Print summary
    print("=" * 100)
    print("PHISHING DOMAINS DETECTED")
    print("=" * 100)
    print()

    for i, result in enumerate(phishing_domains, 1):
        print(f"{i}. {result['domain']}")
        print(f"   Risk Level: {result['risk_level']} (Score: {result['risk_score']}/100)")
        print(f"   Indicators:")
        for indicator in result['indicators']:
            print(f"      - {indicator}")

        if result['matched_keywords']:
            categories = {}
            for cat, kw in result['matched_keywords']:
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(kw)

            for cat, keywords in categories.items():
                print(f"   {cat.replace('_', ' ').title()}: {', '.join(keywords[:5])}" +
                      (f" (+{len(keywords)-5} more)" if len(keywords) > 5 else ""))
        print()

    # Save results to JSON
    print("[+] Saving results to phishing_content_analysis.json...")
    with open('phishing_content_analysis.json', 'w', encoding='utf-8') as f:
        json.dump({
            'total_domains': len(domains),
            'phishing_detected': len(phishing_domains),
            'inaccessible': len(inaccessible_domains),
            'safe': len(safe_domains),
            'results': results
        }, f, indent=2, ensure_ascii=False)

    # Save phishing domains to CSV
    print("[+] Saving phishing domains to phishing_domains.csv...")
    with open('phishing_domains.csv', 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Domain', 'Risk Level', 'Risk Score', 'Indicators', 'Status'])

        for result in phishing_domains:
            writer.writerow([
                result['domain'],
                result['risk_level'],
                result['risk_score'],
                '; '.join(result['indicators']),
                result['status']
            ])

    # Save summary report
    print("[+] Saving summary report to phishing_summary.txt...")
    with open('phishing_summary.txt', 'w', encoding='utf-8') as f:
        f.write("PHISHING DOMAIN ANALYSIS SUMMARY\n")
        f.write("=" * 100 + "\n\n")
        f.write(f"Total Domains Analyzed: {len(domains)}\n")
        f.write(f"Phishing Domains Detected: {len(phishing_domains)}\n")
        f.write(f"Inaccessible Domains: {len(inaccessible_domains)}\n")
        f.write(f"Safe/Low Risk Domains: {len(safe_domains)}\n\n")

        f.write("RISK LEVEL BREAKDOWN\n")
        f.write("-" * 100 + "\n")
        critical = len([r for r in phishing_domains if r['risk_level'] == 'CRITICAL'])
        high = len([r for r in phishing_domains if r['risk_level'] == 'HIGH'])
        medium = len([r for r in phishing_domains if r['risk_level'] == 'MEDIUM'])
        f.write(f"Critical Risk: {critical}\n")
        f.write(f"High Risk: {high}\n")
        f.write(f"Medium Risk: {medium}\n\n")

        f.write("PHISHING DOMAINS LIST\n")
        f.write("=" * 100 + "\n\n")

        for i, result in enumerate(phishing_domains, 1):
            f.write(f"{i}. {result['domain']}\n")
            f.write(f"   Risk: {result['risk_level']} ({result['risk_score']}/100)\n")
            f.write(f"   Indicators: {', '.join(result['indicators'])}\n\n")

    print()
    print("[+] Analysis complete!")
    print(f"[+] Results saved to:")
    print(f"    - phishing_content_analysis.json (full analysis)")
    print(f"    - phishing_domains.csv (phishing domains only)")
    print(f"    - phishing_summary.txt (summary report)")
    print()


if __name__ == "__main__":
    main()
