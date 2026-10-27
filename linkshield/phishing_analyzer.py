"""
LinkShield — Phishing URL Analyzer
Ported from TypeScript to Python
"""

import re
from datetime import datetime
from urllib.parse import urlparse

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
                   '.click', '.link', '.info', '.buzz', '.rest']

TRUSTED_DOMAINS = [
    'google.com', 'facebook.com', 'apple.com', 'microsoft.com', 'amazon.com',
    'twitter.com', 'github.com', 'linkedin.com', 'netflix.com', 'paypal.com',
    'instagram.com', 'youtube.com', 'whatsapp.com', 'chase.com',
    'bankofamerica.com', 'wellsfargo.com'
]

PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
    'password', 'credential', 'suspended', 'locked', 'urgent', 'alert',
    'banking', 'wallet'
]

BRAND_NAMES = [
    'google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal', 'netflix',
    'instagram', 'whatsapp', 'chase', 'wellsfargo', 'bankofamerica', 'twitter',
    'linkedin', 'github'
]


def levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i-1] == b[j-1]:
                dp[i][j] = dp[i-1][j-1]
            else:
                dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
    return dp[m][n]


def is_similar_to_brand(domain: str, brand: str) -> bool:
    parts = domain.split('.')
    main_domain = ''.join(parts[:-1]) if len(parts) >= 2 else domain
    if brand in main_domain:
        return True
    dist = levenshtein(main_domain, brand)
    if dist <= 2 and len(main_domain) >= len(brand) - 1:
        return True
    for part in parts[:-1]:
        if levenshtein(part, brand) <= 2 and len(part) >= len(brand) - 1:
            return True
    return False


def check_https(parsed) -> dict:
    is_secure = parsed.scheme == 'https'
    return {
        'name': 'HTTPS Security',
        'description': 'Checks if the website uses encrypted HTTPS connection',
        'status': 'safe' if is_secure else 'danger',
        'details': 'Connection is encrypted with HTTPS' if is_secure
                   else 'WARNING: No HTTPS encryption detected. Data can be intercepted.',
        'weight': 20
    }


def check_url_length(url: str) -> dict:
    length = len(url)
    if length > 100:
        status, msg = 'danger', 'Suspiciously long URL.'
    elif length > 60:
        status, msg = 'warning', 'Moderately long URL.'
    else:
        status, msg = 'safe', 'Normal length.'
    return {
        'name': 'URL Length',
        'description': 'Unusually long URLs can indicate phishing attempts',
        'status': status,
        'details': f'URL length: {length} characters. {msg}',
        'weight': 10
    }


def check_suspicious_tld(parsed) -> dict:
    hostname = parsed.hostname.lower() if parsed.hostname else ''
    has_suspicious = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
    return {
        'name': 'Domain TLD',
        'description': 'Checks for commonly abused top-level domains',
        'status': 'danger' if has_suspicious else 'safe',
        'details': 'Uses a top-level domain commonly associated with phishing.' if has_suspicious
                   else 'Domain TLD appears standard.',
        'weight': 15
    }


def check_ip_address(parsed) -> dict:
    hostname = parsed.hostname or ''
    ip_regex = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    is_ip = bool(ip_regex.match(hostname))
    return {
        'name': 'IP Address Usage',
        'description': 'Legitimate sites rarely use raw IP addresses',
        'status': 'danger' if is_ip else 'safe',
        'details': 'URL uses an IP address instead of a domain name — strong phishing indicator.' if is_ip
                   else 'Uses a proper domain name.',
        'weight': 20
    }


def check_subdomain_abuse(parsed) -> dict:
    hostname = parsed.hostname or ''
    parts = hostname.split('.')
    subdomain_count = len(parts) - 2
    if subdomain_count > 3:
        status, msg = 'danger', 'Excessive subdomains — possible spoofing.'
    elif subdomain_count > 1:
        status, msg = 'warning', 'Multiple subdomains detected.'
    else:
        status, msg = 'safe', 'Normal structure.'
    return {
        'name': 'Subdomain Analysis',
        'description': 'Excessive subdomains can indicate domain spoofing',
        'status': status,
        'details': f'{subdomain_count} subdomain(s) detected. {msg}',
        'weight': 12
    }


def check_suspicious_characters(parsed) -> dict:
    full_url = parsed.geturl()
    suspicious = re.findall(r'[@%]|\.{2,}|-{3,}', full_url)
    # Cyrillic/homograph check
    has_homograph = bool(re.search(r'[\u0400-\u052F]', full_url))
    if has_homograph:
        status = 'danger'
        details = 'Contains non-Latin characters (possible homograph attack).'
    elif suspicious:
        status = 'warning'
        details = f"Found suspicious characters: {', '.join(set(suspicious))}"
    else:
        status = 'safe'
        details = 'No suspicious characters found.'
    return {
        'name': 'Suspicious Characters',
        'description': 'Checks for character tricks like homograph attacks',
        'status': status,
        'details': details,
        'weight': 15
    }


def check_brand_impersonation(parsed) -> dict:
    hostname = (parsed.hostname or '').lower()
    path = (parsed.path or '').lower()
    full = hostname + path
    is_trusted = any(hostname == d or hostname.endswith('.' + d) for d in TRUSTED_DOMAINS)
    impersonated = []
    for brand in BRAND_NAMES:
        if is_trusted:
            break
        if brand in full:
            impersonated.append(brand)
        elif is_similar_to_brand(hostname, brand):
            impersonated.append(brand)
    impersonated = list(set(impersonated))
    return {
        'name': 'Brand Impersonation',
        'description': 'Detects if URL mimics a well-known brand',
        'status': 'danger' if impersonated else 'safe',
        'details': f"Possible impersonation of: {', '.join(impersonated)}" if impersonated
                   else 'No brand impersonation detected.',
        'weight': 25
    }


def check_phishing_keywords(parsed) -> dict:
    full = ((parsed.hostname or '') + (parsed.path or '') + (parsed.query or '')).lower()
    found = [kw for kw in PHISHING_KEYWORDS if kw in full]
    if len(found) >= 3:
        status = 'danger'
    elif found:
        status = 'warning'
    else:
        status = 'safe'
    return {
        'name': 'Phishing Keywords',
        'description': 'Scans for common phishing-related terms in URL',
        'status': status,
        'details': f"Found keywords: {', '.join(found)}" if found else 'No phishing keywords detected.',
        'weight': 10
    }


def check_port_usage(parsed) -> dict:
    port = str(parsed.port) if parsed.port else ''
    unusual = port and port not in ['80', '443', '']
    return {
        'name': 'Port Analysis',
        'description': 'Unusual ports can indicate rogue servers',
        'status': 'warning' if unusual else 'safe',
        'details': f'Non-standard port {port} detected.' if unusual else 'Standard port usage.',
        'weight': 8
    }


def check_obfuscated_url(raw_url: str):
    lower = raw_url.lower().strip()
    defanged = bool(re.match(r'^(hxxps?|htxps?|http\$s?|https?\$|htt[^p]s?):\/\/', lower))
    domain_part = re.sub(r'^(https?|hxxps?):\/\/', '', lower).split('/')[0].split('?')[0]
    has_special = bool(re.search(r'[!$*^~`|\\{}\[\]]', domain_part))
    has_substitution = False
    if re.search(r'[0-9!@#$%^&*]', domain_part.replace('.', '').replace(':', '')):
        for brand in BRAND_NAMES:
            cleaned = re.sub(r'[^a-z]', '', domain_part)
            matches = sum(1 for c in brand if c in cleaned)
            similarity = matches / len(brand) if brand else 0
            if 0.6 <= similarity < 1.0:
                has_substitution = True
                break
    if defanged or has_special or has_substitution:
        if defanged:
            details = 'Defanged/obfuscated protocol detected (e.g., hxxps, http$). This is a known phishing technique.'
        elif has_special:
            details = f'Special characters found in domain: "{domain_part}". Legitimate domains do not contain these characters.'
        else:
            details = 'Possible character substitution attack — domain mimics a known brand with altered characters.'
        return {
            'name': 'URL Obfuscation',
            'description': 'Detects defanged, obfuscated, or character-substituted URLs',
            'status': 'danger',
            'details': details,
            'weight': 30
        }
    return None


def analyze_url(raw_url: str) -> dict:
    url_str = raw_url.strip()
    original_url = url_str

    # Normalize defanged protocols
    url_str = re.sub(r'^hxxps?://', 'https://', url_str, flags=re.IGNORECASE)
    url_str = re.sub(r'^http\$s?://', 'https://', url_str, flags=re.IGNORECASE)
    url_str = re.sub(r'^https?\$://', 'https://', url_str, flags=re.IGNORECASE)

    protocol_match = re.match(r'^(https?://)', url_str, re.IGNORECASE)
    protocol = protocol_match.group(1) if protocol_match else 'https://'
    rest = url_str[len(protocol):] if protocol_match else url_str

    domain_part = rest.split('/')[0].split('?')[0]
    cleaned_domain = re.sub(r'[!$*^~`|\\{}\[\]]', '', domain_part)
    cleaned_rest = cleaned_domain + rest[len(domain_part):]

    if not url_str.startswith('http://') and not url_str.startswith('https://'):
        url_str = 'https://' + cleaned_rest
    else:
        url_str = protocol + cleaned_rest

    parsed = urlparse(url_str)

    obfuscation_check = check_obfuscated_url(original_url)

    checks = [
        check_https(parsed),
        check_brand_impersonation(parsed),
        check_ip_address(parsed),
        check_suspicious_tld(parsed),
        check_subdomain_abuse(parsed),
        check_suspicious_characters(parsed),
        check_phishing_keywords(parsed),
        check_url_length(url_str),
        check_port_usage(parsed),
    ]

    if obfuscation_check:
        checks.insert(0, obfuscation_check)

    total_weight = sum(c['weight'] for c in checks)
    danger_score = sum(
        c['weight'] if c['status'] == 'danger' else c['weight'] * 0.5 if c['status'] == 'warning' else 0
        for c in checks
    )

    risk_score = round((danger_score / total_weight) * 100)

    danger_checks = [c for c in checks if c['status'] == 'danger']
    critical_names = {'URL Obfuscation', 'Brand Impersonation', 'IP Address Usage', 'Suspicious Characters'}
    has_critical = any(c['name'] in critical_names for c in danger_checks)

    if danger_checks:
        risk_score = max(risk_score, 30)
    if has_critical:
        risk_score = max(risk_score, 60)

    overall_status = 'phishing' if risk_score >= 50 else 'suspicious' if risk_score >= 25 else 'legitimate'

    display_url = original_url.strip()
    if not display_url.startswith('http'):
        display_url = 'https://' + display_url

    return {
        'url': display_url,
        'overall_status': overall_status,
        'risk_score': risk_score,
        'checks': checks,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
