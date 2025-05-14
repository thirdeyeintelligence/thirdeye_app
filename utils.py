import re

def detect_indicator_type(indicator):
    indicator = indicator.strip()

    # IP Address
    ip_regex = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_regex, indicator):
        return 'IP Address'

    # CVE
    if indicator.upper().startswith("CVE-"):
        return 'CVE'

    # URL
    if indicator.startswith("http://") or indicator.startswith("https://"):
        return 'URL'

    # Domain
    domain_regex = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(domain_regex, indicator) and '.' in indicator and '/' not in indicator:
        return 'Domain'

    # SHA256
    if re.match(r'^[a-fA-F0-9]{64}$', indicator):
        return 'SHA256 Hash'

    # SHA1
    if re.match(r'^[a-fA-F0-9]{40}$', indicator):
        return 'SHA1 Hash'

    # MD5
    if re.match(r'^[a-fA-F0-9]{32}$', indicator):
        return 'MD5 Hash'

    return 'Unknown'
