# utils.py

import re

def detect_indicator_type(indicator):
    ipv4_regex = r'^\d{1,3}(\.\d{1,3}){3}$'
    url_regex = r'^(http|https)://'
    domain_regex = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    md5_regex = r'^[a-fA-F0-9]{32}$'
    sha1_regex = r'^[a-fA-F0-9]{40}$'
    sha256_regex = r'^[a-fA-F0-9]{64}$'
    cve_regex = r'^CVE-\d{4}-\d{4,}$'

    if re.match(ipv4_regex, indicator):
        return 'IP Address'
    elif re.match(url_regex, indicator):
        return 'URL'
    elif re.match(domain_regex, indicator):
        return 'Domain'
    elif re.match(md5_regex, indicator):
        return 'MD5 Hash'
    elif re.match(sha1_regex, indicator):
        return 'SHA1 Hash'
    elif re.match(sha256_regex, indicator):
        return 'SHA256 Hash'
    elif re.match(cve_regex, indicator, re.IGNORECASE):
        return 'CVE'
    else:
        return 'Unknown'
