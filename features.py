"""URL-only features shared by training and inference; no network calls."""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit
import tldextract
from ip_intelligence.services import parse_target

TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
FEATURE_NAMES = ["url_length", "hostname_length", "digit_ratio", "special_char_count", "subdomain_count", "hyphen_count", "has_at", "uses_https", "ip_host", "suspicious_word_count", "path_length"]
FEATURE_VERSION = 1
SUSPICIOUS_WORDS = ("login", "verify", "secure", "update", "account", "password")

def normalize_url(raw):
    value = str(raw).strip()
    if not value or len(value) > 2048 or any(ord(c) < 32 or c.isspace() for c in value):
        raise ValueError("Enter a website URL of at most 2048 characters, without spaces.")
    domain, address = parse_target(value)
    if "://" not in value:
        try:
            ip = ipaddress.ip_address(value)
            value = "https://" + ("[" + str(ip) + "]" if ip.version == 6 else str(ip))
        except ValueError:
            value = "https://" + value
    parsed = urlsplit(value)
    port = parsed.port
    expected = 443 if parsed.scheme == "https" else 80
    if port is not None and port != expected:
        raise ValueError("Only the standard HTTP (80) and HTTPS (443) ports are supported.")
    host = domain or address
    authority = "[" + host + "]" if ":" in host else host
    return urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", parsed.query, ""))

def extract_url_features(url):
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    try:
        ipaddress.ip_address(host)
        ip_host = 1
    except ValueError:
        ip_host = 0
    extracted = TLD_EXTRACT(host) if not ip_host else None
    lower = url.lower()
    return dict(zip(FEATURE_NAMES, [len(url), len(host), sum(c.isdigit() for c in url)/max(len(url), 1), sum(not c.isalnum() for c in url), len(extracted.subdomain.split(".")) if extracted and extracted.subdomain else 0, host.count("-"), int("@" in url), int(parsed.scheme == "https"), ip_host, sum(word in lower for word in SUSPICIOUS_WORDS), len(parsed.path)]))

def domain_group(url):
    host = urlsplit(url).hostname or ""
    extracted = TLD_EXTRACT(host)
    return extracted.top_domain_under_public_suffix or host
