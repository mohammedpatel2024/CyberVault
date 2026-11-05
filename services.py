"""Bounded DNS checks and TLS handshakes to previously validated public IPs.
No HTTP request is made to a submitted website.
"""
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
import dns.exception
import dns.resolver
from .features import normalize_url, extract_url_features

class ScanError(ValueError):
    pass

def is_public_address(address):
    ip = ipaddress.ip_address(address)
    if not ip.is_global or ip.is_multicast:
        return False
    # Avoid transition mechanisms that may embed a non-public IPv4 destination.
    if ip.version == 6:
        if ip.ipv4_mapped:
            return is_public_address(str(ip.ipv4_mapped))
        if any(ip in ipaddress.ip_network(net) for net in ("64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32")):
            return False
    return True

def dns_analysis(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not is_public_address(str(ip)):
            raise ScanError("Website scans support public addresses only. Use IP Intelligence to classify private addresses.")
        return [str(ip)], {"address": {"status": "Direct IP", "values": [str(ip)]}}
    resolver = dns.resolver.Resolver()
    records = {}
    addresses = []
    deadline = time.monotonic() + 10
    for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            records[record_type] = {"status": "Time limit reached", "values": []}
            continue
        try:
            answer = resolver.resolve(host + ".", record_type, lifetime=min(2, remaining), search=False)
            values = [str(item)[:500] for item in answer][:12]
            records[record_type] = {"status": "Found", "values": values, "ttl": answer.rrset.ttl if answer.rrset else None}
            if record_type in ("A", "AAAA"):
                # Check ALL answers, even those omitted from the displayed record list.
                for item in answer:
                    address = str(ipaddress.ip_address(item.address))
                    if not is_public_address(address):
                        raise ScanError("DNS returned a private or special-use address. Network checks were blocked.")
                    if address not in addresses:
                        addresses.append(address)
        except dns.resolver.NXDOMAIN as exc:
            raise ScanError("This hostname does not exist in DNS.") from exc
        except dns.resolver.NoAnswer:
            records[record_type] = {"status": "No record", "values": []}
        except dns.exception.DNSException:
            records[record_type] = {"status": "Unavailable or timed out", "values": []}
    if not addresses:
        raise ScanError("No public IP address could be resolved. Check the hostname or try again.")
    # If either address family could not be checked, avoid connecting on incomplete evidence.
    incomplete = any(records[k]["status"] not in ("Found", "No record") for k in ("A", "AAAA"))
    records["network_checks"] = {"status": "Skipped: incomplete address resolution" if incomplete else "Public addresses validated", "values": []}
    return addresses, records

def check_tls(host, address):
    context = ssl.create_default_context()
    family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as raw:
            raw.settimeout(4)
            raw.connect((address, 443))  # Numeric address is pinned; do not resolve host again.
            with context.wrap_socket(raw, server_hostname=host) as secure:
                certificate = secure.getpeercert()
                issuer = ", ".join(value for group in certificate.get("issuer", ()) for key, value in group if key in ("organizationName", "commonName"))
                expires = certificate.get("notAfter", "")
                expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(expires), timezone.utc) if expires else None
                return "Valid", {"connected_ip": address, "hostname_verified": host, "protocol": secure.version(), "issuer": issuer, "expires": expiry.isoformat() if expiry else "Unknown", "days_remaining": (expiry - datetime.now(timezone.utc)).days if expiry else None}
    except ssl.SSLCertVerificationError:
        return "Certificate verification failed", {"connected_ip": address, "message": "Certificate chain, validity dates or hostname could not be verified."}
    except (OSError, ssl.SSLError):
        return "Unavailable", {"connected_ip": address, "message": "TLS handshake failed or timed out. This alone does not establish phishing."}

def assess_risk(features, probability, tls_status, reputation):
    score = 0
    explanations = []
    rules = [(not features["uses_https"], 10, "The submitted URL uses HTTP."), (features["ip_host"], 20, "The URL uses an IP address instead of a domain."), (features["has_at"], 10, "The URL contains an @ character."), (features["url_length"] > 120, 10, "The URL is unusually long."), (features["subdomain_count"] > 3, 10, "The hostname contains many subdomains."), (features["suspicious_word_count"] >= 2, 10, "The URL includes multiple account or verification keywords."), (features["hyphen_count"] >= 3, 5, "The hostname contains several hyphens.")]
    for triggered, points, explanation in rules:
        if triggered:
            score += points
            explanations.append(explanation + f" (+{points})")
    if probability is not None:
        points = 50 if probability >= 75 else 25 if probability >= 50 else 0
        score += points
        explanations.append(f"URL model estimated {probability:.1f}% phishing probability (+{points}). This estimate is not calibrated.")
    if tls_status == "Certificate verification failed":
        score += 20
        explanations.append("TLS certificate verification failed (+20).")
    if reputation == "Threat match":
        score = 100
        explanations.append("Google Safe Browsing returned a threat match (score set to 100).")
    score = min(score, 100)
    incomplete = probability is None or tls_status in ("Unavailable", "Not checked")
    level = "High risk indicators" if score >= 60 else "Review recommended" if score >= 25 else "Incomplete assessment" if incomplete else "Low observed risk"
    if not explanations:
        explanations.append("No configured URL indicators were triggered.")
    if tls_status == "Valid":
        explanations.append("TLS certificate verified; a valid certificate does not establish a safe website.")
    if reputation in ("Not configured", "Not requested", "Unavailable"):
        explanations.append("Threat reputation was not verified.")
    explanations.append("The score combines documented rules and a URL-only model. It is not a measured probability of harm.")
    return score, level, explanations
