import requests
from django.conf import settings

def check_reputation(url, requested=False):
    if not requested:
        return "Not requested", {}
    key = getattr(settings, "SAFE_BROWSING_API_KEY", "")
    if not key:
        return "Not configured", {"message": "No Safe Browsing API key has been configured."}
    payload = {"client": {"clientId": "cyberatlas-ai", "clientVersion": "0.3"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
    try:
        response = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find", params={"key": key}, json=payload, timeout=5, allow_redirects=False)
        response.raise_for_status()
        if response.status_code != 200:
            return "Unavailable", {"message": "The reputation service did not return a successful result."}
        data = response.json()
        if not isinstance(data, dict) or ("matches" in data and not isinstance(data["matches"], list)):
            return "Unavailable", {"message": "The reputation service returned an unexpected response."}
        matches = data.get("matches", [])
        if matches:
            return "Threat match", {"threat_types": sorted({item.get("threatType", "Unknown") for item in matches})}
        return "No known match", {"message": "No match in the queried Google lists; this is not a safety guarantee."}
    except (requests.RequestException, ValueError, TypeError, AttributeError):
        return "Unavailable", {"message": "The reputation service could not be checked."}
