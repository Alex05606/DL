from __future__ import annotations

import math
import re
from typing import Any
from urllib.parse import urlparse

import tldextract

_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), include_psl_private_domains=True
)

SUSPICIOUS_TLDS = {
    "bid", "buzz", "cf", "click", "club", "download", "ga", "gq", "icu",
    "info", "loan", "ml", "online", "top", "vip", "xyz",
}
SUSPICIOUS_KEYWORDS = {
    "account", "alert", "bank", "billing", "claim", "confirm", "invoice",
    "login", "payment", "password", "secure", "signin", "support", "update",
    "verify", "wallet",
}
BRAND_HINTS = {
    "amazon", "apple", "dropbox", "facebook", "github", "gmail", "google",
    "icloud", "meta", "microsoft", "netflix", "office365", "outlook", "paypal",
}


def parse_url(url: str) -> tuple[str, Any]:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string")
    value = url.strip()
    if not re.match(r"^https?://", value, re.IGNORECASE):
        value = "https://" + value
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
    except ValueError as exc:
        raise ValueError(f"Invalid URL: {exc}") from exc
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not hostname
        or any(character.isspace() or ord(character) < 32 for character in hostname)
    ):
        raise ValueError("URL must include a valid HTTP(S) hostname")
    return value, parsed


def registered_domain(url: str) -> str:
    _, parsed = parse_url(url)
    extracted = _EXTRACT(parsed.hostname or "")
    return extracted.top_domain_under_public_suffix.lower() or (parsed.hostname or "").lower()


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def extract_url_features(url: str) -> dict[str, Any]:
    normalized, parsed = parse_url(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    extracted = _EXTRACT(hostname)
    path = parsed.path or ""
    query = parsed.query or ""
    host_and_path = f"{hostname}{path}{query}".lower()
    domain = extracted.top_domain_under_public_suffix or extracted.domain or hostname
    suffix = extracted.suffix.lower()
    labels = hostname.split(".")
    registered_label = (extracted.domain or "").lower()

    return {
        "url": normalized,
        "url_length": len(normalized),
        "hostname_length": len(hostname),
        "registered_domain_length": len(domain),
        "path_length": len(path),
        "query_length": len(query),
        "subdomain_count": max(0, len(labels) - len((extracted.domain or "").split(".")) - len(suffix.split("."))),
        "digit_count": sum(character.isdigit() for character in host_and_path),
        "hyphen_count": host_and_path.count("-"),
        "underscore_count": host_and_path.count("_"),
        "dot_count": hostname.count("."),
        "slash_count": path.count("/"),
        "special_character_count": sum(character in "@%$&?=+~:#" for character in host_and_path),
        "ip_address_host": int(bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname))),
        "at_symbol": int("@" in normalized),
        "double_dot": int(".." in hostname),
        "https": int(parsed.scheme.lower() == "https"),
        "entropy": _entropy(host_and_path),
        "suspicious_tld": int(suffix.split(".")[-1] in SUSPICIOUS_TLDS if suffix else False),
        "suspicious_keyword_count": sum(keyword in host_and_path for keyword in SUSPICIOUS_KEYWORDS),
        "brand_hint_count": sum(brand in host_and_path for brand in BRAND_HINTS),
        "brand_matches_registered_domain": int(registered_label in BRAND_HINTS),
        "brand_in_mismatched_domain": int(
            any(brand in registered_label and registered_label != brand for brand in BRAND_HINTS)
        ),
        "digit_ratio": sum(character.isdigit() for character in hostname) / max(1, len(hostname)),
        "hostname_has_punycode": int("xn--" in hostname),
        "host_path_separator_count": sum(host_and_path.count(character) for character in "/-._"),
    }


def risk_indicators(url: str) -> list[str]:
    normalized, parsed = parse_url(url)
    hostname = (parsed.hostname or "").lower()
    extracted = _EXTRACT(hostname)
    suffix = extracted.suffix.lower()
    whole_url = normalized.lower()
    domain = extracted.top_domain_under_public_suffix.lower()
    indicators: list[str] = []

    if suffix and suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        indicators.append("suspicious top-level domain")
    if any(keyword in whole_url for keyword in SUSPICIOUS_KEYWORDS):
        indicators.append("credential- or payment-related keyword")
    if "@" in normalized:
        indicators.append("userinfo or @-symbol obfuscation")
    if len(normalized) > 100:
        indicators.append("unusually long URL")
    if any(brand in hostname for brand in BRAND_HINTS) and not any(
        domain == brand or domain.startswith(brand + ".") for brand in BRAND_HINTS
    ):
        indicators.append("brand name in a non-matching registered domain")
    if not indicators:
        indicators.append("no strong lexical indicators")
    return indicators
