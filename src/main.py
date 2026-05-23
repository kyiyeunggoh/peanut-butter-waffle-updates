from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import string
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, quote_plus, urljoin, urlparse, urlunparse

import feedparser
import requests
import yaml
from bs4 import BeautifulSoup
from dateutil import parser as date_parser
from dotenv import load_dotenv

try:
    from googlenewsdecoder import gnewsdecoder
except ImportError:
    gnewsdecoder = None


ROOT = Path(__file__).resolve().parents[1]
SOURCES_PATH = ROOT / "config" / "sources.yml"
SEEN_PATH = ROOT / "data" / "seen.json"
COST_LOG_PATH = ROOT / "data" / "cost_log.json"
URL_CACHE_PATH = ROOT / "data" / "url_cache.json"
QUALITY_CACHE_PATH = ROOT / "data" / "quality_cache.json"
CACHE_TTL_DAYS = 7
CACHE_MAX_ENTRIES = 5000
QUALITY_CACHE_VERSION = 3
DOMAIN_QUERY_TERMS = (
    "AI",
    "artificial intelligence",
    "deepfake",
    "fraud",
    "scam",
    "phishing",
    "misinformation",
    "cybercrime",
    "synthetic identity",
    "agentic AI",
)
GLOBAL_FALLBACK_QUERIES = (
    "deepfake",
    "AI fraud",
    "AI scam",
    "voice clone",
    "synthetic identity",
    "phishing AI",
    "AI misinformation",
    "AI cybercrime",
    "agentic AI abuse",
    "scam compound",
    "pig butchering",
    "romance scam AI",
)
SPECIFIC_PRODUCT_RADAR_QUERIES = (
    '"Victim as a Service" scammers',
    '"Designing a System for Engaging with Interactive Scammers"',
    "site:arxiv.org scam LLM fraud deepfake synthetic identity phishing",
    "site:arxiv.org AI scam detection social engineering agent abuse",
    "site:arxiv.org interactive scammers victim as a service",
    "site:arxiv.org watermarking reverse engineered synthetic media detection",
    "site:theverge.com AI watermarking deepfake reverse engineered",
    "site:techcrunch.com WhatsApp spam messaging limits fraud scams",
    "site:c4ads.org scam cyber fraud hotline trafficking Southeast Asia",
    "site:straitstimes.com Singapore scam Cambodia job seekers fraud",
    "site:channelnewsasia.com Singapore scam Cambodia fraud AI deepfake",
    "site:developers.cloudflare.com/changelog crawl endpoint browser rendering AI",
    "site:developers.cloudflare.com scam phishing abuse crawl endpoint",
    "site:security.googleblog.com AI abuse phishing fraud deepfake",
    "site:blog.whatsapp.com spam scams messaging limits",
    "site:about.fb.com scams fraud messaging limits",
)
ALLOWED_ARTICLE_TYPES = (
    "News report",
    "Enforcement report",
    "Investigative report",
    "Deep analysis",
    "Technical article",
    "Threat intelligence report",
    "Research paper",
    "Official report",
    "Policy / platform update",
    "Product / developer changelog",
    "Policy analysis",
    "Advisory / guidance",
    "Opinion / newsletter",
    "Vendor blog",
    "Other",
)
ALLOWED_USEFULNESS_CATEGORIES = (
    "Scam development",
    "Technical abuse / vulnerability",
    "Research / novel method",
    "Operational intelligence",
    "Platform policy / product change",
    "Local Singapore / Southeast Asia relevance",
    "Product idea / data source",
    "Detection / analytics / engineering insight",
    "General context",
)
ACCESS_NOTE = (
    "Access note: If a link has access issues, try the official source, "
    "author-hosted copy, institutional repository, arXiv/SSRN/OSF version, "
    "or reputable secondary coverage."
)
SCAM_KEYWORDS = (
    "abuse",
    "adversarial",
    "ai scam",
    "bot",
    "cyber",
    "deepfake",
    "fraud",
    "impersonation",
    "malware",
    "phishing",
    "prompt injection",
    "safety",
    "scam",
    "security",
    "synthetic media",
)
STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "has",
    "how",
    "in",
    "into",
    "is",
    "it",
    "its",
    "new",
    "of",
    "on",
    "or",
    "that",
    "the",
    "this",
    "to",
    "with",
    "why",
}
PAYWALL_PHRASES = (
    "subscribe to continue",
    "sign in to continue",
    "register to continue",
    "this article is for subscribers",
    "subscribe now",
)
SALES_PROMO_PHRASES = (
    "book a demo",
    "request a demo",
    "contact sales",
    "our platform",
    "our solution",
    "our customers",
    "learn how we can help",
    "schedule a consultation",
    "download our whitepaper",
    "sponsored",
    "partner content",
    "press release",
)
QUALITY_SIGNAL_TERMS = (
    "investigation",
    "investigative",
    "report",
    "research",
    "analysis",
    "threat intelligence",
    "technical",
    "study",
)
PRODUCT_TITLE_TERMS = (
    "launches",
    "announces",
    "partners with",
    "unveils",
    "introduces tool",
    "new product",
    "opens beta",
    "expanding",
    "expands",
    "platform",
    "solution",
)
INVESTIGATIVE_TERMS = (
    "inside",
    "investigation",
    "investigates",
    "exposed",
    "undercover",
    "around the world",
    "scam compound",
    "powering scams",
)
DEEP_ANALYSIS_TERMS = (
    "analysis",
    "lessons",
    "approach",
    "risks",
    "what it means",
    "policy",
)
TECHNICAL_THREAT_TERMS = (
    "threat actors",
    "threat actor",
    "cyber",
    "malware",
    "phishing",
    "infrastructure",
    "campaigns",
    "campaign",
    "intrusion",
    "intrusions",
    "rootkits",
    "rootkit",
    "scam kits",
    "scam kit",
)
ENFORCEMENT_TERMS = (
    "police",
    "interpol",
    "raid",
    "raids",
    "arrest",
    "arrested",
    "lawsuit",
    "lawsuits",
    "prosecution",
    "prosecuted",
    "charged",
    "seized",
)
RESEARCH_METHOD_TERMS = (
    "victim as a service",
    "interactive scammers",
    "detection",
    "dataset",
    "benchmark",
    "measurement",
    "system",
    "framework",
)
PRODUCT_DATA_SOURCE_TERMS = (
    "api",
    "crawl endpoint",
    "browser rendering",
    "changelog",
    "developer",
    "dataset",
    "data source",
    "webhook",
    "feed",
)
DIRECT_ANTI_SCAM_TERMS = (
    "scam",
    "scammer",
    "victim",
    "fraud victim",
    "monetary loss",
    "account takeover",
    "account take-over",
    "impersonation",
    "fake job",
    "fake recruiter",
    "fake officer",
    "fake investment",
    "romance scam",
    "investment scam",
    "pig butchering",
    "phishing kit",
    "scam kit",
    "smishing",
    "vishing",
    "voice cloning",
    "deepfake scam",
    "synthetic identity fraud",
    "money mule",
    "mule account",
    "sim box",
    "sim farm",
    "phone scam",
    "sms scam",
    "messaging scam",
    "whatsapp scam",
    "telegram scam",
    "social engineering",
    "grooming",
    "persuasion",
    "manipulation",
    "deception",
    "trust-building",
    "harmful persuasion",
    "fraud assistance",
    "scam compound",
    "scam farm",
    "call centre",
    "call center",
    "cyber slavery",
    "cambodia scam",
    "myanmar scam",
    "southeast asia scam",
    "fake website",
    "fake ad",
    "fake shopping site",
    "phishing site",
    "credential theft",
    "mule recruitment",
    "bank fraud",
    "payment fraud",
    "fraud ring",
    "fraud syndicate",
    "law enforcement disruption",
    "scam reporting",
    "scam detection",
    "scam intervention",
    "scam triage",
    "hotline",
    "hot lines",
    "interactive scammers",
    "victim as a service",
    "llm misuse",
    "ai-enabled fraud",
)
TECH_MODUS_TERMS = (
    "sim box",
    "voip abuse",
    "caller id spoofing",
    "robocall",
    "bulk messaging",
    "account warming",
    "fake accounts",
    "bot networks",
    "phishing kits",
    "scam kits",
    "credential harvesting",
    "mule networks",
    "payment rails",
    "crypto wallets",
    "fake domains",
    "domain generation",
    "website cloning",
    "ads abuse",
    "platform abuse",
    "reverse engineered",
    "watermarking",
    "messaging limits",
    "forwarding limits",
    "llm-generated scripts",
    "automated grooming",
    "fake persona generation",
    "deepfake video call",
    "voice clone",
    "synthetic identity",
    "identity verification bypass",
    "kyc bypass",
    "account takeover",
    "session hijacking",
    "otp theft",
    "mfa bypass",
    "scammer playbook",
    "modus operandi",
    "organised fraud",
    "organized fraud",
    "organised crime",
    "organized crime",
)
NEGATIVE_CONTEXT_TERMS = (
    "radiology",
    "medical imaging",
    "healthcare imaging",
    "hospital workflow",
    "clinical ai",
    "enterprise agentic ai security",
    "generic enterprise security",
    "generic ransomware",
    "generic malware",
    "generic rootkit",
    "generic network intrusion",
    "generic vulnerability management",
    "securities fraud",
    "quantum-classical fraud detection",
    "generic imbalanced fraud detection",
    "generic banking ai framework",
    "model benchmark unrelated",
)
RESEARCH_POSITIVE_TERMS = (
    "scam",
    "scammer",
    "fraud victim",
    "victim",
    "social engineering",
    "phishing",
    "smishing",
    "vishing",
    "impersonation",
    "romance scam",
    "investment scam",
    "pig butchering",
    "mule",
    "money mule",
    "synthetic identity",
    "deepfake scam",
    "voice clone",
    "fake recruiter",
    "fake job",
    "fake officer",
    "grooming",
    "persuasion",
    "manipulation",
    "deception",
    "trust-building",
    "harmful persuasion",
    "fraud assistance",
    "scam detection",
    "scam conversation",
    "interactive scammers",
    "victim as a service",
    "scam farm",
    "scam compound",
    "phishing kit",
    "scam kit",
    "llm misuse",
    "ai-enabled fraud",
)
RESEARCH_NEGATIVE_TERMS = (
    "enterprise security",
    "generic agentic security",
    "radiology",
    "medical imaging",
    "quantum-classical",
    "generic banking framework",
    "generic fraud detection",
    "imbalanced fraud detection",
    "generic cybersecurity",
    "malware only",
    "ransomware only",
    "rootkit only",
    "network intrusion only",
    "vulnerability management only",
)
RESEARCH_DIRECT_TITLE_TERMS = (
    "scam",
    "scammer",
    "victim as a service",
    "interactive scammers",
    "scam detection",
    "scam intervention",
    "scam triage",
    "scam conversation",
    "fraud victim",
    "social engineering",
    "phishing",
    "smishing",
    "vishing",
    "impersonation",
    "romance scam",
    "investment scam",
    "pig butchering",
    "money mule",
    "synthetic identity",
    "deepfake scam",
    "voice clone",
    "voice cloning",
    "fake recruiter",
    "fake job",
    "fake officer",
    "grooming",
    "harmful persuasion",
    "fraud assistance",
    "scam farm",
    "scam compound",
    "phishing kit",
    "scam kit",
    "llm misuse",
    "ai-enabled fraud",
    "account takeover",
    "bank fraud",
    "payment fraud",
    "deanonymization",
    "de-anonymization",
    "identity verification bypass",
    "kyc bypass",
)
STRONG_SCAM_ANCHOR_TERMS = (
    "scam",
    "scammer",
    "fraud victim",
    "monetary loss",
    "account takeover",
    "account take-over",
    "impersonation scam",
    "fake job",
    "fake recruiter",
    "fake officer",
    "fake investment",
    "romance scam",
    "investment scam",
    "pig butchering",
    "smishing",
    "vishing",
    "money mule",
    "mule account",
    "sim box",
    "sim farm",
    "phone scam",
    "sms scam",
    "messaging scam",
    "whatsapp scam",
    "telegram scam",
    "scam compound",
    "scam farm",
    "call centre scam",
    "call center scam",
    "cyber slavery",
    "cambodia scam",
    "myanmar scam",
    "southeast asia scam",
    "fake shopping site",
    "phishing site",
    "credential theft linked to fraud",
    "bank fraud",
    "payment fraud",
    "fraud ring",
    "fraud syndicate",
    "scam detection",
    "scam intervention",
    "scam triage",
    "interactive scammers",
    "victim as a service",
    "ai-enabled fraud",
    "deepfake scam",
    "voice cloning scam",
    "synthetic identity fraud",
    "scam kit",
    "phishing kit",
)
WEAK_GENERIC_TERMS = (
    "victim",
    "manipulation",
    "deception",
    "phishing",
    "prompt injection",
    "watermarking",
    "cybersecurity",
    "vulnerability",
    "malware",
    "ransomware",
    "ai abuse",
    "cybercrime",
    "fraud",
    "identity",
    "trust",
)
PRODUCT_LAUNCH_TERMS = (
    "launches",
    "unveils",
    "introduces",
    "opens beta",
    "announces",
    "partners with",
    "new tool",
    "new platform",
)
LOCAL_SEA_TERMS = (
    "singapore",
    "southeast asia",
    "south-east asia",
    "cambodia",
    "myanmar",
    "malaysia",
    "thailand",
    "vietnam",
    "philippines",
    "indonesia",
    "asia",
)
LOW_SIGNAL_ENTERTAINMENT_TERMS = (
    "south park",
    "kimmel",
    "trump penis",
    "premiere date",
    "hollywood",
)
TECHNICAL_TYPES = {"Technical article", "Threat intelligence report", "Official report", "Research paper"}
DEEP_ANALYSIS_TYPES = {"Deep analysis", "Investigative report", "Research paper", "Policy analysis"}
PLATFORM_PRODUCT_TYPES = {"Policy / platform update", "Product / developer changelog"}
DEEP_ANALYSIS_SOURCE_HINTS = (
    "wired.com",
    "datasociety.net",
    "cetas.turing.ac.uk",
    "technologyreview.com",
    "bellingcat.com",
    "graphika.com",
)
INTRO_LINES = (
    "Signals worth turning into product decisions.",
    "Adversarial intelligence for scam detection, abuse ops, and product strategy.",
    "Research, platform shifts, and scam infrastructure signals to watch.",
)
CLOSING_LINES = (
    "Use the signal, ignore the noise.",
    "Prioritised for product relevance, not general newsworthiness.",
    "Keep the loop tight between intelligence, detection, and enforcement.",
)
SECTION_ORDER = (
    "🇸🇬 Singapore / Southeast Asia",
    "🧨 Scam trends",
    "🕵️ Investigations & operational intelligence",
    "🧬 Deepfakes, synthetic identity & impersonation",
    "🛠️ Technical abuse & vulnerabilities",
    "📚 Research & novel methods",
    "📱 Platform, telco & bank controls",
    "🧠 Victim psychology & persuasion",
    "🧰 Product ideas & data sources",
    "🚨 Advisories & enforcement",
)


def load_config() -> dict[str, Any]:
    with SOURCES_PATH.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def load_sources(config: dict[str, Any]) -> list[dict[str, Any]]:
    return [source for source in config.get("sources", []) if source.get("enabled", True)]


def empty_seen() -> dict[str, dict[str, Any]]:
    return {"urls": {}, "titles": {}}


def load_seen() -> dict[str, dict[str, Any]]:
    if not SEEN_PATH.exists():
        return empty_seen()

    with SEEN_PATH.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        return empty_seen()

    if "urls" in data or "titles" in data:
        return {
            "urls": data.get("urls", {}) if isinstance(data.get("urls"), dict) else {},
            "titles": data.get("titles", {}) if isinstance(data.get("titles"), dict) else {},
        }

    migrated = empty_seen()
    for item_hash in data.get("items", []):
        migrated["urls"][item_hash] = {
            "url": "",
            "title": "",
            "sent_at": "",
            "article_type": "Other",
        }
    return migrated


def load_cache(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def save_cache(path: Path, data: dict[str, Any]) -> None:
    trimmed_items = sorted(
        data.items(),
        key=lambda item: item[1].get("resolved_at") or item[1].get("checked_at") or "",
        reverse=True,
    )[:CACHE_MAX_ENTRIES]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(dict(trimmed_items), file, indent=2, sort_keys=True)
        file.write("\n")


def cache_record_fresh(record: dict[str, Any], time_key: str) -> bool:
    timestamp = record.get(time_key)
    if not timestamp:
        return False
    try:
        recorded_at = date_parser.parse(timestamp)
    except (TypeError, ValueError, OverflowError):
        return False
    if recorded_at.tzinfo is None:
        recorded_at = recorded_at.replace(tzinfo=timezone.utc)
    return recorded_at.astimezone(timezone.utc) >= datetime.now(timezone.utc) - timedelta(days=CACHE_TTL_DAYS)


def save_seen(seen: dict[str, dict[str, Any]]) -> None:
    SEEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    with SEEN_PATH.open("w", encoding="utf-8") as file:
        json.dump(seen, file, indent=2, sort_keys=True)
        file.write("\n")


def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonicalize_url_text(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower() or "https"
    hostname = (parsed.hostname or "").lower().removeprefix("www.")
    path = parsed.path.rstrip("/")
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    filtered_query = {
        key: values
        for key, values in query_params.items()
        if not key.lower().startswith("utm_") and key.lower() not in {"fbclid", "gclid", "oc"}
    }
    query = "&".join(
        f"{quote_plus(key)}={quote_plus(value)}"
        for key in sorted(filtered_query)
        for value in filtered_query[key]
    )
    return urlunparse((scheme, hostname, path, "", query, ""))


def url_hash(url: str) -> str:
    return stable_hash(canonicalize_url_text(url))


def google_news_rss_url(query: str) -> str:
    encoded_query = quote_plus(query)
    return f"https://news.google.com/rss/search?q={encoded_query}&hl=en-US&gl=US&ceid=US:en"


def source_domain(source: dict[str, Any]) -> str | None:
    if source.get("domain"):
        return str(source["domain"]).removeprefix("www.")

    url = source.get("url")
    if not url:
        return None

    hostname = urlparse(str(url)).hostname
    if not hostname:
        return None
    return hostname.removeprefix("www.")


def build_rss_queries(sources: list[dict[str, Any]]) -> list[dict[str, str]]:
    queries: list[dict[str, str]] = []

    for query in SPECIFIC_PRODUCT_RADAR_QUERIES:
        queries.append(
            {
                "name": "Google News",
                "query": query,
                "url": google_news_rss_url(query),
                "priority": "watchlist",
            }
        )

    for source in sources:
        domain = source_domain(source)
        if domain:
            for term in DOMAIN_QUERY_TERMS:
                query = f"site:{domain} {term}"
                queries.append(
                    {
                        "name": source.get("name", domain),
                        "query": query,
                        "url": google_news_rss_url(query),
                        "priority": "source",
                    }
                )
        elif source.get("url"):
            queries.append(
                {
                    "name": source.get("name", source["url"]),
                    "query": source["url"],
                    "url": source["url"],
                    "priority": "feed",
                }
            )

    for query in GLOBAL_FALLBACK_QUERIES:
        queries.append(
            {
                "name": "Google News",
                "query": query,
                "url": google_news_rss_url(query),
                "priority": "fallback",
            }
        )

    return queries


def entry_datetime(entry: Any) -> datetime | None:
    for parsed_key in ("published_parsed", "updated_parsed"):
        parsed_value = entry.get(parsed_key)
        if parsed_value:
            return datetime(*parsed_value[:6], tzinfo=timezone.utc)

    for text_key in ("published", "updated"):
        text_value = entry.get(text_key)
        if not text_value:
            continue
        try:
            parsed_datetime = date_parser.parse(text_value)
        except (TypeError, ValueError, OverflowError):
            continue
        if parsed_datetime.tzinfo is None:
            return parsed_datetime.replace(tzinfo=timezone.utc)
        return parsed_datetime.astimezone(timezone.utc)

    return None


def parsed_date_text(item: dict[str, Any]) -> str:
    parsed_date = item.get("parsed_date")
    if isinstance(parsed_date, datetime):
        return parsed_date.strftime("%Y-%m-%d")
    return "missing"


def is_within_lookback(
    entry: Any,
    lookback_days: int,
    max_article_age_days: int,
    now: datetime,
    debug: bool,
) -> bool:
    published_at = entry_datetime(entry)
    if published_at is None:
        return debug

    max_age = min(lookback_days, max_article_age_days)
    return published_at >= now - timedelta(days=max_age)


def parse_feed(url: str, timeout_seconds: int = 30) -> Any:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; AI-Abuse-Radar-Bot/1.0; "
            "+https://github.com/actions)"
        )
    }
    response = requests.get(url, headers=headers, timeout=timeout_seconds)
    response.raise_for_status()
    return feedparser.parse(response.content)


def strip_publisher_suffix(title: str) -> str:
    separators = (" - ", " | ", " – ", " — ")
    cleaned = title.strip()
    for separator in separators:
        if separator in cleaned:
            left, right = cleaned.rsplit(separator, 1)
            if 1 <= len(right.split()) <= 6:
                return left.strip()
    return cleaned


def title_fingerprint(title: str) -> str:
    words = normalised_title(title).split()
    return " ".join(words[:14])


def normalised_title(title: str) -> str:
    stripped = strip_publisher_suffix(title).lower()
    translator = str.maketrans({char: " " for char in string.punctuation})
    words = stripped.translate(translator).split()
    meaningful_words = [word for word in words if word not in STOPWORDS]
    return " ".join(meaningful_words)


def fingerprints_similar(left: str, right: str) -> bool:
    if not left or not right:
        return False
    if left == right:
        return True
    left_words = set(left.split())
    right_words = set(right.split())
    if not left_words or not right_words:
        return False
    overlap = len(left_words & right_words) / len(left_words | right_words)
    return overlap >= 0.86


def article_domain(item: dict[str, Any]) -> str:
    url = item.get("canonical_url") or item.get("url") or item.get("original_url") or item.get("link", "")
    return (urlparse(url).hostname or "").lower().removeprefix("www.")


def suggests_product_announcement(text: str) -> bool:
    direct_terms = ("launches", "announces", "partners with", "unveils", "introduces tool", "new product", "opens beta")
    if any(term in text for term in direct_terms):
        return True
    if any(term in text for term in ("expanding", "expands")) and any(
        term in text for term in ("detection", "deepfake", "spam", "scam", "fraud", "abuse", "messaging")
    ):
        return True
    return any(term in text for term in ("platform", "solution")) and any(
        term in text for term in ("launch", "announce", "unveil", "introduce", "demo", "sales")
    )


def classify_article_type(item: dict[str, Any]) -> str:
    domain = article_domain(item)
    source = item.get("source", "").lower()
    title = item.get("title", "").lower()
    haystack = f"{title} {source}"

    if any(domain.endswith(host) for host in ("developers.cloudflare.com", "cloudflare.com")) and any(
        term in haystack for term in PRODUCT_DATA_SOURCE_TERMS
    ):
        return "Product / developer changelog"

    if suggests_product_announcement(haystack):
        if any(term in haystack for term in ("limit", "limits", "spam", "scam", "fraud", "deepfake", "abuse", "detection")):
            return "Policy / platform update"
        return "Vendor blog"

    if any(domain.endswith(host) for host in ("arxiv.org", "dl.acm.org", "ieee.org", "usenix.org", "ndss-symposium.org", "ssrn.com", "osf.io")):
        return "Research paper"

    if any(domain.endswith(host) for host in ("anthropic.com", "openai.com", "cloud.google.com", "mandiant.com", "microsoft.com", "mandiant.com")):
        if any(term in haystack for term in TECHNICAL_THREAT_TERMS) or any(term in haystack for term in ("threat", "actor", "misuse", "fraud", "scam")):
            return "Threat intelligence report"

    if any(domain.endswith(host) for host in ("cisa.gov", "nist.gov", "fbi.gov", "ic3.gov", "interpol.int", "europol.europa.eu", "aisi.gov.uk")):
        if any(term in haystack for term in ("advisory", "guidance", "alert", "warning", "tips")):
            return "Advisory / guidance"
        if any(term in haystack for term in ENFORCEMENT_TERMS):
            return "Enforcement report"
        return "Official report"

    if any(domain.endswith(host) for host in ("police.gov.sg", "gov.sg", "csa.gov.sg", "mas.gov.sg", "imda.gov.sg")):
        if any(term in haystack for term in ("advisory", "guidance", "alert", "warning", "tips")):
            return "Advisory / guidance"
        if any(term in haystack for term in ENFORCEMENT_TERMS):
            return "Enforcement report"
        return "Official report"

    if any(domain.endswith(host) for host in ("meta.com", "about.fb.com", "whatsapp.com", "blog.whatsapp.com", "telegram.org", "signal.org", "apple.com", "blog.google", "deepmind.google")):
        if any(term in haystack for term in ("limit", "limits", "spam", "scam", "fraud", "abuse", "deepfake", "synthetic", "messaging")):
            return "Policy / platform update"

    if any(domain.endswith(host) for host in ("wired.com", "404media.co", "restofworld.org", "bellingcat.com", "graphika.com")):
        if any(term in haystack for term in INVESTIGATIVE_TERMS):
            return "Investigative report"

    if any(domain.endswith(host) for host in ("wired.com", "technologyreview.com", "datasociety.net", "cetas.turing.ac.uk", "hai.stanford.edu", "fulcrum.sg", "c4ads.org")):
        if any(term in haystack for term in DEEP_ANALYSIS_TERMS):
            if any(term in haystack for term in ("policy", "regulation", "governance", "law")):
                return "Policy analysis"
            return "Deep analysis"

    if any(term in haystack for term in ("reverse engineered", "vulnerability", "exploit", "bypass", "watermarking", "prompt injection")):
        return "Technical article"

    if any(domain.endswith(host) for host in ("c4ads.org", "bellingcat.com", "graphika.com", "restofworld.org", "404media.co")):
        if any(term in haystack for term in ("hotline", "hot line", "network", "operation", "infrastructure", "trafficking", "compound")):
            return "Investigative report"

    if any(term in haystack for term in ENFORCEMENT_TERMS):
        mechanism_terms = ("malware", "phishing kit", "rootkit", "exploit", "vulnerability", "infrastructure", "botnet")
        if not any(term in haystack for term in mechanism_terms):
            return "Enforcement report"

    if any(domain.endswith(host) for host in ("therecord.media", "krebsonsecurity.com", "thehackernews.com", "mandiant.com", "cloud.google.com", "microsoft.com", "anthropic.com", "openai.com", "security.googleblog.com")):
        if any(term in haystack for term in TECHNICAL_THREAT_TERMS):
            if any(domain.endswith(host) for host in ("mandiant.com", "cloud.google.com", "microsoft.com", "anthropic.com", "openai.com")):
                return "Threat intelligence report"
            return "Technical article"

    if any(term in haystack for term in ENFORCEMENT_TERMS):
        return "Enforcement report"

    if any(domain.endswith(host) for host in ("wired.com", "reuters.com", "ft.com", "theguardian.com", "bbc.com", "therecord.media", "restofworld.org", "404media.co")):
        return "News report"

    if any(domain.endswith(host) for host in ("datasociety.net", "cetas.turing.ac.uk", "graphika.com", "bellingcat.com", "technologyreview.com", "hai.stanford.edu")):
        if any(term in haystack for term in ("policy", "regulation", "governance", "law")):
            return "Policy analysis"
        return "Deep analysis"

    if any(domain.endswith(host) for host in ("medium.com", "substack.com", "platformer.news")):
        return "Opinion / newsletter"

    if any(name in haystack or domain.endswith(name) for name in ("help net security", "malwarebytes", "securitybrief", "cybersecurity insiders")):
        if any(term in haystack for term in ("how to", "guide", "tips", "explainer")):
            return "Technical article"
        return "Vendor blog"

    if any(marker in haystack for marker in (" arxiv", "- arxiv", "[260", "[250", " ssrn", " acm ", " ieee ", " usenix ", " ndss ")):
        return "Research paper"
    if any(term in haystack for term in ("advisory", "guidance", "guide", "how to")):
        return "Advisory / guidance"
    if any(term in haystack for term in ("analysis", "deep dive", "explained", "study")):
        return "Deep analysis"

    return "News report"


def classify_usefulness_category(item: dict[str, Any]) -> str:
    domain = article_domain(item)
    title = item.get("title", "").lower()
    source = item.get("source", "").lower()
    article_type = item.get("article_type", classify_article_type(item))
    haystack = f"{title} {source} {domain}"

    if any(term in haystack for term in ("victim as a service", "interactive scammers")):
        return "Research / novel method"
    if article_type == "Research paper":
        if any(term in haystack for term in PRODUCT_DATA_SOURCE_TERMS + RESEARCH_METHOD_TERMS):
            return "Product idea / data source"
        return "Research / novel method"
    if article_type in PLATFORM_PRODUCT_TYPES:
        if any(term in haystack for term in PRODUCT_DATA_SOURCE_TERMS):
            return "Product idea / data source"
        return "Platform policy / product change"
    if any(term in haystack for term in ("reverse engineered", "vulnerability", "exploit", "bypass", "watermarking", "prompt injection", "rootkit", "scam kit", "attack tooling")):
        return "Technical abuse / vulnerability"
    if any(term in haystack for term in PRODUCT_DATA_SOURCE_TERMS):
        return "Product idea / data source"
    if article_type in {"Technical article", "Threat intelligence report"}:
        return "Detection / analytics / engineering insight"
    if any(term in haystack for term in ("hotline", "hot line", "compound", "trafficking", "infrastructure", "operation", "network", "call routing")):
        return "Operational intelligence"
    if any(term in haystack for term in LOCAL_SEA_TERMS):
        return "Local Singapore / Southeast Asia relevance"
    if article_type in {"Investigative report", "Deep analysis", "Policy analysis"}:
        return "Operational intelligence"
    if article_type == "Enforcement report" or any(term in haystack for term in ("scam", "fraud", "deepfake", "phishing", "misinformation")):
        return "Scam development"
    return "General context"


def terms_found(text: str, terms: tuple[str, ...]) -> list[str]:
    lowered = text.lower()
    return [term for term in terms if term in lowered]


def candidate_relevance_text(candidate: dict[str, Any], extra_text: str = "") -> str:
    return " ".join(
        str(value)
        for value in (
            candidate.get("title", ""),
            candidate.get("source", ""),
            candidate.get("summary", ""),
            article_domain(candidate),
            extra_text,
        )
        if value
    ).lower()


def classify_research_relevance(candidate: dict[str, Any], text: str) -> tuple[str | None, int | None]:
    article_type = candidate.get("article_type", classify_article_type(candidate))
    if article_type not in {"Research paper", "Technical article", "Threat intelligence report"}:
        return None, None

    direct_terms = terms_found(text, RESEARCH_POSITIVE_TERMS)
    negative_terms = terms_found(text, RESEARCH_NEGATIVE_TERMS)
    has_scam_context = any(
        term in text
        for term in (
            "scam",
            "victim",
            "social engineering",
            "phishing",
            "smishing",
            "vishing",
            "impersonation",
            "harmful persuasion",
        )
    )
    if direct_terms and set(direct_terms).issubset({"persuasion", "manipulation", "deception"}) and not has_scam_context:
        direct_terms = []

    if any(term in text for term in ("victim as a service", "interactive scammers", "scam conversation")):
        return "direct_scam_relevance", 60
    scam_psych_context = has_scam_context
    if any(term in text for term in ("grooming", "trust-building", "harmful persuasion", "victimology")) or (
        scam_psych_context and any(term in text for term in ("persuasion", "manipulation", "deception"))
    ):
        return "victim_psychology_or_persuasion", 60
    if any(term in text for term in ("benchmark", "evaluation", "eval")) and any(
        term in text for term in ("fraud", "scam", "phishing", "social engineering", "harmful persuasion", "deception")
    ):
        return "llm_adverse_use_benchmark", 55
    if any(term in text for term in ("scam detection", "scam intervention", "scam triage", "fraud detection", "phishing detection")) and direct_terms:
        return "scam_detection_or_intervention", 55
    if any(term in text for term in ("deepfake scam", "voice clone", "voice cloning", "synthetic identity", "impersonation")):
        return "deepfake_or_synthetic_identity_scam", 50
    if any(term in text for term in ("whatsapp", "telegram", "sms", "smishing", "vishing", "messaging", "fake accounts", "platform abuse")) and direct_terms:
        return "platform_or_messaging_abuse", 45
    if any(term in text for term in ("reverse engineered", "vulnerability", "exploit", "bypass", "watermarking")):
        return "direct_scam_relevance", 50
    if direct_terms:
        return "direct_scam_relevance", 60
    if any(term in text for term in ("imbalanced fraud detection", "quantum-classical", "fraud detection", "banking ai framework")):
        return "generic_fraud_ml", -35
    if any(term in text for term in ("enterprise security", "agentic detection system", "agentic ai security", "prompt injection", "malware", "ransomware", "rootkit", "network intrusion")):
        return "generic_cybersecurity", -35
    if any(term in text for term in ("ai security", "model safety", "agentic security")) or negative_terms:
        return "generic_ai_security", -40
    return "irrelevant_or_adjacent", -60


def relevance_fields(candidate: dict[str, Any], extra_text: str = "") -> dict[str, Any]:
    text = candidate_relevance_text(candidate, extra_text)
    title_context_text = candidate_relevance_text(candidate)
    strong_terms = terms_found(text, STRONG_SCAM_ANCHOR_TERMS)
    title_strong_terms = terms_found(title_context_text, STRONG_SCAM_ANCHOR_TERMS)
    weak_terms = terms_found(text, WEAK_GENERIC_TERMS)
    broad_psych_terms = {"persuasion", "manipulation", "deception"}
    has_scam_context = any(
        term in text
        for term in (
            "scam",
            "fraud",
            "victim",
            "social engineering",
            "phishing",
            "smishing",
            "vishing",
            "impersonation",
            "harmful persuasion",
        )
    )
    tech_terms = terms_found(text, TECH_MODUS_TERMS)
    negative_terms = terms_found(text, NEGATIVE_CONTEXT_TERMS)
    product_launch_terms = terms_found(text, PRODUCT_LAUNCH_TERMS)
    article_type = candidate.get("article_type", classify_article_type(candidate))
    usefulness_category = candidate.get("usefulness_category", classify_usefulness_category(candidate))
    domain = article_domain(candidate)
    scam_context_terms = [
        term
        for term in weak_terms
        if term in {"fraud", "phishing", "identity", "victim", "cybercrime"}
    ]
    scam_operation_terms = [
        term
        for term in tech_terms
        if term
        in {
            "sim box",
            "voip abuse",
            "caller id spoofing",
            "robocall",
            "bulk messaging",
            "account warming",
            "fake accounts",
            "phishing kits",
            "scam kits",
            "credential harvesting",
            "mule networks",
            "payment rails",
            "crypto wallets",
            "fake domains",
            "website cloning",
            "ads abuse",
            "platform abuse",
            "messaging limits",
            "forwarding limits",
            "llm-generated scripts",
            "automated grooming",
            "fake persona generation",
            "deepfake video call",
            "voice clone",
            "synthetic identity",
            "identity verification bypass",
            "kyc bypass",
            "account takeover",
            "otp theft",
            "scammer playbook",
            "modus operandi",
            "organised fraud",
            "organized fraud",
            "organised crime",
            "organized crime",
        }
    ]

    research_category, research_score = classify_research_relevance(candidate, text)
    hard_rejected = False
    rejection_reason = None
    if negative_terms and not strong_terms:
        anti_scam_relevance = "irrelevant"
        hard_rejected = True
        if any(term in negative_terms for term in ("radiology", "medical imaging", "healthcare imaging", "hospital workflow", "clinical ai")):
            rejection_reason = "generic_healthcare_ai_cyber"
        elif any("securities fraud" in term for term in negative_terms):
            rejection_reason = "generic_securities_fraud"
        elif any("enterprise" in term for term in negative_terms):
            rejection_reason = "generic_enterprise_security"
        else:
            rejection_reason = "negative_domain_context_no_scam_anchor"
    elif product_launch_terms and article_type == "Vendor blog" and not strong_terms:
        anti_scam_relevance = "irrelevant"
        hard_rejected = True
        rejection_reason = "vendor_product_launch_no_scam_anchor"
    elif strong_terms:
        anti_scam_relevance = "direct"
    elif len(scam_context_terms) >= 2 and scam_operation_terms:
        anti_scam_relevance = "direct"
    elif any(domain.endswith(host) for host in ("police.gov.sg", "gov.sg", "csa.gov.sg", "mas.gov.sg", "imda.gov.sg", "fbi.gov", "ic3.gov", "interpol.int", "europol.europa.eu")) and any(
        term in text for term in ("scam", "fraud advisory", "scam prevention", "scam enforcement", "victim protection")
    ):
        anti_scam_relevance = "direct"
    elif usefulness_category in {
        "Product idea / data source",
        "Platform policy / product change",
        "Detection / analytics / engineering insight",
        "Technical abuse / vulnerability",
        "Operational intelligence",
    } and tech_terms:
        anti_scam_relevance = "adjacent"
    elif article_type in {"Research paper", "Technical article", "Threat intelligence report"}:
        anti_scam_relevance = "weak"
    elif any(term in text for term in ("fraud", "cybercrime", "platform abuse", "identity", "ai misuse", "misinformation")):
        anti_scam_relevance = "adjacent"
    else:
        anti_scam_relevance = "weak"
        if weak_terms and not strong_terms:
            rejection_reason = "weak_generic_only_no_scam_anchor"

    downrank_reasons: list[str] = []
    if negative_terms:
        downrank_reasons.append("negative_domain_context")
    if anti_scam_relevance == "weak":
        downrank_reasons.append("weak_anti_scam_relevance")
    if research_category in {"generic_fraud_ml", "generic_cybersecurity", "generic_ai_security", "irrelevant_or_adjacent"}:
        downrank_reasons.append(research_category)

    return {
        "anti_scam_relevance": anti_scam_relevance,
        "strong_scam_anchor_terms_found": strong_terms[:12],
        "title_scam_anchor_terms_found": title_strong_terms[:12],
        "weak_generic_terms_found": weak_terms[:12],
        "direct_relevance_terms_found": strong_terms[:12],
        "technology_modus_terms_found": tech_terms[:12],
        "direct_scam_relevance_terms_found": [term for term in strong_terms if term in RESEARCH_POSITIVE_TERMS or term in STRONG_SCAM_ANCHOR_TERMS][:12],
        "research_relevance_category": research_category,
        "research_relevance_score": research_score,
        "downrank_reason": ", ".join(downrank_reasons) if downrank_reasons else None,
        "hard_rejected": hard_rejected,
        "hard_rejection_reason": rejection_reason,
    }


def quality_config(config: dict[str, Any]) -> dict[str, Any]:
    defaults = {
        "min_word_count_default": 600,
        "min_word_count_research_or_report": 800,
        "min_word_count_news": 400,
        "inspect_top_n_candidates": 40,
        "max_vendor_blog_items_final": 1,
        "require_at_least_one_technical": True,
        "require_at_least_one_deep_analysis": True,
    }
    defaults.update(config.get("quality_filters", {}) or {})
    return defaults


def source_tokens_for_matching(candidate: dict[str, Any]) -> tuple[str, str]:
    domain = article_domain(candidate)
    source = str(candidate.get("source", "")).lower()
    return domain, source


def matches_source_bucket(candidate: dict[str, Any], patterns: list[str]) -> bool:
    domain, source = source_tokens_for_matching(candidate)
    for raw_pattern in patterns:
        pattern = str(raw_pattern).lower().removeprefix("www.")
        if not pattern:
            continue
        if domain == pattern or domain.endswith(f".{pattern}") or pattern in domain:
            return True
        if pattern in source:
            return True
    return False


def source_reputation(candidate: dict[str, Any], config: dict[str, Any]) -> str:
    if matches_source_bucket(candidate, config.get("high_reputation_sources", []) or []):
        return "high"
    if matches_source_bucket(candidate, config.get("vendor_or_low_priority_sources", []) or []):
        return "low"
    return "medium"


def is_high_reputation_source(candidate: dict[str, Any], config: dict[str, Any]) -> bool:
    return source_reputation(candidate, config) == "high"


def is_vendor_or_low_priority_source(candidate: dict[str, Any], config: dict[str, Any]) -> bool:
    return source_reputation(candidate, config) == "low"


def visible_text_from_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for element in soup(["script", "style", "nav", "footer", "header", "aside", "noscript"]):
        element.decompose()

    blocks = soup.find_all(["article", "main", "p", "h1", "h2", "h3"])
    if not blocks and soup.body:
        blocks = [soup.body]

    return " ".join(block.get_text(" ", strip=True) for block in blocks)


def estimate_word_count(text: str) -> int:
    return len(re.findall(r"\b[\w'-]+\b", text))


def inspect_article_quality(
    candidate: dict[str, Any],
    config: dict[str, Any],
    quality_cache: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = candidate.get("canonical_url") or candidate.get("url") or ""
    quality_data: dict[str, Any] = {
        "word_count": None,
        "quality_checked": False,
        "access_status": "unknown",
        "salesy_vendor_pitch": False,
        "press_release_or_sponsored": False,
        "rejection_reason": None,
    }
    cache_key = url_hash(url) if url else ""
    cached = (quality_cache or {}).get(cache_key)
    if cached and cached.get("cache_version") == QUALITY_CACHE_VERSION and cache_record_fresh(cached, "checked_at"):
        cached_data = dict(cached)
        cached_data.pop("checked_at", None)
        cached_data.pop("cache_version", None)
        return cached_data

    if not url.startswith(("http://", "https://")) or is_google_news_url(url):
        quality_data["rejection_reason"] = "unresolved_google_news_url" if is_google_news_url(url) else "invalid_url"
        quality_data.update(relevance_fields(candidate))
        if quality_cache is not None and cache_key:
            quality_cache[cache_key] = {
                **quality_data,
                "cache_version": QUALITY_CACHE_VERSION,
                "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        return quality_data

    try:
        timeout_seconds = int(config.get("request_timeout_seconds", 8))
        response = requests.get(url, timeout=timeout_seconds, headers={"User-Agent": "Mozilla/5.0"})
        response.raise_for_status()
    except requests.Timeout:
        quality_data["rejection_reason"] = "fetch_timeout"
        quality_data.update(relevance_fields(candidate))
        if quality_cache is not None and cache_key:
            quality_cache[cache_key] = {
                **quality_data,
                "cache_version": QUALITY_CACHE_VERSION,
                "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        return quality_data
    except requests.RequestException:
        quality_data["rejection_reason"] = "fetch_failed"
        quality_data.update(relevance_fields(candidate))
        if quality_cache is not None and cache_key:
            quality_cache[cache_key] = {
                **quality_data,
                "cache_version": QUALITY_CACHE_VERSION,
                "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        return quality_data

    visible_text = visible_text_from_html(response.text)
    text_for_signals = f"{candidate.get('title', '')} {candidate.get('source', '')} {visible_text}".lower()
    quality_data["word_count"] = estimate_word_count(visible_text)
    quality_data["quality_checked"] = True
    quality_data["access_status"] = (
        "paywalled_or_login"
        if any(phrase in text_for_signals for phrase in PAYWALL_PHRASES)
        else "available"
    )

    sales_signal_count = sum(1 for phrase in SALES_PROMO_PHRASES if phrase in text_for_signals)
    quality_data["press_release_or_sponsored"] = any(
        phrase in text_for_signals for phrase in ("press release", "sponsored", "partner content")
    )
    if sales_signal_count >= 2 and not is_high_reputation_source(candidate, config):
        quality_data["salesy_vendor_pitch"] = True

    quality_data.update(relevance_fields(candidate, visible_text))
    if quality_cache is not None and cache_key:
        quality_cache[cache_key] = {
            **quality_data,
            "cache_version": QUALITY_CACHE_VERSION,
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
    return quality_data


def compute_quality_score(candidate: dict[str, Any], config: dict[str, Any]) -> int:
    now = datetime.now(timezone.utc)
    quality_score = int(candidate.get("original_score", score_item(candidate, now)))
    article_type = candidate.get("article_type", classify_article_type(candidate))
    usefulness_category = candidate.get("usefulness_category") or classify_usefulness_category(candidate)
    anti_scam_relevance = candidate.get("anti_scam_relevance", "weak")
    research_category = candidate.get("research_relevance_category")
    research_score = candidate.get("research_relevance_score")
    word_count = candidate.get("word_count")
    reputation = source_reputation(candidate, config)
    haystack = f"{candidate.get('title', '')} {candidate.get('source', '')}".lower()
    domain = article_domain(candidate)

    usefulness_boosts = {
        "Research / novel method": 55,
        "Product idea / data source": 50,
        "Technical abuse / vulnerability": 50,
        "Operational intelligence": 45,
        "Detection / analytics / engineering insight": 45,
        "Platform policy / product change": 40,
        "Local Singapore / Southeast Asia relevance": 40,
        "Scam development": 35,
        "General context": 15,
    }
    quality_score += usefulness_boosts.get(usefulness_category, 15)
    if anti_scam_relevance == "direct":
        quality_score += 60
    elif anti_scam_relevance == "adjacent":
        quality_score += 10
    elif anti_scam_relevance == "weak":
        quality_score -= 70

    if isinstance(research_score, int):
        quality_score += research_score

    has_scam_anchor = bool(candidate.get("strong_scam_anchor_terms_found"))
    if has_scam_anchor and candidate.get("technology_modus_terms_found"):
        quality_score += 35
    if has_scam_anchor and any(term in candidate.get("weak_generic_terms_found", []) + candidate.get("direct_relevance_terms_found", []) for term in ("persuasion", "grooming", "trust-building", "manipulation", "deception", "harmful persuasion")):
        quality_score += 40
    if has_scam_anchor and any(term in candidate.get("technology_modus_terms_found", []) for term in ("sim box", "mule networks", "phishing kits", "scam kits", "platform abuse", "fake accounts", "bulk messaging")):
        quality_score += 45
    if anti_scam_relevance == "direct" and usefulness_category == "Local Singapore / Southeast Asia relevance":
        quality_score += 45
    if usefulness_category == "Platform policy / product change" and anti_scam_relevance == "direct":
        quality_score += 40
    if usefulness_category == "Product idea / data source" and anti_scam_relevance == "direct":
        quality_score += 40

    if any(domain.endswith(host) for host in ("arxiv.org", "dl.acm.org", "ieee.org", "usenix.org", "ndss-symposium.org", "ssrn.com", "osf.io")):
        quality_score += 40
    elif any(domain.endswith(host) for host in ("c4ads.org", "bellingcat.com", "graphika.com", "datasociety.net", "cetas.turing.ac.uk", "aisi.gov.uk")):
        quality_score += 35
    elif any(domain.endswith(host) for host in ("wired.com", "404media.co", "restofworld.org", "therecord.media", "krebsonsecurity.com", "theverge.com", "techcrunch.com")):
        quality_score += 30
    elif any(domain.endswith(host) for host in ("police.gov.sg", "mas.gov.sg", "imda.gov.sg", "gov.sg", "csa.gov.sg", "fbi.gov", "europol.europa.eu", "interpol.int", "cisa.gov", "nist.gov")):
        quality_score += 30
    elif any(domain.endswith(host) for host in ("openai.com", "anthropic.com", "security.googleblog.com", "cloud.google.com", "mandiant.com", "microsoft.com")):
        quality_score += 25
    elif any(domain.endswith(host) for host in ("developers.cloudflare.com", "cloudflare.com")) and usefulness_category == "Product idea / data source":
        quality_score += 25
    elif any(domain.endswith(host) for host in ("straitstimes.com", "channelnewsasia.com", "cna.com.sg", "todayonline.com", "mothership.sg")) and usefulness_category == "Local Singapore / Southeast Asia relevance":
        quality_score += 25

    if article_type in {"Research paper", "Threat intelligence report", "Product / developer changelog"}:
        quality_score += 10
    if article_type in {"Investigative report", "Deep analysis", "Policy analysis", "Technical article"}:
        quality_score += 8
    if isinstance(word_count, int):
        if word_count >= 1500:
            quality_score += 20
        elif word_count >= 1000:
            quality_score += 15
        elif word_count >= 600:
            quality_score += 8
        elif word_count < 400 and article_type not in {"Research paper", "Product / developer changelog", "Official report"}:
            quality_score -= 30
        elif word_count < 600:
            quality_score -= 10
    if any(term in haystack for term in QUALITY_SIGNAL_TERMS):
        quality_score += 10

    if reputation == "low":
        quality_score -= 20
    if candidate.get("rejection_reason") == "fetch_failed" and reputation == "high":
        quality_score -= 15
    if candidate.get("salesy_vendor_pitch"):
        quality_score -= 40
    if article_type == "Vendor blog":
        quality_score -= 20
    if article_type == "Opinion / newsletter" and reputation != "high":
        quality_score -= 15
    if suggests_product_announcement(haystack) and usefulness_category not in {"Platform policy / product change", "Product idea / data source"}:
        quality_score -= 35
    if candidate.get("press_release_or_sponsored") or "press release" in haystack or "sponsored" in haystack or "partner content" in haystack:
        quality_score -= 30
    if any(term in haystack for term in LOW_SIGNAL_ENTERTAINMENT_TERMS):
        quality_score -= 35
    if "ai scams are rising" in haystack or "ai scam are rising" in haystack:
        quality_score -= 30
    if article_type == "Advisory / guidance" and usefulness_category == "General context":
        quality_score -= 25
    if "video" in haystack or "/video/" in str(candidate.get("canonical_url", "")).lower():
        quality_score -= 10
    if article_type == "Enforcement report" and usefulness_category not in {
        "Scam development",
        "Operational intelligence",
        "Local Singapore / Southeast Asia relevance",
    }:
        quality_score -= 15
    if research_category in {"generic_fraud_ml", "generic_cybersecurity", "generic_ai_security", "irrelevant_or_adjacent"}:
        quality_score -= 10

    return quality_score


def quality_rejection_reason(candidate: dict[str, Any], config: dict[str, Any]) -> str | None:
    word_count = candidate.get("word_count")
    article_type = candidate.get("article_type", classify_article_type(candidate))
    anti_scam_relevance = candidate.get("anti_scam_relevance", "weak")
    research_category = candidate.get("research_relevance_category")
    usefulness_category = candidate.get("usefulness_category", classify_usefulness_category(candidate))
    title_context = candidate_relevance_text(candidate)
    if candidate.get("hard_rejected"):
        return candidate.get("hard_rejection_reason") or "hard_rejected"
    if anti_scam_relevance == "irrelevant":
        return "irrelevant_anti_scam_relevance"
    if article_type in {"Research paper", "Technical article", "Threat intelligence report"} and not terms_found(
        title_context, RESEARCH_DIRECT_TITLE_TERMS
    ):
        return "generic_research_or_technical"
    if article_type in {"Research paper", "Technical article", "Threat intelligence report"} and (
        anti_scam_relevance != "direct" or not candidate.get("strong_scam_anchor_terms_found")
    ):
        return "generic_research_or_technical"
    if research_category in {"generic_fraud_ml", "generic_cybersecurity", "generic_ai_security", "irrelevant_or_adjacent"}:
        return "generic_research_or_technical"
    if (
        anti_scam_relevance == "direct"
        and not candidate.get("title_scam_anchor_terms_found")
        and not candidate.get("technology_modus_terms_found")
        and usefulness_category in {"General context", "Platform policy / product change"}
    ):
        return "weak_generic_only_no_scam_anchor"
    if anti_scam_relevance == "weak" and candidate.get("weak_generic_terms_found") and not candidate.get("strong_scam_anchor_terms_found"):
        return "weak_generic_only_no_scam_anchor"
    if anti_scam_relevance == "adjacent" and usefulness_category not in {
        "Product idea / data source",
        "Detection / analytics / engineering insight",
        "Platform policy / product change",
        "Technical abuse / vulnerability",
    }:
        return "adjacent_without_product_value"
    if candidate.get("rejection_reason") == "fetch_failed" and not is_high_reputation_source(candidate, config):
        return "fetch_failed"
    if isinstance(word_count, int) and word_count < 300:
        return "thin_article"
    if candidate.get("salesy_vendor_pitch"):
        return "salesy_vendor_pitch"
    if candidate.get("press_release_or_sponsored") and not is_high_reputation_source(candidate, config):
        return "press_release_or_sponsored"
    if article_type == "Vendor blog" and int(candidate.get("quality_score", 0)) < 20:
        return "low_quality_vendor_blog"
    if is_vendor_or_low_priority_source(candidate, config) and isinstance(word_count, int) and word_count < 800:
        return "low_priority_thin_article"
    return None


def apply_quality_filters(
    ranked_candidates: list[dict[str, Any]],
    config: dict[str, Any],
    stats: dict[str, int],
    quality_cache: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    qconfig = quality_config(config)
    inspect_count = int(qconfig.get("inspect_top_n_candidates", 80))
    quality_ranked: list[dict[str, Any]] = []
    accepted: list[dict[str, Any]] = []

    for index, item in enumerate(ranked_candidates):
        candidate = dict(item)
        candidate["article_type"] = classify_article_type(candidate)
        candidate["usefulness_category"] = classify_usefulness_category(candidate)
        candidate["original_score"] = score_item(candidate, datetime.now(timezone.utc))
        candidate["source_reputation"] = source_reputation(candidate, config)
        candidate.setdefault("word_count", None)
        candidate.setdefault("access_status", "unknown")
        candidate.setdefault("salesy_vendor_pitch", False)
        candidate.setdefault("press_release_or_sponsored", False)
        candidate.setdefault("quality_checked", False)
        candidate.setdefault("rejection_reason", None)
        candidate.update(relevance_fields(candidate))

        if index < inspect_count:
            inspection = inspect_article_quality(candidate, config, quality_cache)
            candidate.update(inspection)
            stats["quality_inspected_candidate_count"] = stats.get("quality_inspected_candidate_count", 0) + 1

        candidate["quality_score"] = compute_quality_score(candidate, config)
        rejection_reason = quality_rejection_reason(candidate, config)
        if rejection_reason:
            candidate["rejection_reason"] = rejection_reason
            candidate["quality_rejected"] = True
            stats["quality_rejected_candidate_count"] = stats.get("quality_rejected_candidate_count", 0) + 1
            if rejection_reason == "fetch_failed":
                stats["rejected_fetch_failed_count"] = stats.get("rejected_fetch_failed_count", 0) + 1
            if rejection_reason == "irrelevant_anti_scam_relevance":
                stats["rejected_irrelevant_count"] = stats.get("rejected_irrelevant_count", 0) + 1
            if candidate.get("hard_rejected"):
                stats["hard_rejected_count"] = stats.get("hard_rejected_count", 0) + 1
            if rejection_reason in {
                "negative_domain_context_no_scam_anchor",
                "generic_healthcare_ai_cyber",
                "generic_enterprise_security",
                "generic_securities_fraud",
            }:
                stats["negative_domain_context_rejected_count"] = stats.get("negative_domain_context_rejected_count", 0) + 1
            if rejection_reason == "weak_generic_only_no_scam_anchor":
                stats["weak_generic_only_rejected_count"] = stats.get("weak_generic_only_rejected_count", 0) + 1
            if rejection_reason == "vendor_product_launch_no_scam_anchor":
                stats["product_launch_rejected_count"] = stats.get("product_launch_rejected_count", 0) + 1
            if rejection_reason == "generic_research_or_technical":
                stats["rejected_generic_research_count"] = stats.get("rejected_generic_research_count", 0) + 1
        else:
            if candidate.get("rejection_reason") == "fetch_failed":
                candidate["quality_issue"] = "fetch_failed"
                candidate["rejection_reason"] = None
            else:
                candidate["rejection_reason"] = candidate.get("rejection_reason")
            candidate["quality_rejected"] = False
            accepted.append(candidate)

        quality_ranked.append(candidate)

    quality_ranked = sorted(
        quality_ranked,
        key=lambda item: (
            not item.get("quality_rejected", False),
            int(item.get("quality_score", 0)),
            int(item.get("original_score", 0)),
            item.get("title", ""),
        ),
        reverse=True,
    )
    accepted = sorted(
        accepted,
        key=lambda item: (
            int(item.get("quality_score", 0)),
            int(item.get("original_score", 0)),
            item.get("title", ""),
        ),
        reverse=True,
    )
    return accepted, quality_ranked


def is_technical_item(item: dict[str, Any]) -> bool:
    return item.get("article_type", classify_article_type(item)) in TECHNICAL_TYPES


def is_deep_analysis_item(item: dict[str, Any]) -> bool:
    article_type = item.get("article_type", classify_article_type(item))
    if article_type in DEEP_ANALYSIS_TYPES:
        return True
    domain = article_domain(item)
    return any(domain == source or domain.endswith(f".{source}") for source in DEEP_ANALYSIS_SOURCE_HINTS)


def is_scam_development_item(item: dict[str, Any]) -> bool:
    article_type = item.get("article_type", classify_article_type(item))
    usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
    return article_type == "Enforcement report" or usefulness_category in {
        "Scam development",
        "Local Singapore / Southeast Asia relevance",
        "Operational intelligence",
    }


def is_platform_product_item(item: dict[str, Any]) -> bool:
    article_type = item.get("article_type", classify_article_type(item))
    usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
    return article_type in PLATFORM_PRODUCT_TYPES or usefulness_category in {
        "Platform policy / product change",
        "Product idea / data source",
    }


def is_local_sea_item(item: dict[str, Any]) -> bool:
    usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
    haystack = f"{item.get('title', '')} {article_domain(item)} {item.get('source', '')}".lower()
    return usefulness_category == "Local Singapore / Southeast Asia relevance" or any(term in haystack for term in LOCAL_SEA_TERMS)


def is_plain_news_item(item: dict[str, Any]) -> bool:
    return item.get("article_type", classify_article_type(item)) == "News report"


def is_research_item(item: dict[str, Any]) -> bool:
    return item.get("article_type", classify_article_type(item)) == "Research paper"


def is_final_allowed_relevance(item: dict[str, Any]) -> bool:
    relevance = item.get("anti_scam_relevance", "weak")
    if relevance == "direct":
        return True
    if relevance == "adjacent":
        return item.get("usefulness_category", classify_usefulness_category(item)) in {
            "Product idea / data source",
            "Detection / analytics / engineering insight",
            "Platform policy / product change",
            "Technical abuse / vulnerability",
        }
    return False


def dedupe_items_by_url(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen_urls: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for item in items:
        item_key = canonicalize_url_text(item.get("canonical_url") or item.get("url") or "")
        if item_key in seen_urls:
            continue
        seen_urls.add(item_key)
        deduped.append(item)
    return deduped


def story_amount_tokens(title: str) -> set[str]:
    lowered = title.lower().replace("s$", "$")
    tokens = set()
    for value, unit in re.findall(r"(?:\$|s\$)?\b(\d+(?:\.\d+)?)\s*(m|million|mil|bn|billion)?\b", lowered):
        if unit in {"m", "million", "mil"}:
            tokens.add(f"{value}m")
        elif unit in {"bn", "billion"}:
            tokens.add(f"{value}b")
    return tokens


def same_story_by_signature(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_title = str(left.get("title", "")).lower()
    right_title = str(right.get("title", "")).lower()
    left_story_text = f"{left_title} {left.get('canonical_url') or left.get('url') or ''}".lower()
    right_story_text = f"{right_title} {right.get('canonical_url') or right.get('url') or ''}".lower()
    left_amounts = story_amount_tokens(left_title)
    right_amounts = story_amount_tokens(right_title)
    if left_amounts and left_amounts & right_amounts:
        left_context = set(normalised_title(left_title).split())
        right_context = set(normalised_title(right_title).split())
        shared_context = left_context & right_context
        scam_context = {"scam", "deepfake", "impersonation", "victim", "wong", "singapore", "losses"}
        return bool(shared_context & scam_context) or ("scam" in left_title and "scam" in right_title)
    if "wong" in left_story_text and "wong" in right_story_text:
        left_deepfake = "deepfake" in left_story_text or "fake zoom" in left_story_text
        right_deepfake = "deepfake" in right_story_text or "fake zoom" in right_story_text
        if left_deepfake and right_deepfake and "scam" in left_story_text and "scam" in right_story_text:
            return True
    return False


def dedupe_final_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen_urls: set[str] = set()
    seen_fingerprints: list[str] = []
    deduped: list[dict[str, Any]] = []
    for item in items:
        urls = {
            canonicalize_url_text(item.get("canonical_url") or item.get("url") or ""),
            canonicalize_url_text(item.get("original_url", "")) if item.get("original_url") else "",
        }
        fingerprint = item.get("title_fingerprint") or title_fingerprint(item.get("title", ""))
        if any(url and url in seen_urls for url in urls):
            continue
        if any(fingerprints_similar(fingerprint, seen_fingerprint) for seen_fingerprint in seen_fingerprints):
            continue
        if any(same_story_by_signature(item, seen_item) for seen_item in deduped):
            continue
        seen_urls.update(url for url in urls if url)
        seen_fingerprints.append(fingerprint)
        deduped.append(item)
    return deduped


def build_quality_shortlist(
    ranked_candidates: list[dict[str, Any]],
    shortlist_count: int,
    config: dict[str, Any],
) -> list[dict[str, Any]]:
    qconfig = quality_config(config)
    shortlist = list(ranked_candidates[:shortlist_count])
    inspected_candidates = [item for item in ranked_candidates if item.get("quality_checked")]
    candidate_pool = dedupe_items_by_url(inspected_candidates + ranked_candidates)

    if qconfig.get("require_at_least_one_technical", True) and not any(is_technical_item(item) for item in shortlist):
        match = next((item for item in candidate_pool if is_technical_item(item)), None)
        if match:
            shortlist.insert(0, match)

    if qconfig.get("require_at_least_one_deep_analysis", True) and not any(is_deep_analysis_item(item) for item in shortlist):
        match = next((item for item in candidate_pool if is_deep_analysis_item(item)), None)
        if match:
            shortlist.insert(0, match)

    for predicate in (is_scam_development_item, is_platform_product_item, is_local_sea_item):
        if not any(predicate(item) for item in shortlist):
            match = next((item for item in candidate_pool if predicate(item)), None)
            if match:
                shortlist.insert(0, match)

    shortlist = dedupe_final_items(dedupe_items_by_url(shortlist))
    non_research_available = sum(1 for item in ranked_candidates if not is_research_item(item))
    max_research = 4 if non_research_available >= shortlist_count - 4 else shortlist_count
    capped: list[dict[str, Any]] = []
    research_count = 0
    for item in shortlist + ranked_candidates:
        if item in capped:
            continue
        if is_research_item(item):
            if research_count >= max_research:
                continue
            research_count += 1
        capped.append(item)
        if len(capped) >= shortlist_count:
            break

    return capped[:shortlist_count]


def article_type_distribution(items: list[dict[str, Any]]) -> dict[str, int]:
    distribution: dict[str, int] = {}
    for item in items:
        article_type = item.get("article_type", classify_article_type(item))
        distribution[article_type] = distribution.get(article_type, 0) + 1
    return dict(sorted(distribution.items()))


def usefulness_category_distribution(items: list[dict[str, Any]]) -> dict[str, int]:
    distribution: dict[str, int] = {}
    for item in items:
        usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
        distribution[usefulness_category] = distribution.get(usefulness_category, 0) + 1
    return dict(sorted(distribution.items()))


def shortlist_source_domains(items: list[dict[str, Any]]) -> list[str]:
    domains: list[str] = []
    for item in items:
        domain = article_domain(item) or "unknown"
        if domain not in domains:
            domains.append(domain)
    return domains


def select_final_items(items: list[dict[str, Any]], config: dict[str, Any], max_items: int) -> list[dict[str, Any]]:
    min_quality_score = int(config.get("min_final_quality_score", 80))
    eligible_items = [
        item
        for item in items
        if is_final_allowed_relevance(item) and int(item.get("quality_score") or 0) >= min_quality_score
    ]
    items = dedupe_final_items(eligible_items)
    selected: list[dict[str, Any]] = []

    def add_match(predicate: Any) -> None:
        if any(predicate(item) for item in selected):
            return
        match = next((item for item in items if predicate(item) and item not in selected), None)
        if match:
            selected.append(match)

    add_match(is_technical_item)
    add_match(is_deep_analysis_item)
    add_match(is_scam_development_item)
    add_match(is_platform_product_item)
    add_match(is_local_sea_item)

    max_vendor_items = int(quality_config(config).get("max_vendor_blog_items_final", 1))
    vendor_count = sum(1 for item in selected if item.get("article_type", classify_article_type(item)) == "Vendor blog")
    plain_news_count = sum(1 for item in selected if is_plain_news_item(item))
    generic_advisory_count = sum(
        1
        for item in selected
        if item.get("article_type", classify_article_type(item)) == "Advisory / guidance"
        and item.get("usefulness_category", classify_usefulness_category(item)) == "General context"
    )
    research_count = sum(1 for item in selected if is_research_item(item))

    for item in items:
        if item in selected:
            continue
        article_type = item.get("article_type", classify_article_type(item))
        usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
        if article_type == "Vendor blog":
            if vendor_count >= max_vendor_items or usefulness_category not in {
                "Technical abuse / vulnerability",
                "Product idea / data source",
                "Detection / analytics / engineering insight",
            }:
                continue
            vendor_count += 1
        if is_research_item(item) and research_count >= 2:
            exceptional_direct_research = (
                item.get("anti_scam_relevance") == "direct"
                and int(item.get("research_relevance_score") or 0) >= 55
                and int(item.get("quality_score") or 0) >= 120
            )
            if not exceptional_direct_research:
                continue
        if is_research_item(item):
            research_count += 1
        if is_plain_news_item(item) and plain_news_count >= 2:
            higher_value_remaining = any(
                not is_plain_news_item(other) and other not in selected for other in items[items.index(item) + 1 :]
            )
            if higher_value_remaining:
                continue
        if is_plain_news_item(item):
            plain_news_count += 1
        if article_type == "Advisory / guidance" and usefulness_category == "General context":
            if generic_advisory_count >= 1:
                continue
            generic_advisory_count += 1
        selected.append(item)
        if len(selected) >= max_items:
            break

    return dedupe_final_items(selected)[:max_items]


def limit_vendor_blog_items(items: list[dict[str, Any]], config: dict[str, Any], max_items: int) -> list[dict[str, Any]]:
    max_vendor_items = int(quality_config(config).get("max_vendor_blog_items_final", 1))
    selected: list[dict[str, Any]] = []
    vendor_count = 0

    for item in items:
        if item.get("article_type", classify_article_type(item)) == "Vendor blog":
            if vendor_count >= max_vendor_items:
                continue
            vendor_count += 1
        selected.append(item)
        if len(selected) >= max_items:
            break

    return selected


def recency_boost(item: dict[str, Any], now: datetime) -> int:
    parsed_date = item.get("parsed_date")
    if not isinstance(parsed_date, datetime):
        return 0

    age_days = (now - parsed_date).days
    if age_days <= 7:
        return 9
    if age_days <= 30:
        return 6
    if age_days <= 90:
        return 3
    return -10_000


def score_item(item: dict[str, Any], now: datetime | None = None) -> int:
    title = item["title"].lower()
    score = sum(3 for keyword in SCAM_KEYWORDS if keyword in title)
    if now is not None:
        score += recency_boost(item, now)
    return score


def is_seen(candidate: dict[str, Any], seen: dict[str, dict[str, Any]]) -> bool:
    seen_urls = seen.get("urls", {})
    seen_titles = seen.get("titles", {})
    original_url = candidate.get("original_url", "")
    canonical_url = candidate.get("canonical_url") or candidate.get("url", "")
    fingerprint = candidate.get("title_fingerprint") or title_fingerprint(candidate.get("title", ""))

    url_hashes = {candidate.get("canonical_url_hash"), candidate.get("original_url_hash")}
    if canonical_url:
        url_hashes.add(url_hash(canonical_url))
    if original_url:
        url_hashes.add(url_hash(original_url))

    return any(item_hash in seen_urls for item_hash in url_hashes if item_hash) or fingerprint in seen_titles


def prune_seen(seen: dict[str, dict[str, Any]], retention_days: int) -> dict[str, dict[str, Any]]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    pruned = empty_seen()

    for url_key, record in seen.get("urls", {}).items():
        sent_at = record.get("sent_at")
        if not sent_at:
            pruned["urls"][url_key] = record
            continue
        try:
            sent_at_datetime = date_parser.parse(sent_at)
        except (TypeError, ValueError, OverflowError):
            pruned["urls"][url_key] = record
            continue
        if sent_at_datetime.tzinfo is None:
            sent_at_datetime = sent_at_datetime.replace(tzinfo=timezone.utc)
        if sent_at_datetime.astimezone(timezone.utc) >= cutoff:
            pruned["urls"][url_key] = record

    for title_key, record in seen.get("titles", {}).items():
        sent_at = record.get("sent_at")
        if not sent_at:
            pruned["titles"][title_key] = record
            continue
        try:
            sent_at_datetime = date_parser.parse(sent_at)
        except (TypeError, ValueError, OverflowError):
            pruned["titles"][title_key] = record
            continue
        if sent_at_datetime.tzinfo is None:
            sent_at_datetime = sent_at_datetime.replace(tzinfo=timezone.utc)
        if sent_at_datetime.astimezone(timezone.utc) >= cutoff:
            pruned["titles"][title_key] = record

    return pruned


def mark_sent_items_seen(
    brief: list[dict[str, Any]],
    seen: dict[str, dict[str, Any]],
    retention_days: int = 365,
) -> dict[str, dict[str, Any]]:
    updated_seen = prune_seen(seen, retention_days)
    sent_at = datetime.now().astimezone().isoformat(timespec="seconds")

    for item in brief:
        article_type = item.get("article_type", classify_article_type(item))
        usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
        title = item.get("title", "")
        canonical_url = item.get("canonical_url", "")
        original_url = item.get("original_url", "")
        fingerprint = item.get("title_fingerprint") or title_fingerprint(title)

        for item_url in {canonical_url, original_url}:
            if not item_url:
                continue
            updated_seen["urls"][url_hash(item_url)] = {
                "url": item_url,
                "title": title,
                "normalised_title": normalised_title(title),
                "sent_at": sent_at,
                "article_type": article_type,
                "usefulness_category": usefulness_category,
            }

        updated_seen["titles"][fingerprint] = {
            "title": normalised_title(title),
            "normalised_title": normalised_title(title),
            "sent_at": sent_at,
            "article_type": article_type,
            "usefulness_category": usefulness_category,
        }

    return updated_seen


def fetch_candidates(
    sources: list[dict[str, Any]],
    seen: dict[str, dict[str, Any]],
    lookback_days: int,
    max_article_age_days: int,
    debug: bool,
    config: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    queries = build_rss_queries(sources)
    max_queries = int(config.get("max_rss_queries_per_run", 120))
    request_timeout = int(config.get("request_timeout_seconds", 8))
    max_google_news_candidates = int(config.get("max_google_news_candidates", 3000))
    max_arxiv_candidates = int(config.get("max_arxiv_candidates", 300))
    max_watchlist_candidates = int(config.get("max_watchlist_candidates", 50))
    raw_candidate_count = 0
    date_filtered_count = 0
    seen_filtered_count = 0
    deduped_by_url: dict[str, dict[str, Any]] = {}
    now = datetime.now(timezone.utc)

    query_cap_reached = len(queries) > max_queries
    cap_reached_by_fetcher = {
        "google_news": False,
        "arxiv": False,
        "watchlist": False,
    }

    for query in queries[:max_queries]:
        try:
            feed = parse_feed(query["url"], request_timeout)
        except requests.RequestException as exc:
            print(f"RSS fetch failed for query '{query['query']}': {exc}")
            continue

        raw_candidate_count += len(feed.entries)

        for entry in feed.entries:
            parsed_date = entry_datetime(entry)
            if not is_within_lookback(entry, lookback_days, max_article_age_days, now, debug):
                continue

            original_url = entry.get("link", query["url"])
            original_url_hash = url_hash(original_url)
            title = entry.get("title", "Untitled")
            query_text = query.get("query", "").lower()
            if query.get("priority") == "watchlist" and sum(1 for item in deduped_by_url.values() if item.get("fetcher") == "watchlist") >= max_watchlist_candidates:
                cap_reached_by_fetcher["watchlist"] = True
                continue
            if "site:arxiv.org" in query_text and sum(1 for item in deduped_by_url.values() if item.get("fetcher") == "arxiv") >= max_arxiv_candidates:
                cap_reached_by_fetcher["arxiv"] = True
                continue
            if "news.google.com" in query["url"] and len(deduped_by_url) >= max_google_news_candidates:
                cap_reached_by_fetcher["google_news"] = True
                continue
            candidate = {
                "id": original_url_hash,
                "url": original_url,
                "original_url": original_url,
                "original_url_hash": original_url_hash,
                "canonical_url": original_url,
                "canonical_url_hash": original_url_hash,
                "source": query["name"],
                "title": title,
                "normalised_title": normalised_title(title),
                "title_fingerprint": title_fingerprint(title),
                "summary": entry.get("summary", ""),
                "parsed_date": parsed_date,
                "fetcher": "watchlist" if query.get("priority") == "watchlist" else "arxiv" if "site:arxiv.org" in query_text else "google_news",
            }
            date_filtered_count += 1

            if is_seen(candidate, seen):
                seen_filtered_count += 1
                continue
            if original_url_hash in deduped_by_url:
                continue

            deduped_by_url[original_url_hash] = candidate

    candidates = dedupe_by_title(rule_rank_items(list(deduped_by_url.values()), now), now)
    return candidates, {
        "rss_queries_run": min(len(queries), max_queries),
        "raw_candidate_count": raw_candidate_count,
        "date_filtered_candidate_count": date_filtered_count,
        "seen_filtered_candidate_count": seen_filtered_count,
        "ranked_unseen_candidate_count": len(candidates),
        "query_cap_reached": int(query_cap_reached),
        "queries_available_count": len(queries),
        "google_news_candidate_cap_reached": int(cap_reached_by_fetcher["google_news"]),
        "arxiv_candidate_cap_reached": int(cap_reached_by_fetcher["arxiv"]),
        "watchlist_candidate_cap_reached": int(cap_reached_by_fetcher["watchlist"]),
    }


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def estimate_cost(input_tokens: int, output_tokens: int) -> float:
    input_price = float(os.getenv("GEMINI_INPUT_PRICE_PER_1M", "0.25"))
    output_price = float(os.getenv("GEMINI_OUTPUT_PRICE_PER_1M", "1.50"))
    return (input_tokens / 1_000_000 * input_price) + (output_tokens / 1_000_000 * output_price)


def actual_gemini_cost(prompt_tokens: int | None, output_tokens: int | None, thoughts_tokens: int | None) -> float | None:
    if prompt_tokens is None or output_tokens is None:
        return None

    billable_output_tokens = output_tokens + (thoughts_tokens or 0)
    return estimate_cost(prompt_tokens, billable_output_tokens)


def rule_rank_items(items: list[dict[str, Any]], now: datetime | None = None) -> list[dict[str, Any]]:
    if now is None:
        now = datetime.now(timezone.utc)

    def score(item: dict[str, Any]) -> tuple[bool, int, str]:
        item_url = item.get("url") or item.get("canonical_url") or item.get("original_url", "")
        return not is_google_news_url(item_url), score_item(item, now), item["title"]

    return sorted(items, key=score, reverse=True)


def dedupe_by_title(items: list[dict[str, Any]], now: datetime) -> list[dict[str, Any]]:
    kept: list[dict[str, Any]] = []

    for item in items:
        fingerprint = item.get("title_fingerprint", "")
        duplicate_index = next(
            (
                index
                for index, kept_item in enumerate(kept)
                if fingerprints_similar(fingerprint, kept_item.get("title_fingerprint", ""))
            ),
            None,
        )

        if duplicate_index is None:
            kept.append(item)
            continue

        if score_item(item, now) > score_item(kept[duplicate_index], now):
            kept[duplicate_index] = item

    return rule_rank_items(kept, now)


def is_google_news_url(url: str) -> bool:
    parsed = urlparse(url)
    if "news.google.com" not in parsed.netloc.lower():
        return False
    return any(path in parsed.path for path in ("/rss/articles", "/articles", "/read"))


def non_google_news_url(url: str) -> str | None:
    if not url:
        return None
    absolute_url = url.strip()
    if not absolute_url.startswith(("http://", "https://")):
        return None
    if is_google_news_url(absolute_url) or "news.google.com" in urlparse(absolute_url).netloc.lower():
        return None
    return absolute_url


def refresh_url(content: str, base_url: str) -> str | None:
    match = re.search(r"url\s*=\s*([^;]+)", content, flags=re.IGNORECASE)
    if not match:
        return None
    return urljoin(base_url, match.group(1).strip("'\" "))


def google_news_article_id(url: str) -> str | None:
    path_parts = [part for part in urlparse(url).path.split("/") if part]
    for marker in ("articles", "read"):
        if marker in path_parts:
            marker_index = path_parts.index(marker)
            if marker_index + 1 < len(path_parts):
                return path_parts[marker_index + 1]
    return None


def google_news_decoding_params(article_id: str) -> tuple[str, str] | None:
    headers = {"User-Agent": "Mozilla/5.0"}
    for path in ("articles", "rss/articles"):
        response = requests.get(f"https://news.google.com/{path}/{article_id}", headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        data_element = soup.select_one("c-wiz > div[jscontroller]")
        if not data_element:
            continue
        signature = data_element.get("data-n-a-sg")
        timestamp = data_element.get("data-n-a-ts")
        if signature and timestamp:
            return signature, timestamp
    return None


def decode_google_news_article_url(article_id: str) -> str | None:
    params = google_news_decoding_params(article_id)
    if not params:
        return None
    signature, timestamp = params
    inner_payload = (
        '["garturlreq",[["X","X",["X","X"],null,null,1,1,"US:en",null,1,'
        'null,null,null,null,null,0,1],"X","X",1,[1,1,1],1,1,null,0,0,'
        f'null,0],"{article_id}",{timestamp},"{signature}"]'
    )
    request_payload = json.dumps([[["Fbv4je", inner_payload, None, "generic"]]], separators=(",", ":"))
    response = requests.post(
        "https://news.google.com/_/DotsSplashUi/data/batchexecute",
        headers={
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            "User-Agent": "Mozilla/5.0",
        },
        data=f"f.req={quote(request_payload)}",
        timeout=10,
    )
    response.raise_for_status()

    try:
        parsed_data = json.loads(response.text.split("\n\n", 1)[1])[:-2]
        decoded_url = json.loads(parsed_data[0][2])[1]
    except (IndexError, TypeError, json.JSONDecodeError):
        return None
    return non_google_news_url(decoded_url)


def resolve_google_news_url_with_method(url: str) -> tuple[str, str]:
    if not is_google_news_url(url):
        return url, "not_google_news"

    if gnewsdecoder is not None:
        try:
            result = gnewsdecoder(url, interval=1)
        except Exception:
            result = None
        if isinstance(result, dict) and result.get("status") is True:
            decoded_url = non_google_news_url(result.get("decoded_url", ""))
            if decoded_url:
                return decoded_url, "googlenewsdecoder"

    article_id = google_news_article_id(url)
    if article_id:
        try:
            decoded_url = decode_google_news_article_url(article_id)
        except requests.RequestException:
            decoded_url = None
        if decoded_url:
            return decoded_url, "fallback"

    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
    )
        response.raise_for_status()
    except requests.RequestException:
        return url, "unresolved"

    resolved_url = response.url
    if resolved_url and "news.google.com" not in urlparse(resolved_url).netloc.lower():
        return resolved_url, "fallback"

    soup = BeautifulSoup(response.text, "html.parser")
    canonical_link = soup.find("link", rel=lambda value: value and "canonical" in value)
    if canonical_link:
        candidate_url = non_google_news_url(urljoin(url, canonical_link.get("href", "")))
        if candidate_url:
            return candidate_url, "fallback"

    og_url = soup.find("meta", property="og:url")
    if og_url:
        candidate_url = non_google_news_url(urljoin(url, og_url.get("content", "")))
        if candidate_url:
            return candidate_url, "fallback"

    refresh_meta = soup.find("meta", attrs={"http-equiv": lambda value: value and value.lower() == "refresh"})
    if refresh_meta:
        candidate_url = refresh_url(refresh_meta.get("content", ""), url)
        candidate_url = non_google_news_url(candidate_url or "")
        if candidate_url:
            return candidate_url, "fallback"

    for link in soup.find_all("a", href=True):
        candidate_url = non_google_news_url(urljoin(url, link["href"]))
        if candidate_url:
            return candidate_url, "fallback"

    return url, "unresolved"


def resolve_google_news_url(url: str) -> str:
    decoded_url, _method = resolve_google_news_url_with_method(url)
    return decoded_url


def canonicalise_top_candidates(
    ranked: list[dict[str, Any]],
    limit: int = 50,
    stats: dict[str, int] | None = None,
    url_cache: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    canonicalised: list[dict[str, Any]] = []

    for index, item in enumerate(ranked):
        candidate = dict(item)
        if index < limit:
            candidate["original_url"] = candidate["url"]
            was_google_news = is_google_news_url(candidate["original_url"])
            method = "not_google_news"
            cache_key = url_hash(candidate["original_url"])
            cached = (url_cache or {}).get(cache_key)
            if cached and cache_record_fresh(cached, "resolved_at"):
                candidate["canonical_url"] = cached.get("canonical_url", candidate["url"])
                method = "cache"
                if was_google_news and stats is not None:
                    stats["url_cache_hit_count"] = stats.get("url_cache_hit_count", 0) + 1
            else:
                try:
                    candidate["canonical_url"], method = resolve_google_news_url_with_method(candidate["url"])
                except Exception:
                    candidate["canonical_url"] = candidate["url"]
                    method = "unresolved"
                if url_cache is not None:
                    url_cache[cache_key] = {
                        "canonical_url": candidate["canonical_url"],
                        "resolved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    }
            candidate["url"] = candidate["canonical_url"]
            candidate["url_decode_method"] = method
            candidate["canonical_url_hash"] = url_hash(candidate["canonical_url"])
            candidate["id"] = candidate["canonical_url_hash"]
            if was_google_news and stats is not None:
                stats["google_news_url_decode_attempt_count"] = stats.get("google_news_url_decode_attempt_count", 0) + 1
                if not is_google_news_url(candidate["canonical_url"]):
                    stats["google_news_url_resolved_count"] = stats.get("google_news_url_resolved_count", 0) + 1
                else:
                    stats["unresolved_google_news_url_count"] = stats.get("unresolved_google_news_url_count", 0) + 1
            if was_google_news:
                time.sleep(0.1)

        candidate["article_type"] = classify_article_type(candidate)
        candidate["usefulness_category"] = classify_usefulness_category(candidate)
        canonicalised.append(candidate)

    return canonicalised


def filter_seen_and_dedupe_candidates(
    candidates: list[dict[str, Any]],
    seen: dict[str, dict[str, Any]],
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    filtered: list[dict[str, Any]] = []
    seen_urls: set[str] = set()

    for candidate in candidates:
        if is_seen(candidate, seen):
            stats["seen_filtered_candidate_count"] += 1
            continue
        if candidate["canonical_url_hash"] in seen_urls:
            continue

        seen_urls.add(candidate["canonical_url_hash"])
        filtered.append(candidate)

    return dedupe_by_title(rule_rank_items(filtered, now), now)


def filter_unresolved_google_news_candidates(
    candidates: list[dict[str, Any]],
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for candidate in candidates:
        canonical_url = candidate.get("canonical_url") or candidate.get("url") or ""
        if is_google_news_url(canonical_url):
            stats["unresolved_google_news_candidate_filtered_count"] = (
                stats.get("unresolved_google_news_candidate_filtered_count", 0) + 1
            )
            continue
        filtered.append(candidate)
    return filtered


def print_pipeline_report(pipeline: dict[str, Any]) -> None:
    stats = pipeline["stats"]
    timing = pipeline.get("timing", {})
    ranked_candidates = pipeline.get("quality_ranked_candidates") or pipeline["ranked_candidates"]

    print(f"Total RSS queries run: {stats['rss_queries_run']}")
    print(f"Total raw candidates fetched: {stats['raw_candidate_count']}")
    print(f"Total candidates after date filter: {stats['date_filtered_candidate_count']}")
    print(f"Total candidates filtered as already seen: {stats['seen_filtered_candidate_count']}")
    print(f"Total unresolved Google News candidates filtered: {stats.get('unresolved_google_news_candidate_filtered_count', 0)}")
    print(f"Total ranked unseen candidates: {stats['ranked_unseen_candidate_count']}")
    print(f"Total candidates quality-inspected: {stats.get('quality_inspected_candidate_count', 0)}")
    print(f"Total candidates rejected as thin/salesy/vendor pitch: {stats.get('quality_rejected_candidate_count', 0)}")
    print(f"rejected_fetch_failed_count: {stats.get('rejected_fetch_failed_count', 0)}")
    print(f"rejected_irrelevant_count: {stats.get('rejected_irrelevant_count', 0)}")
    print(f"rejected_generic_research_count: {stats.get('rejected_generic_research_count', 0)}")
    print(f"hard_rejected_count: {stats.get('hard_rejected_count', 0)}")
    print(f"negative_domain_context_rejected_count: {stats.get('negative_domain_context_rejected_count', 0)}")
    print(f"weak_generic_only_rejected_count: {stats.get('weak_generic_only_rejected_count', 0)}")
    print(f"product_launch_rejected_count: {stats.get('product_launch_rejected_count', 0)}")
    print(f"query cap reached: {bool(stats.get('query_cap_reached', 0))}")
    print(
        "candidate caps reached by fetcher: "
        f"google_news={bool(stats.get('google_news_candidate_cap_reached', 0))}, "
        f"arxiv={bool(stats.get('arxiv_candidate_cap_reached', 0))}, "
        f"watchlist={bool(stats.get('watchlist_candidate_cap_reached', 0))}"
    )
    print(f"fetch runtime seconds: {timing.get('fetch_runtime_seconds', 0):.2f}")
    print(f"URL resolution runtime seconds: {timing.get('url_resolution_runtime_seconds', 0):.2f}")
    print(f"quality inspection runtime seconds: {timing.get('quality_inspection_runtime_seconds', 0):.2f}")
    resolved = stats.get("google_news_url_resolved_count", 0)
    attempted = stats.get("google_news_url_decode_attempt_count", 0)
    print(f"Google News URLs resolved: {resolved}/{attempted}")
    print(f"unresolved_google_news_url: {stats.get('unresolved_google_news_url_count', 0)}")
    print(f"Shortlist count: {len(pipeline['shortlist'])}")
    print(f"Final shortlist article_type distribution: {article_type_distribution(pipeline['shortlist'])}")
    print(f"Final shortlist usefulness_category distribution: {usefulness_category_distribution(pipeline['shortlist'])}")
    print(f"Final shortlist source domains: {', '.join(shortlist_source_domains(pipeline['shortlist']))}")
    print(f"research_or_technical_count: {sum(1 for item in pipeline['shortlist'] if is_technical_item(item))}")
    print(f"research_items_in_shortlist: {sum(1 for item in pipeline['shortlist'] if is_research_item(item))}")
    print(f"direct_anti_scam_items_in_shortlist: {sum(1 for item in pipeline['shortlist'] if item.get('anti_scam_relevance') == 'direct')}")
    print(f"weak_or_adjacent_items_in_shortlist: {sum(1 for item in pipeline['shortlist'] if item.get('anti_scam_relevance') in {'weak', 'adjacent'})}")
    print(f"investigative_or_deep_analysis_count: {sum(1 for item in pipeline['shortlist'] if is_deep_analysis_item(item))}")
    print(f"platform_or_product_data_source_count: {sum(1 for item in pipeline['shortlist'] if is_platform_product_item(item))}")
    print(f"singapore_or_southeast_asia_count: {sum(1 for item in pipeline['shortlist'] if is_local_sea_item(item))}")
    print(f"plain_news_report_count: {sum(1 for item in pipeline['shortlist'] if is_plain_news_item(item))}")
    print("Top 30 quality-ranked candidates:")

    for index, item in enumerate(ranked_candidates[:30], start=1):
        original_url = item.get("original_url", "")
        canonical_url = item.get("canonical_url") or item.get("url", "")
        line = (
            f"{index}. quality_score={item.get('quality_score')} | "
            f"score={item.get('original_score', score_item(item, datetime.now(timezone.utc)))} | "
            f"parsed_date={parsed_date_text(item)} | "
            f"article_type={item.get('article_type', classify_article_type(item))} | "
            f"usefulness_category={item.get('usefulness_category', classify_usefulness_category(item))} | "
            f"anti_scam_relevance={item.get('anti_scam_relevance')} | "
            f"strong_scam_anchor_terms={item.get('strong_scam_anchor_terms_found', [])} | "
            f"weak_generic_terms={item.get('weak_generic_terms_found', [])} | "
            f"direct_terms={item.get('direct_relevance_terms_found', [])} | "
            f"tech_modus_terms={item.get('technology_modus_terms_found', [])} | "
            f"research_relevance_category={item.get('research_relevance_category')} | "
            f"research_relevance_score={item.get('research_relevance_score')} | "
            f"direct_scam_terms={item.get('direct_scam_relevance_terms_found', [])} | "
            f"downrank_reason={item.get('downrank_reason')} | "
            f"hard_rejected={item.get('hard_rejected', False)} | "
            f"word_count={item.get('word_count')} | "
            f"source_domain={article_domain(item)} | "
            f"title={item['title']} | "
            f"url={canonical_url}"
        )
        if original_url and original_url != canonical_url:
            line += f" | original_url={original_url}"
        if item.get("rejection_reason"):
            line += f" | rejection_reason={item['rejection_reason']}"
        print(line)


def print_selected_articles(items: list[dict[str, Any]]) -> None:
    print("Final selected articles:")
    for index, item in enumerate(items, start=1):
        article_type = item.get("article_type", classify_article_type(item))
        usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
        print(f"{index}. [{article_type} · {usefulness_category}] {item['title']}")
        print(item["canonical_url"])


def build_gemini_prompt(items: list[dict[str, Any]], sent_count: int) -> str:
    candidates = json.dumps(
        [
            {
                "id": item["id"],
                "title": item["title"],
                "url": item["canonical_url"],
                "source": item["source"],
                "parsed_date": parsed_date_text(item),
                "article_type": item.get("article_type", classify_article_type(item)),
                "usefulness_category": item.get("usefulness_category", classify_usefulness_category(item)),
                "anti_scam_relevance": item.get("anti_scam_relevance"),
                "direct_relevance_terms_found": item.get("direct_relevance_terms_found", []),
                "technology_modus_terms_found": item.get("technology_modus_terms_found", []),
                "research_relevance_category": item.get("research_relevance_category"),
                "research_relevance_score": item.get("research_relevance_score"),
                "downrank_reason": item.get("downrank_reason"),
                "word_count": item.get("word_count"),
                "quality_score": item.get("quality_score"),
                "access_status": item.get("access_status", "unknown"),
                "source_reputation": item.get("source_reputation", "medium"),
                "salesy_vendor_pitch": bool(item.get("salesy_vendor_pitch", False)),
            }
            for item in items
        ],
        ensure_ascii=True,
    )
    return (
        "You are selecting articles for a product leader building national-scale anti-scam products. "
        "Do not optimise for general newsworthiness. Optimise for product-relevant adversarial intelligence: "
        "scam developments, attacker methods, technical vulnerabilities, research, operational intelligence, "
        "platform changes, local Singapore/Southeast Asia developments, product ideas, and data-source opportunities. "
        "Select for direct anti-scam product relevance. Do not select generic AI/cybersecurity articles unless they clearly help understand scammer modus operandi, victim manipulation, monetary-loss fraud, account takeover, scam infrastructure, platform/telco/bank controls, or technologies used by scammers to scale. "
        "Reject healthcare/radiology/enterprise-security/generic-cyber items unless they have a direct scam/fraud/social-engineering link. "
        "Do not select research merely because it is technical or about fraud generally. Research should be selected only if it directly helps anti-scam product work: scammer methods, victim psychology, harmful persuasion, LLM-enabled scam abuse, scam detection, scam intervention, deepfake scams, synthetic identity, social engineering, or adverse-use benchmarks. "
        "Exclude generic cybersecurity, generic enterprise agent security, generic fraud ML, or unrelated technical domains unless there is a direct scam/social-engineering link. "
        f"You may select between 3 and {sent_count} articles. Do not always select the maximum. Select only articles that are genuinely relevant to anti-scam product work. "
        "Do not pad the list with weak or generic items. If only 4 strong items exist, return 4. Never include duplicates or near-duplicates. Prefer direct anti-scam relevance over general AI/cyber news. "
        "Correct any wrong article labels. Do not label enforcement or arrest stories as Technical articles unless they contain technical mechanisms. "
        "Prioritise articles like 'Victim as a Service' that reveal novel anti-scam product ideas, research methods, scam engagement systems, detection approaches, or engineering workflows. "
        "Avoid vendor pitch, product announcements without anti-scam or engineering relevance, thin posts, and generic consumer advice. "
        "Include at least one technical/threat-intelligence item if available. "
        "Include at least one deep analysis/investigative/research item if available. "
        f"Return JSON only with this shape: "
        f'{{"items":[{{"rank":1,"section":"Scam trends","article_type":"News report","usefulness_category":"Scam development","title":"Article title","url":"https://example.com"}}]}}. '
        "Return no commentary.\n\n"
        f"{candidates}"
    )


def call_gemini(prompt: str, model: str, max_output_tokens: int) -> tuple[str, dict[str, Any] | None]:
    api_key = os.environ["GEMINI_API_KEY"]
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    response = requests.post(
        url,
        params={"key": api_key},
        json={
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": max_output_tokens,
            },
        },
        timeout=60,
    )
    response.raise_for_status()
    data = response.json()
    parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
    text = "\n".join(part.get("text", "") for part in parts)
    return text, data.get("usageMetadata")


def rank_with_gemini(
    items: list[dict[str, Any]],
    sent_count: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    model = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
    max_output_tokens = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "600"))
    max_cost = float(os.getenv("MAX_DAILY_GEMINI_COST_USD", "0.02"))
    prompt = build_gemini_prompt(items, sent_count)
    estimated_input_tokens = len(prompt) // 4
    estimated_output_tokens = max_output_tokens
    estimated_cost_usd = estimate_cost(estimated_input_tokens, estimated_output_tokens)

    print(f"Estimated input tokens: {estimated_input_tokens}")
    print(f"Estimated output token cap: {estimated_output_tokens}")
    print(f"Estimated Gemini cost: ${estimated_cost_usd:.6f}")

    cost_data: dict[str, Any] = {
        "model": model,
        "used_llm": False,
        "estimated_input_tokens": estimated_input_tokens,
        "estimated_output_tokens": estimated_output_tokens,
        "estimated_cost_usd": round(estimated_cost_usd, 6),
        "actual_prompt_tokens": None,
        "actual_output_tokens": None,
        "actual_thoughts_tokens": None,
        "actual_total_tokens": None,
        "actual_cost_usd": None,
    }

    if estimated_cost_usd > max_cost:
        print(f"Gemini cost cap exceeded: estimated ${estimated_cost_usd:.6f} > cap ${max_cost:.6f}.")
        return items, cost_data

    if not os.getenv("GEMINI_API_KEY"):
        print("Gemini skipped: GEMINI_API_KEY is not set.")
        return items, cost_data

    try:
        text, usage = call_gemini(prompt, model, max_output_tokens)
    except requests.RequestException as exc:
        print(f"Gemini skipped after request failure: {exc}")
        return items, cost_data

    cost_data["used_llm"] = True
    if usage:
        prompt_tokens = usage.get("promptTokenCount")
        output_tokens = usage.get("candidatesTokenCount")
        thoughts_tokens = usage.get("thoughtsTokenCount")
        total_tokens = usage.get("totalTokenCount")
        cost_data["actual_prompt_tokens"] = prompt_tokens
        cost_data["actual_output_tokens"] = output_tokens
        cost_data["actual_thoughts_tokens"] = thoughts_tokens
        cost_data["actual_total_tokens"] = total_tokens

        actual_cost = actual_gemini_cost(prompt_tokens, output_tokens, thoughts_tokens)
        if actual_cost is not None:
            cost_data["actual_cost_usd"] = round(actual_cost, 6)

        print(f"Actual prompt tokens: {prompt_tokens}")
        print(f"Actual output tokens: {output_tokens}")
        print(f"Actual thoughts tokens: {thoughts_tokens}")
        print(f"Actual total tokens: {total_tokens}")
        print(f"Actual estimated Gemini cost: ${actual_cost:.6f}" if actual_cost is not None else "Actual estimated Gemini cost unavailable.")
    else:
        print("Actual token usage was unavailable.")

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = {"items": []}

    items_by_url = {canonicalize_url_text(item["canonical_url"]): item for item in items}
    ranked: list[dict[str, Any]] = []
    for gemini_item in payload.get("items", []):
        url = canonicalize_url_text(gemini_item.get("url", ""))
        item = items_by_url.get(url)
        if not item:
            continue
        updated_item = dict(item)
        article_type = gemini_item.get("article_type")
        if article_type in ALLOWED_ARTICLE_TYPES:
            updated_item["article_type"] = article_type
        usefulness_category = gemini_item.get("usefulness_category")
        if usefulness_category in ALLOWED_USEFULNESS_CATEGORIES:
            updated_item["usefulness_category"] = usefulness_category
        if gemini_item.get("title"):
            updated_item["title"] = gemini_item["title"]
        ranked.append(updated_item)

    ranked_urls = {canonicalize_url_text(item["canonical_url"]) for item in ranked}
    ranked.extend(item for item in items if canonicalize_url_text(item["canonical_url"]) not in ranked_urls)
    return ranked, cost_data


def load_cost_log() -> dict[str, list[dict[str, Any]]]:
    if not COST_LOG_PATH.exists():
        return {"runs": []}

    with COST_LOG_PATH.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, dict) and isinstance(data.get("runs"), list):
        return data
    return {"runs": []}


def save_cost_log(run: dict[str, Any]) -> None:
    cost_log = load_cost_log()
    cost_log["runs"].append(run)
    cost_log["runs"] = cost_log["runs"][-180:]

    COST_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with COST_LOG_PATH.open("w", encoding="utf-8") as file:
        json.dump(cost_log, file, indent=2)
        file.write("\n")


def build_cost_run(
    mode: str,
    cost_data: dict[str, Any],
    candidate_count: int,
    shortlist_count: int,
    sent_count: int,
) -> dict[str, Any]:
    return {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "mode": mode,
        **cost_data,
        "candidate_count": candidate_count,
        "shortlist_count": shortlist_count,
        "sent_count": sent_count,
    }


def write_github_summary(run: dict[str, Any]) -> None:
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    lines = [
        "## Gemini cost summary",
        "",
        f"- Date: {run['date']}",
        f"- Model: {run['model']}",
        f"- Mode: {run['mode']}",
        f"- Used Gemini: {run['used_llm']}",
        f"- Estimated tokens: {run['estimated_input_tokens']} input, {run['estimated_output_tokens']} output",
        f"- Estimated cost: ${run['estimated_cost_usd']:.6f}",
        f"- Actual tokens: {run['actual_prompt_tokens']} input, {run['actual_output_tokens']} output, {run['actual_thoughts_tokens']} thoughts, {run['actual_total_tokens']} total",
        f"- Actual cost: {run['actual_cost_usd']}",
        f"- Counts: {run['candidate_count']} candidates, {run['shortlist_count']} shortlisted, {run['sent_count']} sent",
        "",
    ]

    with Path(summary_path).open("a", encoding="utf-8") as file:
        file.write("\n".join(lines))


def rotating_line(lines: tuple[str, ...], today: datetime) -> str:
    return lines[today.timetuple().tm_yday % len(lines)]


def telegram_section(item: dict[str, Any]) -> str:
    usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
    article_type = item.get("article_type", classify_article_type(item))
    terms = set(item.get("strong_scam_anchor_terms_found", [])) | set(item.get("technology_modus_terms_found", []))
    if usefulness_category == "Local Singapore / Southeast Asia relevance":
        return "🇸🇬 Singapore / Southeast Asia"
    if usefulness_category == "Scam development":
        return "🧨 Scam trends"
    if usefulness_category == "Operational intelligence" or article_type == "Investigative report":
        return "🕵️ Investigations & operational intelligence"
    if any(term in terms for term in ("deepfake scam", "voice cloning scam", "synthetic identity fraud", "impersonation scam", "voice clone", "synthetic identity", "deepfake video call")):
        return "🧬 Deepfakes, synthetic identity & impersonation"
    if usefulness_category == "Technical abuse / vulnerability":
        return "🛠️ Technical abuse & vulnerabilities"
    if usefulness_category == "Research / novel method":
        return "📚 Research & novel methods"
    if usefulness_category == "Platform policy / product change":
        return "📱 Platform, telco & bank controls"
    if any(term in terms for term in ("grooming", "persuasion", "manipulation", "deception", "trust-building", "harmful persuasion")):
        return "🧠 Victim psychology & persuasion"
    if usefulness_category == "Product idea / data source":
        return "🧰 Product ideas & data sources"
    if article_type in {"Advisory / guidance", "Enforcement report", "Official report"}:
        return "🚨 Advisories & enforcement"
    return "🧨 Scam trends"


def grouped_items_by_section(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {section: [] for section in SECTION_ORDER}
    for item in sorted(items, key=lambda value: int(value.get("quality_score") or 0), reverse=True):
        grouped.setdefault(telegram_section(item), []).append(item)
    return {section: grouped.get(section, []) for section in SECTION_ORDER if grouped.get(section)}


def section_distribution(items: list[dict[str, Any]]) -> dict[str, int]:
    return {section: len(section_items) for section, section_items in grouped_items_by_section(items).items()}


def format_digest(items: list[dict[str, Any]]) -> str:
    today_datetime = datetime.now(timezone.utc)
    today = today_datetime.strftime("%d %b %Y")
    lines = [
        "🕵️ AI Abuse & Scam Radar",
        today,
        "",
        rotating_line(INTRO_LINES, today_datetime),
        "",
    ]

    item_number = 1
    for section, section_items in grouped_items_by_section(items).items():
        lines.append(section)
        for item in section_items:
            article_type = item.get("article_type", classify_article_type(item))
            usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
            lines.append(f"{item_number}. [{article_type} · {usefulness_category}] {item['title']}")
            lines.append(item["canonical_url"])
            lines.append("")
            item_number += 1

    lines.append(rotating_line(CLOSING_LINES, today_datetime))
    lines.append("")
    lines.append(ACCESS_NOTE)

    return "\n".join(lines)


def format_no_items_message() -> str:
    today_datetime = datetime.now(timezone.utc)
    return "\n".join(
        [
            "🕵️ AI Abuse & Scam Radar",
            today_datetime.strftime("%d %b %Y"),
            "",
            "No strong new AI abuse / scam-relevant items found today. Useful paranoia resumes tomorrow.",
        ]
    )


def send_telegram_message(text: str) -> None:
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    channel_id = os.getenv("TELEGRAM_CHANNEL_ID") or os.environ["TELEGRAM_CHAT_ID"]
    url = f"https://api.telegram.org/bot{token}/sendMessage"

    response = requests.post(
        url,
        json={
            "chat_id": channel_id,
            "text": text,
            "disable_web_page_preview": False,
        },
        timeout=30,
    )
    response.raise_for_status()


def run_pipeline(
    config: dict[str, Any],
    seen: dict[str, dict[str, Any]],
    resolve_urls: bool = True,
    debug: bool = False,
) -> dict[str, Any]:
    lookback_days = int(os.getenv("LOOKBACK_DAYS", config.get("lookback_days", "90")))
    max_article_age_days = int(os.getenv("MAX_ARTICLE_AGE_DAYS", config.get("max_article_age_days", "90")))
    shortlist_count = int(os.getenv("DIGEST_SHORTLIST_COUNT", config.get("max_candidates_for_llm", "20")))
    inspect_count = int(quality_config(config).get("inspect_top_n_candidates", 80))
    sources = load_sources(config)

    timing: dict[str, float] = {}
    fetch_started = time.monotonic()
    ranked_candidates, stats = fetch_candidates(sources, seen, lookback_days, max_article_age_days, debug, config)
    timing["fetch_runtime_seconds"] = time.monotonic() - fetch_started
    raw_candidates = list(ranked_candidates)

    url_cache = load_cache(URL_CACHE_PATH)
    quality_cache = load_cache(QUALITY_CACHE_PATH)
    if resolve_urls:
        resolve_started = time.monotonic()
        ranked_candidates = canonicalise_top_candidates(
            ranked_candidates,
            limit=max(50, inspect_count),
            stats=stats,
            url_cache=url_cache,
        )
        timing["url_resolution_runtime_seconds"] = time.monotonic() - resolve_started
        save_cache(URL_CACHE_PATH, url_cache)
    else:
        timing["url_resolution_runtime_seconds"] = 0.0

    ranked_candidates = filter_seen_and_dedupe_candidates(
        ranked_candidates,
        seen,
        stats,
    )
    if resolve_urls:
        ranked_candidates = filter_unresolved_google_news_candidates(ranked_candidates, stats)
    quality_started = time.monotonic()
    ranked_candidates, quality_ranked_candidates = apply_quality_filters(ranked_candidates, config, stats, quality_cache)
    timing["quality_inspection_runtime_seconds"] = time.monotonic() - quality_started
    save_cache(QUALITY_CACHE_PATH, quality_cache)
    stats["ranked_unseen_candidate_count"] = len(ranked_candidates)
    shortlist = build_quality_shortlist(ranked_candidates, shortlist_count, config)

    return {
        "rss_queries_run": stats["rss_queries_run"],
        "raw_candidates": raw_candidates,
        "date_filtered_candidates": raw_candidates,
        "seen_filtered_count": stats["seen_filtered_candidate_count"],
        "ranked_candidates": ranked_candidates,
        "quality_ranked_candidates": quality_ranked_candidates,
        "shortlist": shortlist,
        "stats": stats,
        "timing": timing,
    }


def print_url_decode_test(url: str) -> None:
    try:
        decoded_url, method = resolve_google_news_url_with_method(url)
    except Exception:
        decoded_url, method = url, "unresolved"

    print(f"original_url: {url}")
    print(f"decoded_url: {decoded_url}")
    print(f"method used: {method}")


def main() -> None:
    total_started = time.monotonic()
    load_dotenv(ROOT / ".env")

    if "--test-url-decode" in sys.argv:
        flag_index = sys.argv.index("--test-url-decode")
        if flag_index + 1 >= len(sys.argv):
            print('Usage: python src/main.py --test-url-decode "<google news url>"')
            return
        print_url_decode_test(sys.argv[flag_index + 1])
        return

    config = load_config()
    dry_run_no_resolve = "--dry-run-no-resolve" in sys.argv
    dry_run = dry_run_no_resolve or "--dry-run" in sys.argv or os.getenv("DRY_RUN", "").lower() in {"1", "true", "yes"}
    dry_run_with_llm = "--dry-run-with-llm" in sys.argv
    debug = "--debug" in sys.argv or os.getenv("DEBUG", "").lower() in {"1", "true", "yes"}
    max_items = int(os.getenv("MAX_ARTICLES_TO_SEND", config.get("max_articles_to_send", "8")))
    min_items = int(os.getenv("MIN_ARTICLES_TO_SEND", config.get("min_articles_to_send", "3")))
    seen_retention_days = int(os.getenv("SEEN_RETENTION_DAYS", config.get("seen_retention_days", "365")))
    seen = prune_seen(load_seen(), seen_retention_days)
    pipeline = run_pipeline(config, seen, resolve_urls=not dry_run_no_resolve, debug=debug)
    ranked_candidates = pipeline["ranked_candidates"]
    shortlist = pipeline["shortlist"]

    if dry_run and not dry_run_with_llm:
        print_pipeline_report(pipeline)
        print(f"total runtime seconds: {time.monotonic() - total_started:.2f}")
        return

    if not ranked_candidates:
        print_pipeline_report(pipeline)
        print("No new items to send: ranked_candidates is empty after the shared pipeline.")
        if pipeline["stats"].get("unresolved_google_news_candidate_count", 0):
            print("Some candidates were excluded because their Google News URLs could not be resolved.")
        return

    if not shortlist:
        print_pipeline_report(pipeline)
        print("No new items to send.")
        return

    gemini_started = time.monotonic()
    ranked_items, cost_data = rank_with_gemini(shortlist, max_items)
    gemini_runtime = time.monotonic() - gemini_started
    pipeline["timing"]["gemini_runtime_seconds"] = gemini_runtime
    selected_items = select_final_items(ranked_items, config, max_items)
    final_dedupe_count = len(ranked_items) - len(dedupe_final_items(ranked_items))

    if dry_run_with_llm:
        run = build_cost_run(
            "dry-run-with-llm",
            cost_data,
            candidate_count=len(ranked_candidates),
            shortlist_count=len(shortlist),
            sent_count=len(selected_items),
        )
        save_cost_log(run)
        print_pipeline_report(pipeline)
        print(f"number of final selected articles: {len(selected_items)}")
        print(f"article count below min: {len(selected_items) < min_items}")
        print(f"article count above max: {len(selected_items) > max_items}")
        print(f"final section distribution: {section_distribution(selected_items)}")
        print(f"final dedupe count: {final_dedupe_count}")
        print("Telegram preview:")
        print(format_digest(selected_items) if len(selected_items) >= min_items else format_no_items_message())
        print("Telegram was not sent.")
        print("seen.json was not updated.")
        print(f"Gemini runtime seconds: {gemini_runtime:.2f}")
        print(f"total runtime seconds: {time.monotonic() - total_started:.2f}")
        print_selected_articles(selected_items)
        return

    run = build_cost_run(
        "send",
        cost_data,
        candidate_count=len(ranked_candidates),
        shortlist_count=len(shortlist),
        sent_count=len(selected_items),
    )
    save_cost_log(run)
    write_github_summary(run)

    telegram_started = time.monotonic()
    message = format_digest(selected_items) if len(selected_items) >= min_items else format_no_items_message()
    send_telegram_message(message)
    telegram_runtime = time.monotonic() - telegram_started

    if len(selected_items) >= min_items:
        seen = mark_sent_items_seen(selected_items, seen, seen_retention_days)
        save_seen(seen)

    print(f"Gemini runtime seconds: {gemini_runtime:.2f}")
    print(f"Telegram send runtime seconds: {telegram_runtime:.2f}")
    print(f"total runtime seconds: {time.monotonic() - total_started:.2f}")
    print(f"Sent {len(selected_items)} item(s) to the Telegram channel.")


if __name__ == "__main__":
    main()
