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
CANDIDATE_CACHE_PATH = ROOT / "data" / "candidate_cache.json"
RANKING_RUNS_PATH = ROOT / "data" / "ranking_runs.json"
CACHE_TTL_DAYS = 7
CANDIDATE_CACHE_TTL_HOURS = 12
CACHE_MAX_ENTRIES = 5000
QUALITY_CACHE_VERSION = 6
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
MONITORED_SOURCE_QUERY_TERMS = (
    "scam",
    "fraud",
    "deepfake",
)
INVESTIGATIVE_MONITORED_SOURCE_QUERY_TERMS = (
    "scam investigation",
    "scam compound",
    "fraud network",
    "phishing kit",
    "deepfake scam",
    "scam infrastructure",
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
    "scam victim psychology",
    "scam victim persuasion",
    "scam victim vulnerability",
    "scam victim grooming",
    "fraud victim decision making",
    "online deception victim psychology",
    "social engineering persuasion study",
    "harmful persuasion LLM benchmark",
    "LLM scam assistance benchmark",
    "LLM phishing benchmark",
    "LLM social engineering benchmark",
    "romance scam victim psychology",
    "pig butchering victim psychology",
    "investment scam persuasion",
    "scammer victim conversation analysis",
    "scammer scripts LLM",
    "interactive scammers",
    "victim as a service",
    "scam detection intervention study",
    "scam reporting triage research",
    "scam compounds Southeast Asia investigation",
    "cyber scam compounds investigation",
    "pig butchering scam compound investigation",
    "scam call centre investigation",
    "scam syndicate investigation",
    "online fraud network investigation",
    "romance scam network investigation",
    "investment scam network investigation",
    "fake job scam investigation",
    "human trafficking scam compound investigation",
    "cyber slavery scam compound investigation",
    "Cambodia scam compound investigation",
    "Myanmar scam compound investigation",
    "Laos scam compound investigation",
    "Philippines scam compound investigation",
    "Sri Lanka scam network investigation",
    "mule network fraud investigation",
    "SIM box scam investigation",
    "VoIP scam infrastructure",
    "phishing kit investigation",
    "scam kit underground market",
    "fake website scam infrastructure",
    "fake ad scam network",
    "deepfake scam investigation",
    "voice clone scam investigation",
    "synthetic identity fraud investigation",
    "AI scam investigation",
    "LLM scam automation investigation",
    "platform abuse scam investigation",
    "WhatsApp scam network",
    "Telegram scam network",
    "Facebook ad scam investigation",
    "TikTok deepfake scam ads",
    "crypto scam network investigation",
    "payment fraud network investigation",
)
SPECIFIC_PRODUCT_RADAR_QUERIES = (
    '"Profiling User Vulnerability to Phishing Through Psychological and Behavioral Factors"',
    '"My Parents’ Expectations Were Overwhelming" "Online Dating Romance Scams"',
    '"My Parents" "Expectations Were Overwhelming" "Online Dating Romance Scams"',
    '"HELLO BOSS" "deepfake" "scams"',
    '"Inside the Chinese Realtime Deepfake Software Powering Scams Around the World"',
    '"Deepfakes on Demand" "Fraud as a Service"',
    '"Victim as a Service" "Interactive Scammers"',
    '"Large-scale online deanonymization with LLMs"',
    '"visa-exemption policy" "global scam rings"',
    '"Chinese nationals" "cyberscam compound" Myanmar',
    '"Victim as a Service" scammers',
    '"Designing a System for Engaging with Interactive Scammers"',
    "site:arxiv.org scam victim psychology",
    "site:arxiv.org social engineering persuasion LLM",
    "site:arxiv.org harmful persuasion fraud scam",
    "site:arxiv.org LLM scam phishing benchmark",
    "site:arxiv.org scammer victim conversation",
    "site:arxiv.org online deception victim",
    "site:arxiv.org interactive scammers",
    "site:arxiv.org victim as a service",
    "site:arxiv.org scam detection intervention",
    "site:ssrn.com scam victim psychology",
    "site:arxiv.org fraud victim decision making",
    "site:arxiv.org LLM social engineering benchmark",
    "site:arxiv.org deepfake scam detection",
    "site:arxiv.org synthetic identity fraud",
    "site:ssrn.com fraud victim decision making",
    "site:ssrn.com social engineering fraud",
    "site:osf.io scam victim psychology",
    "site:dl.acm.org phishing social engineering scam",
    "site:dl.acm.org online fraud victim psychology",
    "site:ieee.org scam detection phishing social engineering",
    "site:usenix.org phishing social engineering scam",
    "site:ndss-symposium.org phishing social engineering scam",
    "site:arxiv.org scam LLM fraud deepfake synthetic identity phishing",
    "site:arxiv.org AI scam detection social engineering agent abuse",
    "site:arxiv.org interactive scammers victim as a service",
    "site:arxiv.org watermarking reverse engineered synthetic media detection",
    "site:theverge.com AI watermarking deepfake reverse engineered",
    "site:techcrunch.com WhatsApp spam messaging limits fraud scams",
    "site:c4ads.org scam cyber fraud hotline trafficking Southeast Asia",
    "site:straitstimes.com Singapore scam Cambodia job seekers fraud",
    "site:channelnewsasia.com Singapore scam Cambodia fraud AI deepfake",
    "site:channelnewsasia.com Cambodia scam compound Vietnam",
    "site:channelnewsasia.com online scams human trafficking Cambodia Vietnam",
    "site:channelnewsasia.com scam compounds online scams Cambodia",
    "site:developers.cloudflare.com/changelog crawl endpoint browser rendering AI",
    "site:developers.cloudflare.com scam phishing abuse crawl endpoint",
    "site:security.googleblog.com AI abuse phishing fraud deepfake",
    "site:blog.whatsapp.com spam scams messaging limits",
    "site:about.fb.com scams fraud messaging limits",
    "site:c4ads.org scam fraud trafficking hotline",
    "site:c4ads.org cyber scam network Southeast Asia",
    "site:wired.com scam deepfake fraud AI",
    "site:wired.com scam compound fraud network",
    "site:wired.com phishing kit scammer AI abuse",
    "site:wired.com cybercrime scam fraud investigation",
    "site:404media.co scam deepfake fraud AI",
    "site:404media.co realtime deepfake scam",
    "site:404media.co phishing kit scammer cybercrime",
    "site:restofworld.org scam compound fraud Southeast Asia",
    "site:restofworld.org online fraud workers scam",
    "site:graphika.com scam fraud influence operation AI",
    "site:bellingcat.com scam network fraud cyber",
    "site:therecord.media scam network phishing kit fraud AI",
    "site:krebsonsecurity.com phishing kit scam fraud",
    "site:technologyreview.com scam deepfake AI fraud",
    "site:reuters.com scam compound fraud cyber",
    "site:apnews.com scam compound fraud trafficking",
    "site:bbc.com scam compound fraud trafficking",
    "site:theguardian.com scam compound fraud trafficking",
    "site:ft.com scam fraud cybercrime AI",
    "site:asia.nikkei.com scam fraud Southeast Asia cyber",
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
    "Product/company profile",
    "Sponsored / vendor content",
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
    "Deepfakes, synthetic identity & impersonation",
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
    "charges",
    "seized",
    "crackdown",
    "sanction",
    "sanctions",
)
RESEARCH_METHOD_TERMS = (
    "victim as a service",
    "interactive scammers",
    "detection",
    "dataset",
    "benchmark",
    "measurement",
    "empirical",
    "ecosystem",
    "advertising ecosystem",
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
    "fake government official",
    "fake government officials",
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
    "scam ring",
    "scam rings",
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
    "online deception",
    "victim protection",
    "real-time scam warning",
    "scam message",
    "scam call",
    "scam compliance",
    "fraud decision making",
    "victim decision making",
    "digital fraud detection",
    "entity verification",
    "phishing detection",
    "user vulnerability to phishing",
    "psychological and behavioral factors",
    "fake website detection",
    "vishing detection",
    "smishing detection",
    "scam reporting",
    "llm scam",
    "llm phishing",
    "llm social engineering",
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
    "backrooms",
    "horror myth",
    "horror movie",
    "filmmaker",
    "movie interview",
    "movie trailer",
    "premiere",
    "south park",
    "kimmel",
    "trump penis",
    "premiere date",
    "hollywood",
)
FINAL_DISALLOWED_REJECTION_REASONS = {
    "generic_research_or_technical",
    "weak_generic_only_no_scam_anchor",
    "generic_cybersecurity",
    "generic_ai_security",
    "generic_fraud_ml",
    "irrelevant_or_adjacent",
    "generic_enterprise_security",
    "generic_healthcare_ai_cyber",
    "negative_domain_context_no_scam_anchor",
    "vendor_product_launch_no_scam_anchor",
    "irrelevant_anti_scam_relevance",
    "entertainment_or_culture_no_scam_anchor",
}
SOFT_FINAL_REJECTION_REASONS = {"fetch_failed", "fetch_timeout"}
TECHNICAL_TYPES = {"Technical article", "Threat intelligence report", "Official report", "Research paper"}
DEEP_ANALYSIS_TYPES = {"Deep analysis", "Investigative report", "Research paper", "Policy analysis"}
PLATFORM_PRODUCT_TYPES = {"Policy / platform update", "Product / developer changelog"}
DEEP_ANALYSIS_SOURCE_HINTS = (
    "wired.com",
    "404media.co",
    "restofworld.org",
    "c4ads.org",
    "datasociety.net",
    "cetas.turing.ac.uk",
    "technologyreview.com",
    "bellingcat.com",
    "graphika.com",
    "therecord.media",
    "krebsonsecurity.com",
)
HIGH_VALUE_INVESTIGATIVE_DOMAINS = (
    "wired.com",
    "404media.co",
    "c4ads.org",
    "restofworld.org",
    "graphika.com",
    "bellingcat.com",
    "therecord.media",
    "krebsonsecurity.com",
    "technologyreview.com",
    "datasociety.net",
    "cetas.turing.ac.uk",
)
HIGH_VALUE_PRODUCT_DOMAINS = (
    "techcrunch.com",
    "theverge.com",
    "developers.cloudflare.com",
    "cloudflare.com",
    "security.googleblog.com",
    "blog.google",
    "about.fb.com",
    "meta.com",
    "blog.whatsapp.com",
    "whatsapp.com",
    "openai.com",
    "anthropic.com",
    "microsoft.com",
)
SECTION_ORDER = (
    "🧠 VICTIM PSYCHOLOGY & PERSUASION",
    "📚 RESEARCH & NOVEL METHODS",
    "🕵️ INVESTIGATIONS & OPERATIONAL INTELLIGENCE",
    "🧨 SCAM TRENDS",
    "🧬 DEEPFAKES, SYNTHETIC IDENTITY & IMPERSONATION",
    "🛠️ TECHNICAL ABUSE & VULNERABILITIES",
    "📱 PLATFORM, TELCO & BANK CONTROLS",
    "🧰 PRODUCT IDEAS & DATA SOURCES",
    "🇸🇬 SINGAPORE / SOUTHEAST ASIA",
    "🚨 ADVISORIES & ENFORCEMENT",
)
SECTION_MARKER = "▸"
TAKEAWAY_MARKER = "•"


def load_config() -> dict[str, Any]:
    with SOURCES_PATH.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def load_sources(config: dict[str, Any]) -> list[dict[str, Any]]:
    return [source for source in config.get("sources", []) if source.get("enabled", True)]


def empty_seen() -> dict[str, dict[str, Any]]:
    return {"urls": {}, "titles": {}, "stories": {}}


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
            "stories": data.get("stories", {}) if isinstance(data.get("stories"), dict) else {},
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


def fetch_config_hash(config: dict[str, Any]) -> str:
    payload = {
        "sources": [
            {"name": source.get("name"), "domain": source.get("domain"), "url": source.get("url"), "enabled": source.get("enabled", True)}
            for source in config.get("sources", [])
        ],
        "domain_terms": DOMAIN_QUERY_TERMS,
        "monitored_source_terms": MONITORED_SOURCE_QUERY_TERMS,
        "fallback_queries": GLOBAL_FALLBACK_QUERIES,
        "specific_queries": SPECIFIC_PRODUCT_RADAR_QUERIES,
        "reference_examples": configured_reference_examples(config),
        "monitored_sources": configured_monitored_sources(config),
        "lookback_days": config.get("lookback_days"),
        "max_article_age_days": config.get("max_article_age_days"),
        "news_max_article_age_days": config.get("news_max_article_age_days"),
        "platform_product_official_max_article_age_days": config.get("platform_product_official_max_article_age_days"),
        "academic_research_max_article_age_days": config.get("academic_research_max_article_age_days"),
        "investigative_longform_max_article_age_days": config.get("investigative_longform_max_article_age_days"),
        "max_rss_queries_per_run": config.get("max_rss_queries_per_run"),
    }
    return stable_hash(json.dumps(payload, sort_keys=True, default=str))


def candidate_for_cache(candidate: dict[str, Any]) -> dict[str, Any]:
    cached = dict(candidate)
    parsed_date = cached.get("parsed_date")
    if isinstance(parsed_date, datetime):
        cached["parsed_date"] = parsed_date.isoformat()
    cached["source_name"] = cached.get("source", "")
    cached["source_domain"] = article_domain(cached)
    return cached


def candidate_from_cache(candidate: dict[str, Any]) -> dict[str, Any]:
    restored = dict(candidate)
    parsed_date = restored.get("parsed_date")
    if isinstance(parsed_date, str) and parsed_date:
        try:
            restored["parsed_date"] = date_parser.parse(parsed_date)
        except (TypeError, ValueError, OverflowError):
            restored["parsed_date"] = None
    restored.setdefault("source", restored.get("source_name", "candidate_cache"))
    restored.setdefault("canonical_url", restored.get("url", ""))
    restored.setdefault("original_url", restored.get("canonical_url") or restored.get("url", ""))
    restored.setdefault("canonical_url_hash", url_hash(restored.get("canonical_url") or restored.get("url", "")))
    restored.setdefault("original_url_hash", url_hash(restored.get("original_url", "")))
    restored.setdefault("id", restored.get("canonical_url_hash"))
    restored.setdefault("title_fingerprint", title_fingerprint(restored.get("title", "")))
    restored.setdefault("normalised_title", normalised_title(restored.get("title", "")))
    return restored


def load_candidate_cache(config: dict[str, Any], require_fresh: bool = True) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not CANDIDATE_CACHE_PATH.exists():
        return [], {"used_candidate_cache": False, "candidate_cache_age_minutes": None, "reason": "missing"}
    try:
        with CANDIDATE_CACHE_PATH.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (json.JSONDecodeError, OSError):
        return [], {"used_candidate_cache": False, "candidate_cache_age_minutes": None, "reason": "invalid"}

    created_at_text = data.get("created_at")
    try:
        created_at = date_parser.parse(created_at_text)
    except (TypeError, ValueError, OverflowError):
        return [], {"used_candidate_cache": False, "candidate_cache_age_minutes": None, "reason": "invalid_created_at"}
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    age_minutes = (datetime.now(timezone.utc) - created_at.astimezone(timezone.utc)).total_seconds() / 60
    expires_at_text = data.get("expires_at")
    fresh = age_minutes <= CANDIDATE_CACHE_TTL_HOURS * 60
    if expires_at_text:
        try:
            expires_at = date_parser.parse(expires_at_text)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            fresh = datetime.now(timezone.utc) <= expires_at.astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            pass
    if require_fresh and not fresh:
        return [], {"used_candidate_cache": False, "candidate_cache_age_minutes": round(age_minutes, 1), "reason": "expired"}

    expected_hash = fetch_config_hash(config)
    cached_hash = data.get("fetch_config_hash")
    config_hash_matches = not cached_hash or cached_hash == expected_hash
    if require_fresh and not config_hash_matches:
        return [], {
            "used_candidate_cache": False,
            "candidate_cache_age_minutes": round(age_minutes, 1),
            "reason": "config_hash_mismatch",
            "fetch_config_hash": cached_hash,
        }

    candidates = [candidate_from_cache(candidate) for candidate in data.get("candidates", []) if isinstance(candidate, dict)]
    return candidates, {
        "used_candidate_cache": True,
        "candidate_cache_age_minutes": round(age_minutes, 1),
        "candidate_cache_candidate_count": len(candidates),
        "fetch_config_hash": data.get("fetch_config_hash"),
        "config_hash_matches": config_hash_matches,
        "fresh": fresh,
    }


def save_candidate_cache(candidates: list[dict[str, Any]], config: dict[str, Any]) -> None:
    now = datetime.now(timezone.utc)
    payload = {
        "created_at": now.isoformat(timespec="seconds"),
        "expires_at": (now + timedelta(hours=CANDIDATE_CACHE_TTL_HOURS)).isoformat(timespec="seconds"),
        "fetch_config_hash": fetch_config_hash(config),
        "candidate_count": len(candidates),
        "candidates": [candidate_for_cache(candidate) for candidate in candidates],
    }
    CANDIDATE_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CANDIDATE_CACHE_PATH.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, sort_keys=True)
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


def domain_from_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower().removeprefix("www.")


def google_news_entry_source(entry: Any, fallback_name: str) -> tuple[str, str]:
    source = entry.get("source") or entry.get("source_detail") or {}
    source_name = fallback_name
    source_url = ""
    if isinstance(source, dict):
        source_name = str(source.get("title") or source.get("name") or fallback_name)
        source_url = str(source.get("href") or source.get("url") or "")
    elif source:
        source_name = str(source)

    source_domain_value = domain_from_url(source_url)
    if not source_domain_value:
        title = str(entry.get("title", ""))
        if " - " in title:
            publisher = title.rsplit(" - ", 1)[1].strip()
            if publisher:
                source_name = publisher
    return source_name, source_domain_value


def configured_reference_examples(config: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for raw_entry in config.get("reference_examples", []) or config.get("reference_urls", []) or config.get("watchlist", []) or []:
        if isinstance(raw_entry, str):
            entries.append({"url": raw_entry, "include_as_candidate": False, "evergreen_reference": False})
        elif isinstance(raw_entry, dict) and raw_entry.get("url"):
            entries.append(dict(raw_entry))
    return entries


def configured_monitored_sources(config: dict[str, Any]) -> list[str]:
    domains: list[str] = []
    for raw_domain in config.get("monitored_sources", []) or []:
        domain = str(raw_domain).strip().lower().removeprefix("www.")
        if domain and domain not in domains:
            domains.append(domain)
    return domains


def reference_example_queries(config: dict[str, Any]) -> list[str]:
    queries: list[str] = []
    for entry in configured_reference_examples(config):
        url = str(entry.get("url") or "")
        domain = (urlparse(url).hostname or "").lower().removeprefix("www.")
        signal_text = f"{entry.get('title', '')} {entry.get('summary', '')}"
        tokens = [
            token
            for token in re.findall(r"[a-z0-9]+", signal_text.lower())
            if len(token) >= 4 and token not in STOPWORDS
        ]
        meaningful = []
        for token in tokens:
            if token not in meaningful:
                meaningful.append(token)
            if len(meaningful) >= 6:
                break
        if domain and meaningful:
            queries.append(f"site:{domain} {' '.join(meaningful)}")
    return queries


def is_longform_query_text(query: str) -> bool:
    lowered = query.lower()
    return any(
        term in lowered
        for term in (
            "404media.co",
            "wired.com",
            "c4ads.org",
            "restofworld.org",
            "graphika.com",
            "bellingcat.com",
            "therecord.media",
            "krebsonsecurity.com",
            "technologyreview.com",
            "investigation",
            "investigative",
            "scam compound",
            "fraud network",
            "scam infrastructure",
            "phishing kit",
            "scam kit",
            "cyber slavery",
            "human trafficking",
        )
    )


def build_rss_queries(sources: list[dict[str, Any]], config: dict[str, Any] | None = None) -> list[dict[str, str]]:
    queries: list[dict[str, str]] = []

    targeted_queries = sorted(
        SPECIFIC_PRODUCT_RADAR_QUERIES,
        key=lambda query: (0 if is_longform_query_text(query) else 1, query.lower()),
    )
    for query in targeted_queries:
        queries.append(
            {
                "name": "Google News",
                "query": query,
                "url": google_news_rss_url(query),
                "priority": "targeted",
            }
        )

    for query in reference_example_queries(config or {}):
        queries.append(
            {
                "name": "Google News",
                "query": query,
                "url": google_news_rss_url(query),
                "priority": "targeted_reference",
            }
        )

    seen_source_domains: set[str] = set()
    for domain in configured_monitored_sources(config or {}):
        seen_source_domains.add(domain)
        terms = (
            INVESTIGATIVE_MONITORED_SOURCE_QUERY_TERMS + MONITORED_SOURCE_QUERY_TERMS
            if any(domain.endswith(host) for host in HIGH_VALUE_INVESTIGATIVE_DOMAINS)
            else MONITORED_SOURCE_QUERY_TERMS
        )
        for term in terms:
            query = f"site:{domain} {term}"
            queries.append(
                {
                    "name": domain,
                    "query": query,
                    "url": google_news_rss_url(query),
                    "priority": "monitored_source",
                }
            )

    for source in sources:
        domain = source_domain(source)
        if domain:
            if domain in seen_source_domains:
                continue
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


def query_group_for_query(query: str, priority: str = "") -> str:
    lowered = query.lower()
    if any(term in lowered for term in ("victim psychology", "victim persuasion", "victim vulnerability", "grooming", "harmful persuasion", "decision making", "conversation analysis")):
        return "psychology"
    if any(term in lowered for term in ("arxiv.org", "ssrn.com", "osf.io", "dl.acm.org", "ieee.org", "usenix.org", "ndss-symposium.org", "benchmark", "research", "study")):
        return "academic"
    if any(term in lowered for term in ("c4ads.org", "wired.com", "404media.co", "restofworld.org", "graphika.com", "bellingcat.com", "investigation", "investigative", "longform")):
        return "investigative"
    if any(term in lowered for term in ("compound", "syndicate", "mule", "sim box", "voip", "phishing kit", "scam kit", "fake website", "fake ad", "call centre", "call center", "infrastructure")):
        return "international"
    if any(term in lowered for term in ("developer", "cloudflare", "whatsapp", "telegram", "meta", "platform", "messaging limits", "bank controls", "telco")):
        return "platform_product"
    if any(term in lowered for term in ("singapore", "cambodia", "myanmar", "southeast asia", "south-east asia", "straitstimes", "channelnewsasia", "mothership", "cna.com.sg")):
        return "singapore_sea"
    if priority == "monitored_source":
        return "monitored_source"
    if priority == "targeted":
        return "targeted"
    return "broad"


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


def item_age_days(item: dict[str, Any], now: datetime) -> int | None:
    parsed_date = item.get("parsed_date")
    if not isinstance(parsed_date, datetime):
        return None
    return max(0, (now - parsed_date).days)


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


def parse_datetime_from_html(soup: BeautifulSoup) -> datetime | None:
    selectors = (
        ("meta", {"property": "article:published_time"}, "content"),
        ("meta", {"property": "article:modified_time"}, "content"),
        ("meta", {"name": "date"}, "content"),
        ("meta", {"name": "dc.date"}, "content"),
        ("meta", {"name": "citation_publication_date"}, "content"),
        ("time", {}, "datetime"),
    )
    for tag_name, attrs, value_attr in selectors:
        for tag in soup.find_all(tag_name, attrs=attrs):
            value = tag.get(value_attr)
            if not value:
                continue
            try:
                parsed = date_parser.parse(str(value))
            except (TypeError, ValueError, OverflowError):
                continue
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
    return None


def title_from_url(url: str) -> str:
    parsed = urlparse(url)
    slug = parsed.path.rstrip("/").split("/")[-1] or parsed.netloc
    title = re.sub(r"[-_]+", " ", slug)
    title = re.sub(r"\s+", " ", title).strip()
    return title.title() if title else url


def fetch_reference_url_candidate(
    entry: dict[str, Any],
    seen: dict[str, dict[str, Any]],
    max_article_age_days: int,
    debug: bool,
    config: dict[str, Any],
) -> dict[str, Any] | None:
    url = str(entry.get("url", "")).strip()
    if not url:
        return None

    evergreen = bool(entry.get("evergreen_reference", False))
    timeout_seconds = int(config.get("request_timeout_seconds", 8))
    has_config_title = bool(entry.get("title"))
    has_config_summary = bool(entry.get("summary"))
    title = str(entry.get("title") or title_from_url(url))
    canonical_url = url
    summary = str(entry.get("summary") or "")
    parsed_date: datetime | None = None
    access_status = "unknown"

    try:
        response = requests.get(url, timeout=timeout_seconds, headers={"User-Agent": "Mozilla/5.0"})
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        title_tag = (
            soup.find("meta", property="og:title")
            or soup.find("meta", attrs={"name": "twitter:title"})
            or soup.find("title")
        )
        if title_tag and not has_config_title:
            title_value = title_tag.get("content") if title_tag.name == "meta" else title_tag.get_text(" ", strip=True)
            if title_value:
                title = str(title_value)
        summary_tag = soup.find("meta", property="og:description") or soup.find("meta", attrs={"name": "description"})
        if summary_tag and summary_tag.get("content") and not has_config_summary:
            summary = str(summary_tag.get("content"))
        canonical_tag = soup.find("link", rel=lambda value: value and "canonical" in value)
        if canonical_tag and canonical_tag.get("href"):
            canonical_url = urljoin(url, str(canonical_tag.get("href")))
        parsed_date = parse_datetime_from_html(soup)
        text_for_access = soup.get_text(" ", strip=True).lower()
        if any(phrase in text_for_access for phrase in PAYWALL_PHRASES):
            access_status = "paywalled_or_login"
        else:
            access_status = "available"
    except requests.RequestException:
        access_status = "unknown"

    now = datetime.now(timezone.utc)
    if parsed_date is None and not (debug or evergreen):
        return None
    recency_probe = {
        "title": title,
        "summary": summary,
        "url": canonical_url,
        "canonical_url": canonical_url,
        "parsed_date": parsed_date,
        "query_group": "reference_url",
        "evergreen_reference": evergreen,
    }
    recency_probe["article_type"] = classify_article_type(recency_probe)
    recency_probe["usefulness_category"] = classify_usefulness_category(recency_probe)
    if not is_within_candidate_recency_window(recency_probe, config, now, debug, None, max_article_age_days):
        return None

    canonical_hash = url_hash(canonical_url)
    original_hash = url_hash(url)
    candidate = {
        "id": canonical_hash,
        "url": canonical_url,
        "original_url": url,
        "original_url_hash": original_hash,
        "canonical_url": canonical_url,
        "canonical_url_hash": canonical_hash,
        "source": entry.get("name") or (urlparse(canonical_url).hostname or "reference_url"),
        "source_domain": (urlparse(canonical_url).hostname or "").lower().removeprefix("www."),
        "title": title,
        "normalised_title": normalised_title(title),
        "title_fingerprint": title_fingerprint(title),
        "summary": summary,
        "parsed_date": parsed_date,
        "fetcher": "reference_url",
        "query_group": "reference_url",
        "query": "reference_url",
        "reference_url_candidate": True,
        "evergreen_reference": evergreen,
        "access_status": access_status,
    }
    if is_seen(candidate, seen):
        return None
    return candidate


def strip_publisher_suffix(title: str) -> str:
    separators = (" - ", " | ", " – ", " — ")
    cleaned = title.strip()
    for separator in separators:
        if separator in cleaned:
            left, right = cleaned.rsplit(separator, 1)
            if 1 <= len(right.split()) <= 6:
                return left.strip()
    return cleaned


def display_title(title: str) -> str:
    cleaned = strip_publisher_suffix(str(title or "Untitled"))
    cleaned = re.sub(r"\s*This work was conducted.*$", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*Supported solely by.*$", "", cleaned, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", cleaned).strip() or "Untitled"


def title_fingerprint(title: str) -> str:
    words = normalised_title(title).split()
    return " ".join(words[:14])


def normalised_title(title: str) -> str:
    stripped = strip_publisher_suffix(title).lower()
    translator = str.maketrans({char: " " for char in string.punctuation})
    words = stripped.translate(translator).split()
    meaningful_words = [word for word in words if word not in STOPWORDS]
    return " ".join(meaningful_words)


def normalize_title_for_dedupe(title: str) -> str:
    cleaned = strip_publisher_suffix(str(title or "")).lower()
    replacements = {
        "spam links": "spam",
        "spam link": "spam",
        "email address": "email",
        "e-mail address": "email",
        "microsoft account": "microsoft",
        "microsoft email": "microsoft",
        "official microsoft": "microsoft",
        "internal microsoft": "microsoft",
        "government officials": "government official",
        "fake zoom meeting": "fake zoom",
    }
    for old, new in replacements.items():
        cleaned = cleaned.replace(old, new)
    translator = str.maketrans({char: " " for char in string.punctuation})
    cleaned = cleaned.translate(translator)
    filler_words = STOPWORDS | {
        "official",
        "internal",
        "address",
        "links",
        "link",
        "story",
        "says",
        "said",
        "over",
        "after",
        "about",
        "into",
        "using",
        "use",
    }
    words = [word for word in cleaned.split() if word not in filler_words]
    return re.sub(r"\s+", " ", " ".join(words)).strip()


def title_token_set(title: str) -> set[str]:
    return {token for token in normalize_title_for_dedupe(title).split() if len(token) >= 3}


def url_slug_token_set(url: str) -> set[str]:
    parsed = urlparse(url or "")
    slug = parsed.path.rstrip("/").split("/")[-1]
    slug = re.sub(r"\.[a-z0-9]+$", "", slug.lower())
    return {
        token
        for token in normalize_title_for_dedupe(slug.replace("-", " ")).split()
        if len(token) >= 3 and any(char.isalpha() for char in token) and token not in {"html", "pdf", "abs"}
    }


def token_similarity(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def parsed_date_key(item: dict[str, Any]) -> str:
    parsed_date = item.get("parsed_date")
    if isinstance(parsed_date, datetime):
        return parsed_date.strftime("%Y-%m-%d")
    if isinstance(parsed_date, str) and parsed_date:
        try:
            return date_parser.parse(parsed_date).strftime("%Y-%m-%d")
        except (TypeError, ValueError, OverflowError):
            return parsed_date[:10]
    return ""


def same_story_key(candidate: dict[str, Any]) -> str:
    domain = article_domain(candidate)
    date_key = parsed_date_key(candidate)
    title_tokens = title_token_set(candidate.get("title", ""))
    slug_tokens = url_slug_token_set(candidate.get("canonical_url") or candidate.get("url") or "")
    meaningful = sorted((title_tokens | slug_tokens) - {"article", "story", "news"})[:10]
    return "|".join([domain, date_key, " ".join(meaningful[:8])])


def near_duplicate_reason(left: dict[str, Any], right: dict[str, Any]) -> str | None:
    left_canonical = canonicalize_url_text(left.get("canonical_url") or left.get("url") or "")
    right_canonical = canonicalize_url_text(right.get("canonical_url") or right.get("url") or "")
    if left_canonical and right_canonical and left_canonical == right_canonical:
        return "same_canonical_url"
    left_original = canonicalize_url_text(left.get("original_url", ""))
    right_original = canonicalize_url_text(right.get("original_url", ""))
    if left_original and right_original and left_original == right_original:
        return "same_original_url"

    left_fingerprint = left.get("title_fingerprint") or title_fingerprint(left.get("title", ""))
    right_fingerprint = right.get("title_fingerprint") or title_fingerprint(right.get("title", ""))
    if left_fingerprint and right_fingerprint and left_fingerprint == right_fingerprint:
        return "same_title_fingerprint"

    left_title_tokens = title_token_set(left.get("title", ""))
    right_title_tokens = title_token_set(right.get("title", ""))
    title_similarity = token_similarity(left_title_tokens, right_title_tokens)
    same_domain = article_domain(left) == article_domain(right)
    same_date = parsed_date_key(left) and parsed_date_key(left) == parsed_date_key(right)
    left_story_text = f"{left.get('title', '')} {left.get('canonical_url') or left.get('url') or ''}".lower()
    right_story_text = f"{right.get('title', '')} {right.get('canonical_url') or right.get('url') or ''}".lower()
    if same_domain and article_domain(left).endswith("404media.co"):
        both_deepfake_software = all(
            "deepfake" in text and ("scam" in text or "scammer" in text or "scams" in text)
            for text in (left_story_text, right_story_text)
        )
        if both_deepfake_software and any(marker in f"{left_story_text} {right_story_text}" for marker in ("hello boss", "podcast", "chinese realtime")):
            return "same_longform_investigation_prefer_full_article"
    if same_domain and same_date and title_similarity >= 0.55:
        return f"same_domain_date_title_similarity:{title_similarity:.2f}"

    left_slug_tokens = url_slug_token_set(left.get("canonical_url") or left.get("url") or "")
    right_slug_tokens = url_slug_token_set(right.get("canonical_url") or right.get("url") or "")
    slug_similarity = token_similarity(left_slug_tokens, right_slug_tokens)
    if same_domain and slug_similarity >= 0.55:
        return f"same_domain_slug_similarity:{slug_similarity:.2f}"
    if title_similarity >= 0.70:
        return f"title_similarity:{title_similarity:.2f}"

    left_normalized = normalize_title_for_dedupe(left.get("title", ""))
    right_normalized = normalize_title_for_dedupe(right.get("title", ""))
    if left_normalized and right_normalized:
        shorter, longer = sorted((left_normalized, right_normalized), key=len)
        if len(shorter) >= 24 and shorter in longer:
            return "title_containment"
    return None


def near_duplicate(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return near_duplicate_reason(left, right) is not None


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
    if item.get("source_domain"):
        return str(item.get("source_domain", "")).lower().removeprefix("www.")
    url = item.get("canonical_url") or item.get("url") or item.get("original_url") or item.get("link", "")
    return (urlparse(url).hostname or "").lower().removeprefix("www.")


def suggests_product_announcement(text: str) -> bool:
    if any(term in text for term in ("crackdown", "sanction", "sanctions", "charged", "arrest", "arrested", "raid", "raids")):
        return False
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


def is_sponsored_vendor_content_signal(item: dict[str, Any]) -> bool:
    url = str(item.get("canonical_url") or item.get("url") or item.get("original_url") or "").lower()
    text = f"{item.get('title', '')} {item.get('source', '')} {url}".lower()
    return any(marker in text for marker in ("sponsor", "sponsored", "partner content", "/sponsor/"))


def classify_article_type(item: dict[str, Any]) -> str:
    domain = article_domain(item)
    source = item.get("source", "").lower()
    title = item.get("title", "").lower()
    summary = str(item.get("summary", "")).lower()
    article_excerpt = str(item.get("article_excerpt", "")).lower()
    haystack = f"{title} {source} {summary} {article_excerpt}"

    if is_sponsored_vendor_content_signal(item):
        return "Sponsored / vendor content"

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

    if any(term in haystack for term in ("raised $", "raises $", "funding", "startup", "founder raised", "series a", "series b")):
        if any(domain.endswith(host) for host in ("techcrunch.com", "theverge.com", "venturebeat.com")):
            return "Product/company profile"

    if any(domain.endswith(host) for host in HIGH_VALUE_INVESTIGATIVE_DOMAINS) and has_direct_scam_article_evidence(item):
        if any(term in haystack for term in INVESTIGATIVE_TERMS + ("network", "operation", "infrastructure", "compound", "syndicate", "underworld", "scammer")):
            return "Investigative report"

    if any(domain.endswith(host) for host in HIGH_VALUE_INVESTIGATIVE_DOMAINS + ("hai.stanford.edu", "fulcrum.sg")) and has_direct_scam_article_evidence(item):
        if any(term in haystack for term in DEEP_ANALYSIS_TERMS + ("ecosystem", "method", "methods", "playbook", "how scammers", "how fraudsters")):
            if any(term in haystack for term in ("policy", "regulation", "governance", "law")):
                return "Policy analysis"
            return "Deep analysis"

    if any(domain.endswith(host) for host in ("techcrunch.com", "theverge.com")) and any(
        term in haystack
        for term in (
            "scammer",
            "scammers",
            "abusing",
            "abuse",
            "phishing",
            "spam",
            "messaging limits",
            "limits",
            "deepfake",
            "identity verification",
            "platform",
            "microsoft",
            "whatsapp",
            "telegram",
            "tiktok",
            "meta",
        )
    ):
        if "deepfake" in haystack and any(term in haystack for term in ("scam", "scams", "fraud")) and not any(
            term in haystack for term in ("limits", "policy", "verification", "new tool", "launches", "announces")
        ):
            return "News report"
        if any(term in haystack for term in ("limits", "policy", "platform", "verification", "messaging", "whatsapp", "meta", "tiktok")):
            return "Policy / platform update"
        return "Technical article"

    if any(term in haystack for term in ("visa-exemption", "visa exemption", "scam ring", "scam rings", "syndicate")) and any(
        term in haystack for term in ("malaysia", "myanmar", "cambodia", "southeast asia", "transnational")
    ):
        return "News report"

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

    if any(domain.endswith(host) for host in ("wired.com", "reuters.com", "ft.com", "theguardian.com", "bbc.com", "therecord.media", "restofworld.org", "404media.co", "techcrunch.com", "theverge.com")):
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
    if article_type == "Product/company profile":
        if any(term in haystack for term in ("api", "dataset", "architecture", "detection method", "data source", "platform")):
            return "Product idea / data source"
        return "General context"
    if article_type == "Sponsored / vendor content":
        if any(term in haystack for term in ("fraud as a service", "faas", "deepfakes on demand", "deepfake", "phishing kit", "scam kit", "identity fraud")):
            return "Technical abuse / vulnerability"
        if any(term in haystack for term in PRODUCT_DATA_SOURCE_TERMS):
            return "Product idea / data source"
        if any(term in haystack for term in ("scam", "fraud", "phishing", "synthetic identity", "impersonation")):
            return "Scam development"
        return "General context"
    if any(term in haystack for term in ("deepfake scam", "voice cloning scam", "voice clone", "synthetic identity fraud", "impersonation scam")) or (
        "deepfake" in haystack and any(term in haystack for term in ("scam", "scams", "fraud"))
    ):
        return "Deepfakes, synthetic identity & impersonation"
    if any(
        term in haystack
        for term in (
            "visa-exemption",
            "visa exemption",
            "scam ring",
            "scam rings",
            "syndicate",
            "fake government official",
            "fake government officials",
        )
    ) and any(term in haystack for term in ("malaysia", "myanmar", "cambodia", "southeast asia", "transnational")):
        return "Operational intelligence"
    if any(term in haystack for term in ("reverse engineered", "vulnerability", "exploit", "bypass", "watermarking", "prompt injection", "rootkit", "scam kit", "attack tooling")):
        return "Technical abuse / vulnerability"
    if any(term in haystack for term in PRODUCT_DATA_SOURCE_TERMS):
        return "Product idea / data source"
    if article_type in {"Technical article", "Threat intelligence report"}:
        return "Detection / analytics / engineering insight"
    if any(
        term in haystack
        for term in (
            "hotline",
            "hot line",
            "compound",
            "trafficking",
            "infrastructure",
            "operation",
            "network",
            "call routing",
            "visa-exemption",
            "visa exemption",
            "scam ring",
            "scam rings",
            "syndicate",
            "fake government official",
            "fake government officials",
        )
    ):
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
            candidate.get("article_excerpt", ""),
            article_domain(candidate),
            extra_text,
        )
        if value
    ).lower()


def article_evidence_text(candidate: dict[str, Any], extra_text: str = "") -> str:
    return " ".join(
        str(value)
        for value in (
            candidate.get("title", ""),
            candidate.get("summary", ""),
            candidate.get("article_excerpt", ""),
            extra_text,
        )
        if value
    ).lower()


def has_direct_scam_article_evidence(candidate: dict[str, Any], extra_text: str = "") -> bool:
    text = article_evidence_text(candidate, extra_text)
    if terms_found(text, STRONG_SCAM_ANCHOR_TERMS):
        return True
    return any(
        term in text
        for term in (
            "social engineering",
            "phishing",
            "smishing",
            "vishing",
            "identity fraud",
            "online fraud",
            "cybercrime syndicate",
            "fraud syndicate",
            "fraud ring",
        )
    )


def is_low_signal_entertainment_item(candidate: dict[str, Any]) -> bool:
    return any(term in article_evidence_text(candidate) for term in LOW_SIGNAL_ENTERTAINMENT_TERMS)


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
    if is_low_signal_entertainment_item(candidate) and not has_direct_scam_article_evidence(candidate, extra_text):
        anti_scam_relevance = "irrelevant"
        hard_rejected = True
        rejection_reason = "entertainment_or_culture_no_scam_anchor"
    elif negative_terms and not strong_terms:
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
    elif article_type in {"Research paper", "Technical article", "Threat intelligence report"} and terms_found(
        title_context_text, RESEARCH_DIRECT_TITLE_TERMS
    ) and research_category not in {
        "generic_fraud_ml",
        "generic_cybersecurity",
        "generic_ai_security",
        "irrelevant_or_adjacent",
    }:
        anti_scam_relevance = "direct"
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
        "max_research_items_shortlist": 10,
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


def configured_research_reputation(config: dict[str, Any]) -> dict[str, Any]:
    defaults = {
        "high_reputation_venue_domains": (
            "ndss-symposium.org",
            "usenix.org",
            "dl.acm.org",
            "acm.org",
            "ieee.org",
            "computer.org",
            "petsymposium.org",
        ),
        "high_reputation_venue_terms": (
            "ACM Conference on Computer and Communications Security",
            "ACM CCS",
            "IEEE Symposium on Security and Privacy",
            "IEEE S&P",
            "USENIX Security",
            "Network and Distributed System Security Symposium",
            "NDSS",
            "Privacy Enhancing Technologies Symposium",
            "PETS",
        ),
        "high_reputation_institution_domains": (),
    }
    configured = config.get("research_reputation", {}) or {}
    return {**defaults, **configured}


def domains_in_text(text: str) -> set[str]:
    lowered = text.lower()
    domains = set()
    for match in re.findall(r"(?<![a-z0-9.-])([a-z0-9][a-z0-9.-]+\.[a-z]{2,})(?![a-z0-9.-])", lowered):
        domains.add(match.removeprefix("www."))
    return domains


def research_reputation_signals(candidate: dict[str, Any], config: dict[str, Any], extra_text: str = "") -> list[str]:
    article_type = candidate.get("article_type", classify_article_type(candidate))
    if article_type != "Research paper":
        return []

    reputation_config = configured_research_reputation(config)
    signals: list[str] = []
    domain = article_domain(candidate)
    for raw_domain in reputation_config.get("high_reputation_venue_domains", []) or []:
        venue_domain = str(raw_domain).lower().removeprefix("www.")
        if venue_domain and (domain == venue_domain or domain.endswith(f".{venue_domain}")):
            signals.append(f"venue:{venue_domain}")
            break

    text = candidate_relevance_text(candidate, extra_text)
    for raw_term in reputation_config.get("high_reputation_venue_terms", []) or []:
        term = str(raw_term).strip()
        if term and term.lower() in text:
            signal = f"venue_term:{term}"
            if signal not in signals:
                signals.append(signal)
            break

    text_domains = domains_in_text(text)
    for raw_domain in reputation_config.get("high_reputation_institution_domains", []) or []:
        institution_domain = str(raw_domain).lower().removeprefix("www.")
        if not institution_domain:
            continue
        if any(text_domain == institution_domain or text_domain.endswith(f".{institution_domain}") for text_domain in text_domains):
            signals.append(f"institution_domain:{institution_domain}")
            if len([signal for signal in signals if signal.startswith("institution_domain:")]) >= 3:
                break
    return signals


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


def article_excerpt_from_text(text: str, limit: int = 1400) -> str:
    cleaned = clean_summary_text(text, limit * 2)
    if not cleaned:
        return ""

    boilerplate_markers = (
        "comment loader",
        "save story",
        "sign up for our newsletters",
        "subscribe to our newsletter",
        "all rights reserved",
        "advertisement",
        "skip to main content",
    )
    sentences = [
        sentence.strip()
        for sentence in re.split(r"(?<=[.!?])\s+", cleaned)
        if sentence.strip() and not any(marker in sentence.lower() for marker in boilerplate_markers)
    ]
    excerpt = " ".join(sentences[:10]).strip()
    if not excerpt:
        excerpt = cleaned
    if len(excerpt) <= limit:
        return excerpt
    return excerpt[:limit].rsplit(" ", 1)[0].rstrip(" ,;:-") + "..."


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
        "article_excerpt": "",
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
    quality_data["article_excerpt"] = article_excerpt_from_text(visible_text)
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

    quality_data["research_reputation_signals"] = research_reputation_signals(candidate, config, visible_text)
    quality_data.update(relevance_fields(candidate, visible_text))
    if quality_cache is not None and cache_key:
        quality_cache[cache_key] = {
            **quality_data,
            "cache_version": QUALITY_CACHE_VERSION,
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
    return quality_data


def candidate_signal_text(item: dict[str, Any]) -> str:
    values = [
        item.get("title", ""),
        item.get("source", ""),
        item.get("summary", ""),
        item.get("article_excerpt", ""),
        article_domain(item),
        " ".join(item.get("strong_scam_anchor_terms_found", []) or []),
        " ".join(item.get("weak_generic_terms_found", []) or []),
        " ".join(item.get("technology_modus_terms_found", []) or []),
    ]
    return " ".join(str(value) for value in values if value).lower()


def item_domain_matches(item: dict[str, Any], domains: tuple[str, ...]) -> bool:
    domain = article_domain(item)
    return any(domain == host or domain.endswith(f".{host}") for host in domains)


def is_sponsored_vendor_item(item: dict[str, Any]) -> bool:
    return item.get("article_type", classify_article_type(item)) in {"Sponsored / vendor content", "Vendor blog"} or bool(
        item.get("press_release_or_sponsored")
    )


def is_relevant_sponsored_vendor_item(item: dict[str, Any]) -> bool:
    text = candidate_signal_text(item)
    usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
    return is_sponsored_vendor_item(item) and (
        usefulness_category
        in {
            "Technical abuse / vulnerability",
            "Scam development",
            "Product idea / data source",
            "Detection / analytics / engineering insight",
        }
        or any(
            term in text
            for term in (
                "fraud as a service",
                "faas",
                "deepfakes on demand",
                "deepfake abuse",
                "scam infrastructure",
                "scam methods",
                "phishing kit",
                "scam kit",
                "identity fraud",
                "synthetic identity",
                "platform abuse",
            )
        )
    )


def is_psychology_item(item: dict[str, Any]) -> bool:
    text = candidate_relevance_text(item)
    return any(
        term in text
        for term in (
            "victim psychology",
            "victim vulnerability",
            "user vulnerability",
            "psychological",
            "behavioral factors",
            "behavioural factors",
            "fraud victim",
            "scam victim",
            "persuasion",
            "grooming",
            "trust-building",
            "harmful persuasion",
            "decision making",
            "deception victim",
            "social engineering",
            "scammer victim conversation",
            "scam conversation",
            "parental pressure",
            "expectations were overwhelming",
            "online dating romance scams",
        )
    )


def is_llm_adverse_use_item(item: dict[str, Any]) -> bool:
    text = candidate_signal_text(item)
    return any(term in text for term in ("llm", "large language model", "benchmark", "evaluation", "eval")) and any(
        term in text
        for term in (
            "scam",
            "phishing",
            "fraud assistance",
            "harmful persuasion",
            "social engineering",
            "deception",
            "scammer",
        )
    )


def is_direct_research_item(item: dict[str, Any]) -> bool:
    return item.get("article_type", classify_article_type(item)) == "Research paper" and item.get(
        "anti_scam_relevance"
    ) == "direct"


def is_investigative_or_operational_item(item: dict[str, Any]) -> bool:
    article_type = item.get("article_type", classify_article_type(item))
    usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
    if article_type in {"Investigative report", "Deep analysis", "Policy analysis"} or usefulness_category == "Operational intelligence":
        return True
    if item_domain_matches(item, HIGH_VALUE_INVESTIGATIVE_DOMAINS):
        return has_direct_scam_article_evidence(item)
    return False


def is_modus_infrastructure_item(item: dict[str, Any]) -> bool:
    text = candidate_signal_text(item)
    return any(
        term in text
        for term in (
            "modus operandi",
            "scam infrastructure",
            "scam compound",
            "scam farm",
            "fraud syndicate",
            "fraud ring",
            "money mule",
            "mule account",
            "mule network",
            "sim box",
            "sim farm",
            "voip abuse",
            "bulk messaging",
            "fake accounts",
            "phishing kit",
            "scam kit",
            "fake website",
            "fake domains",
            "fake ad",
            "call centre",
            "call center",
            "platform abuse",
            "payment rails",
        )
    )


def is_sea_operational_intelligence_item(item: dict[str, Any]) -> bool:
    text = candidate_signal_text(item)
    return is_local_sea_item(item) and any(
        term in text
        for term in (
            "scam compound",
            "compound",
            "scam ring",
            "scam rings",
            "syndicate",
            "visa-exemption",
            "visa exemption",
            "policy abuse",
            "travel policy",
            "mule",
            "call centre",
            "call center",
            "fake government official",
            "fake government officials",
            "fake officer",
            "impersonation",
            "cross-border",
            "transnational",
            "trafficking",
            "cyber slavery",
            "myanmar",
            "cambodia",
            "malaysia",
        )
    )


def is_podcast_video_or_summary_item(item: dict[str, Any]) -> bool:
    text = candidate_signal_text(item)
    url = str(item.get("canonical_url") or item.get("url") or "").lower()
    return any(term in text for term in ("podcast", "video", "watch ", "summary", "roundup")) or any(
        marker in url for marker in ("/podcast", "/video", "/watch/")
    )


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

    quality_score += category_recency_adjustment(candidate, config, now)

    usefulness_boosts = {
        "Research / novel method": 75,
        "Product idea / data source": 65,
        "Technical abuse / vulnerability": 65,
        "Operational intelligence": 65,
        "Detection / analytics / engineering insight": 55,
        "Platform policy / product change": 65,
        "Local Singapore / Southeast Asia relevance": 25,
        "Deepfakes, synthetic identity & impersonation": 60,
        "Scam development": 30,
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
    research_reputation_signal_count = len(candidate.get("research_reputation_signals", []) or [])
    if article_type == "Research paper" and anti_scam_relevance == "direct" and research_reputation_signal_count:
        quality_score += min(35, 15 + research_reputation_signal_count * 10)

    has_scam_anchor = bool(candidate.get("strong_scam_anchor_terms_found"))
    if is_psychology_item(candidate):
        quality_score += 90
    if is_investigative_or_operational_item(candidate):
        quality_score += 85
    if is_direct_research_item(candidate):
        quality_score += 90
    if is_llm_adverse_use_item(candidate):
        quality_score += 85
    if is_modus_infrastructure_item(candidate):
        quality_score += 80
    if is_sea_operational_intelligence_item(candidate):
        quality_score += 60
    if is_platform_product_item(candidate):
        quality_score += 65
    if is_modus_infrastructure_item(candidate) and not is_local_sea_item(candidate):
        quality_score += 70

    if has_scam_anchor and candidate.get("technology_modus_terms_found"):
        quality_score += 35
    if has_scam_anchor and any(term in candidate.get("weak_generic_terms_found", []) + candidate.get("direct_relevance_terms_found", []) for term in ("persuasion", "grooming", "trust-building", "manipulation", "deception", "harmful persuasion")):
        quality_score += 40
    if has_scam_anchor and any(term in candidate.get("technology_modus_terms_found", []) for term in ("sim box", "mule networks", "phishing kits", "scam kits", "platform abuse", "fake accounts", "bulk messaging")):
        quality_score += 45
    if anti_scam_relevance == "direct" and usefulness_category == "Local Singapore / Southeast Asia relevance":
        quality_score += 10
    if usefulness_category == "Platform policy / product change" and anti_scam_relevance == "direct":
        quality_score += 65
    if usefulness_category == "Product idea / data source" and anti_scam_relevance == "direct":
        quality_score += 65

    if any(domain.endswith(host) for host in ("arxiv.org", "dl.acm.org", "ieee.org", "usenix.org", "ndss-symposium.org", "ssrn.com", "osf.io")):
        quality_score += 90 if is_direct_research_item(candidate) else 10
    elif any(domain.endswith(host) for host in ("c4ads.org", "wired.com", "404media.co", "restofworld.org", "graphika.com", "bellingcat.com")):
        quality_score += 85
    elif any(domain.endswith(host) for host in ("datasociety.net", "cetas.turing.ac.uk", "technologyreview.com", "aisi.gov.uk")):
        quality_score += 45
    elif any(domain.endswith(host) for host in ("therecord.media", "krebsonsecurity.com", "theverge.com", "techcrunch.com")):
        quality_score += 30
    elif any(domain.endswith(host) for host in ("police.gov.sg", "mas.gov.sg", "imda.gov.sg", "gov.sg", "csa.gov.sg", "fbi.gov", "europol.europa.eu", "interpol.int", "cisa.gov", "nist.gov")):
        quality_score += 30
    elif any(domain.endswith(host) for host in ("openai.com", "anthropic.com", "security.googleblog.com", "cloud.google.com", "mandiant.com", "microsoft.com")):
        quality_score += 25
    elif any(domain.endswith(host) for host in ("developers.cloudflare.com", "cloudflare.com")) and usefulness_category == "Product idea / data source":
        quality_score += 25
    elif any(domain.endswith(host) for host in ("straitstimes.com", "channelnewsasia.com", "cna.com.sg", "todayonline.com", "mothership.sg")) and usefulness_category == "Local Singapore / Southeast Asia relevance":
        quality_score += 10

    if article_type in {"Research paper", "Threat intelligence report", "Product / developer changelog"}:
        quality_score += 10
    if article_type in {"Investigative report", "Deep analysis", "Policy analysis", "Technical article"}:
        quality_score += 8
    if article_type == "Sponsored / vendor content" and is_relevant_sponsored_vendor_item(candidate):
        quality_score += 25
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
    if article_type == "Sponsored / vendor content":
        quality_score -= 20
    if article_type == "Product/company profile":
        quality_score -= 55
    if article_type == "Opinion / newsletter" and reputation != "high":
        quality_score -= 15
    if suggests_product_announcement(haystack) and usefulness_category not in {"Platform policy / product change", "Product idea / data source"}:
        quality_score -= 35
    if candidate.get("press_release_or_sponsored") or "press release" in haystack or "sponsored" in haystack or "partner content" in haystack:
        quality_score -= 10 if is_relevant_sponsored_vendor_item(candidate) else 45
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
    direct_title_terms = terms_found(title_context, RESEARCH_DIRECT_TITLE_TERMS)
    if candidate.get("hard_rejected"):
        return candidate.get("hard_rejection_reason") or "hard_rejected"
    if not is_within_candidate_recency_window(candidate, config, datetime.now(timezone.utc), False):
        return "outdated_article"
    if anti_scam_relevance == "irrelevant":
        return "irrelevant_anti_scam_relevance"
    if article_type in {"Research paper", "Technical article", "Threat intelligence report"} and not direct_title_terms:
        return "generic_research_or_technical"
    positive_research_category = research_category not in {
        "generic_fraud_ml",
        "generic_cybersecurity",
        "generic_ai_security",
        "irrelevant_or_adjacent",
    }
    has_direct_research_signal = bool(candidate.get("strong_scam_anchor_terms_found")) or (
        bool(direct_title_terms) and positive_research_category
    )
    if article_type in {"Research paper", "Technical article", "Threat intelligence report"} and (
        anti_scam_relevance != "direct" or not has_direct_research_signal
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
    high_rep_paywalled = candidate.get("access_status") == "paywalled_or_login" and is_high_reputation_source(candidate, config)
    if isinstance(word_count, int) and word_count < 300 and not high_rep_paywalled:
        return "thin_article"
    if candidate.get("salesy_vendor_pitch"):
        return "salesy_vendor_pitch"
    if candidate.get("press_release_or_sponsored") and not is_high_reputation_source(candidate, config) and not is_relevant_sponsored_vendor_item(candidate):
        return "press_release_or_sponsored"
    if article_type in {"Vendor blog", "Sponsored / vendor content"} and int(candidate.get("quality_score", 0)) < 20:
        return "low_quality_vendor_blog"
    if is_vendor_or_low_priority_source(candidate, config) and isinstance(word_count, int) and word_count < 800 and not high_rep_paywalled:
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
        candidate.setdefault("article_excerpt", "")
        candidate.setdefault("rejection_reason", None)
        candidate.setdefault("research_reputation_signals", research_reputation_signals(candidate, config))
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
            if not soft_final_rejection_allowed(candidate, config):
                candidate["quality_score"] = -999
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
            final_reason = final_ineligibility_reason(candidate, config, allow_adjacent=True)
            if final_reason:
                candidate["final_ineligibility_reason"] = final_reason
                candidate["rejection_reason"] = final_reason
                candidate["quality_rejected"] = True
                candidate["quality_score"] = -999
                stats["quality_rejected_candidate_count"] = stats.get("quality_rejected_candidate_count", 0) + 1
            else:
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


def is_platform_product_official_update_item(item: dict[str, Any]) -> bool:
    article_type = item.get("article_type", classify_article_type(item))
    usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
    return article_type in PLATFORM_PRODUCT_TYPES or article_type in {
        "Official report",
        "Advisory / guidance",
        "Product/company profile",
    } or usefulness_category in {
        "Platform policy / product change",
        "Product idea / data source",
    }


def is_local_sea_item(item: dict[str, Any]) -> bool:
    usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
    haystack = f"{item.get('title', '')} {article_domain(item)} {item.get('source', '')}".lower()
    return usefulness_category == "Local Singapore / Southeast Asia relevance" or any(term in haystack for term in LOCAL_SEA_TERMS)


def is_local_current_affairs_item(item: dict[str, Any]) -> bool:
    if is_sea_operational_intelligence_item(item):
        return False
    return is_local_sea_item(item) and item.get("article_type", classify_article_type(item)) in {
        "News report",
        "Enforcement report",
        "Official report",
        "Advisory / guidance",
    }


def is_plain_news_item(item: dict[str, Any]) -> bool:
    return item.get("article_type", classify_article_type(item)) == "News report"


def is_company_profile_item(item: dict[str, Any]) -> bool:
    article_type = item.get("article_type", classify_article_type(item))
    text = candidate_signal_text(item)
    return article_type == "Product/company profile" or (
        any(term in text for term in ("raised $", "raises $", "funding", "startup", "founder raised", "series a", "series b"))
        and not any(term in text for term in ("architecture", "api", "dataset", "technical", "detection method"))
    )


def is_research_psychology_item(item: dict[str, Any]) -> bool:
    return is_direct_research_item(item) or is_psychology_item(item)


def is_longform_investigative_item(item: dict[str, Any]) -> bool:
    article_type = item.get("article_type", classify_article_type(item))
    usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
    text = candidate_signal_text(item)
    scam_anchors = (
        "scam",
        "fraud",
        "phishing",
        "impersonation",
        "deepfake scam",
        "voice clone",
        "synthetic identity",
        "mule",
        "scam compound",
        "scam farm",
        "call centre",
        "call center",
        "cyber slavery",
        "pig butchering",
        "romance scam",
        "investment scam",
        "fake job",
        "fake ad",
        "fake website",
        "scammer",
        "victim",
        "social engineering",
    )
    operational_markers = (
        "network",
        "infrastructure",
        "syndicate",
        "compound",
        "operation",
        "modus operandi",
        "playbook",
        "platform abuse",
        "enforcement",
        "investigation",
        "victim journey",
        "payments",
        "mule",
        "sim",
        "voip",
        "phishing kit",
        "scam kit",
        "data source",
        "detection",
        "intervention",
    )
    has_investigative_shape = article_type in {"Investigative report", "Deep analysis", "Policy analysis"} or (
        usefulness_category != "General context"
        and is_investigative_or_operational_item(item)
        and item_domain_matches(item, HIGH_VALUE_INVESTIGATIVE_DOMAINS)
    )
    return has_investigative_shape and any(term in text for term in scam_anchors) and any(
        term in text for term in operational_markers
    )


def is_technical_platform_product_item(item: dict[str, Any]) -> bool:
    usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
    return is_technical_item(item) or is_platform_product_item(item) or usefulness_category in {
        "Technical abuse / vulnerability",
        "Detection / analytics / engineering insight",
        "Product idea / data source",
    }


def is_high_value_domain_item(item: dict[str, Any]) -> bool:
    domain = article_domain(item)
    return any(domain.endswith(host) for host in HIGH_VALUE_INVESTIGATIVE_DOMAINS + HIGH_VALUE_PRODUCT_DOMAINS)


def has_strong_product_radar_signal(item: dict[str, Any]) -> bool:
    text = candidate_signal_text(item)
    return item.get("anti_scam_relevance") == "direct" and (
        bool(item.get("strong_scam_anchor_terms_found"))
        or bool(item.get("technology_modus_terms_found"))
        or any(
            term in text
            for term in (
                "scammer",
                "scammers",
                "scam compound",
                "phishing kit",
                "scam kit",
                "deepfake",
                "voice clone",
                "synthetic identity",
                "platform abuse",
                "messaging limits",
                "identity verification",
                "infrastructure",
                "operation",
                "network",
                "abusing",
                "abuse",
            )
        )
    )


def is_high_value_product_radar_item(item: dict[str, Any]) -> bool:
    if not is_high_value_domain_item(item) or not has_strong_product_radar_signal(item):
        return False
    article_type = item.get("article_type", classify_article_type(item))
    usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
    if usefulness_category == "General context":
        return False
    return article_type in {
        "Investigative report",
        "Deep analysis",
        "Technical article",
        "Policy / platform update",
        "Product / developer changelog",
        "News report",
    } or usefulness_category in {
        "Operational intelligence",
        "Technical abuse / vulnerability",
        "Platform policy / product change",
        "Product idea / data source",
        "Detection / analytics / engineering insight",
        "Scam development",
    }


def is_research_item(item: dict[str, Any]) -> bool:
    return item.get("article_type", classify_article_type(item)) == "Research paper"


def is_research_or_product_idea_item(item: dict[str, Any]) -> bool:
    usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
    return is_research_item(item) or usefulness_category == "Product idea / data source"


def is_exceptional_research_item(item: dict[str, Any]) -> bool:
    if not is_research_item(item):
        return False
    if item.get("anti_scam_relevance") != "direct":
        return False
    text = candidate_signal_text(item)
    exceptional_markers = (
        "victim as a service",
        "interactive scammers",
        "scam victim",
        "victim psychology",
        "persuasion",
        "grooming",
        "harmful persuasion",
        "romance scam",
        "pig butchering",
        "scammer victim conversation",
        "scam detection",
        "scam intervention",
        "fraud as a service",
        "deepfake scam",
        "voice clone",
        "synthetic identity fraud",
    )
    return (
        int(item.get("quality_score") or 0) >= 450
        and int(item.get("research_relevance_score") or 0) >= 55
        and (is_psychology_item(item) or any(marker in text for marker in exceptional_markers))
    )


def is_non_academic_longform_operational_item(item: dict[str, Any]) -> bool:
    if is_research_item(item):
        return False
    article_type = item.get("article_type", classify_article_type(item))
    usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
    return (
        is_longform_investigative_item(item)
        or usefulness_category == "Operational intelligence"
        or article_type in {"Investigative report", "Deep analysis"}
    )


def soft_final_rejection_allowed(item: dict[str, Any], config: dict[str, Any] | None = None) -> bool:
    reason = item.get("rejection_reason")
    if reason not in SOFT_FINAL_REJECTION_REASONS:
        return False
    return not config or is_high_reputation_source(item, config)


def final_ineligibility_reason(
    item: dict[str, Any],
    config: dict[str, Any] | None = None,
    *,
    allow_adjacent: bool = False,
) -> str | None:
    item = corrected_final_item(item)
    article_type = item.get("article_type", classify_article_type(item))
    usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
    relevance = item.get("anti_scam_relevance", "weak")
    rejection_reason = item.get("rejection_reason")
    if item.get("hard_rejected"):
        return item.get("hard_rejection_reason") or "hard_rejected"
    if rejection_reason:
        if rejection_reason in FINAL_DISALLOWED_REJECTION_REASONS:
            return rejection_reason
        if not soft_final_rejection_allowed(item, config):
            return rejection_reason
    if usefulness_category == "General context":
        return "general_context"
    if article_type == "Other":
        return "other_article_type"
    if config and is_vendor_or_low_priority_source(item, config) and is_sponsored_vendor_item(item) and not is_relevant_sponsored_vendor_item(item):
        return "low_quality_vendor_spam"
    if relevance == "direct":
        return None
    if allow_adjacent and relevance == "adjacent" and usefulness_category in {
        "Platform policy / product change",
        "Operational intelligence",
        "Technical abuse / vulnerability",
        "Product idea / data source",
    }:
        return None
    return f"{relevance}_anti_scam_relevance"


def is_strict_final_eligible(item: dict[str, Any], config: dict[str, Any] | None = None) -> bool:
    return final_ineligibility_reason(item, config, allow_adjacent=False) is None


def is_relaxed_final_eligible(item: dict[str, Any], config: dict[str, Any] | None = None) -> bool:
    return final_ineligibility_reason(item, config, allow_adjacent=True) is None


def is_final_allowed_relevance(item: dict[str, Any]) -> bool:
    relevance = item.get("anti_scam_relevance", "weak")
    if is_relevant_sponsored_vendor_item(item):
        return item.get("anti_scam_relevance") in {"direct", "adjacent"} or bool(item.get("strong_scam_anchor_terms_found"))
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


def corrected_final_item(item: dict[str, Any]) -> dict[str, Any]:
    corrected = dict(item)
    title_text = candidate_relevance_text(corrected)
    article_type = corrected.get("article_type", classify_article_type(corrected))
    if is_sponsored_vendor_content_signal(corrected):
        corrected["article_type"] = "Sponsored / vendor content"
        if corrected.get("usefulness_category") == "General context":
            corrected["usefulness_category"] = classify_usefulness_category(corrected)
    if article_type == "Technical article" and any(term in title_text for term in ENFORCEMENT_TERMS):
        technical_markers = (
            "phishing kit",
            "scam kit",
            "malware",
            "vulnerability",
            "api",
            "dataset",
            "detection method",
            "reverse engineered",
            "architecture",
        )
        if not any(term in title_text for term in technical_markers):
            corrected["article_type"] = "Enforcement report"
            if corrected.get("usefulness_category") == "Technical abuse / vulnerability":
                corrected["usefulness_category"] = "Scam development"
    if "visa" in title_text and "scam" in title_text and any(term in title_text for term in ("ring", "rings", "syndicate", "policy", "exemption")):
        corrected["usefulness_category"] = "Operational intelligence"
    if "fake" in title_text and any(term in title_text for term in ("government official", "government officials", "officer")):
        corrected["article_type"] = "Enforcement report"
        if corrected.get("usefulness_category") == "General context":
            corrected["usefulness_category"] = "Scam development"
    return corrected


def final_selection_score(item: dict[str, Any]) -> int:
    score = int(item.get("quality_score") or 0)
    if is_direct_research_item(item):
        score += 90
    if is_psychology_item(item):
        score += 90
    if is_llm_adverse_use_item(item):
        score += 85
    if is_investigative_or_operational_item(item):
        score += 85
    if is_modus_infrastructure_item(item):
        score += 80
    if is_sea_operational_intelligence_item(item):
        score += 60
    if is_platform_product_item(item):
        score += 65
    if is_high_value_product_radar_item(item):
        score += 45
    if is_local_sea_item(item):
        score += 35
    if is_relevant_sponsored_vendor_item(item):
        score += 25
    if item.get("article_type", classify_article_type(item)) == "Enforcement report":
        score -= 20
    if is_company_profile_item(item):
        score -= 70
    if is_plain_news_item(item) and not is_high_value_product_radar_item(item):
        score -= 15
    if is_sponsored_vendor_item(item) and not is_relevant_sponsored_vendor_item(item):
        score -= 80
    if is_podcast_video_or_summary_item(item):
        score -= 45
    return score


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
        if any(same_story_by_signature(item, seen_item) or near_duplicate(item, seen_item) for seen_item in deduped):
            continue
        seen_urls.update(url for url in urls if url)
        seen_fingerprints.append(fingerprint)
        deduped.append(item)
    return deduped


def dedupe_near_duplicates(
    items: list[dict[str, Any]],
    stats: dict[str, Any] | None = None,
    prefix: str = "duplicates",
    examples_limit: int = 5,
) -> list[dict[str, Any]]:
    ordered = sorted(
        items,
        key=lambda item: (final_selection_score(item), int(item.get("quality_score") or 0), int(item.get("original_score") or 0), item.get("title", "")),
        reverse=True,
    )
    kept: list[dict[str, Any]] = []
    removed_examples: list[dict[str, str]] = []
    removed_count = 0
    for item in ordered:
        duplicate_of = None
        duplicate_reason = None
        for kept_item in kept:
            duplicate_reason = near_duplicate_reason(item, kept_item)
            if duplicate_reason:
                duplicate_of = kept_item
                break
        if duplicate_of:
            removed_count += 1
            if duplicate_reason == "same_longform_investigation_prefer_full_article":
                if stats is not None:
                    stats["duplicate_podcast_or_summary_removed_count"] = stats.get("duplicate_podcast_or_summary_removed_count", 0) + 1
            if len(removed_examples) < examples_limit:
                removed_examples.append(
                    {
                        "removed_title": display_title(item.get("title", "")),
                        "kept_title": display_title(duplicate_of.get("title", "")),
                        "reason": duplicate_reason or "near_duplicate",
                    }
                )
            continue
        kept.append(item)
    if stats is not None:
        stats[f"{prefix}_duplicates_removed_count"] = stats.get(f"{prefix}_duplicates_removed_count", 0) + removed_count
        stats.setdefault(f"{prefix}_duplicate_examples", []).extend(removed_examples)
    return kept


def near_duplicate_pairs(items: list[dict[str, Any]]) -> list[dict[str, str]]:
    pairs: list[dict[str, str]] = []
    for left_index, left in enumerate(items):
        for right in items[left_index + 1 :]:
            reason = near_duplicate_reason(left, right)
            if reason:
                pairs.append(
                    {
                        "left_title": display_title(left.get("title", "")),
                        "right_title": display_title(right.get("title", "")),
                        "reason": reason,
                    }
                )
    return pairs


def build_quality_shortlist(
    ranked_candidates: list[dict[str, Any]],
    shortlist_count: int,
    config: dict[str, Any],
) -> list[dict[str, Any]]:
    pool = [
        item
        for item in dedupe_final_items(ranked_candidates)
        if not item.get("quality_rejected")
        and not item.get("hard_rejected")
        and not item.get("rejection_reason")
        and is_strict_final_eligible(item, config)
    ]
    pool = sorted(pool, key=final_selection_score, reverse=True)
    shortlist: list[dict[str, Any]] = []
    domain_counts: dict[str, int] = {}
    local_current_affairs_count = 0
    local_total_count = 0
    plain_news_count = 0
    company_profile_count = 0
    sponsored_vendor_count = 0
    research_count = 0
    max_research_items = min(
        shortlist_count,
        int(quality_config(config).get("max_research_items_shortlist", max(1, shortlist_count // 2))),
    )

    def can_add(item: dict[str, Any], *, strict: bool = True) -> bool:
        if item in shortlist:
            return False
        if len(dedupe_final_items(shortlist + [item])) == len(shortlist):
            return False
        if not strict:
            return True
        domain = article_domain(item)
        domain_limit = 4 if any(domain.endswith(host) for host in ("arxiv.org", "ssrn.com", "osf.io", "dl.acm.org", "ieee.org", "usenix.org", "ndss-symposium.org")) else 2
        if is_high_value_product_radar_item(item):
            domain_limit = max(domain_limit, 3)
        if domain_counts.get(domain, 0) >= domain_limit:
            return False
        if is_research_item(item) and research_count >= max_research_items:
            return False
        local_limit = 3 if is_sea_operational_intelligence_item(item) else 2
        if is_local_sea_item(item) and local_total_count >= local_limit:
            return False
        if is_local_current_affairs_item(item) and local_current_affairs_count >= 2:
            return False
        if is_plain_news_item(item) and plain_news_count >= 3 and not is_high_value_product_radar_item(item):
            return False
        if is_company_profile_item(item) and company_profile_count >= 1:
            return False
        if is_sponsored_vendor_item(item) and sponsored_vendor_count >= 1:
            return False
        if is_sponsored_vendor_item(item) and not is_relevant_sponsored_vendor_item(item):
            return False
        return True

    def add_item(item: dict[str, Any]) -> None:
        nonlocal local_current_affairs_count, local_total_count, plain_news_count, company_profile_count, sponsored_vendor_count, research_count
        shortlist.append(item)
        domain = article_domain(item)
        domain_counts[domain] = domain_counts.get(domain, 0) + 1
        if is_research_item(item):
            research_count += 1
        if is_local_sea_item(item):
            local_total_count += 1
        if is_local_current_affairs_item(item):
            local_current_affairs_count += 1
        if is_plain_news_item(item) and not is_high_value_product_radar_item(item):
            plain_news_count += 1
        if is_company_profile_item(item):
            company_profile_count += 1
        if is_sponsored_vendor_item(item):
            sponsored_vendor_count += 1

    def add_bucket(predicate: Any, target: int, *, strict: bool = True) -> None:
        added = 0
        for item in pool:
            if added >= target or len(shortlist) >= shortlist_count:
                break
            if predicate(item) and can_add(item, strict=strict):
                add_item(item)
                added += 1

    def add_bucket_prefer_non_research(predicate: Any, target: int, *, strict: bool = True) -> None:
        added = 0
        for prefer_research in (False, True):
            for item in pool:
                if added >= target or len(shortlist) >= shortlist_count:
                    return
                if is_research_item(item) != prefer_research:
                    continue
                if predicate(item) and can_add(item, strict=strict):
                    add_item(item)
                    added += 1

    add_bucket(is_non_academic_longform_operational_item, 4)
    add_bucket(is_longform_investigative_item, 3)
    add_bucket_prefer_non_research(lambda item: is_modus_infrastructure_item(item) or item.get("usefulness_category") == "Operational intelligence", 3)
    add_bucket_prefer_non_research(is_technical_platform_product_item, 3)
    add_bucket(is_research_psychology_item, 2)
    add_bucket(is_local_sea_item, 2)

    for item in pool:
        if len(shortlist) >= shortlist_count:
            break
        if can_add(item):
            add_item(item)

    return dedupe_final_items(shortlist)[:shortlist_count]


def eligible_for_shortlist(item: dict[str, Any], config: dict[str, Any] | None = None, *, relaxed: bool = False) -> bool:
    final_eligible = is_relaxed_final_eligible(item, config) if relaxed else is_strict_final_eligible(item, config)
    return (
        not item.get("quality_rejected")
        and not item.get("hard_rejected")
        and (not item.get("rejection_reason") or soft_final_rejection_allowed(item, config))
        and final_eligible
    )


def candidate_identity(item: dict[str, Any]) -> str:
    return canonicalize_url_text(item.get("canonical_url") or item.get("url") or item.get("original_url") or item.get("id", ""))


def identify_must_include_candidates(items: list[dict[str, Any]], config: dict[str, Any]) -> list[dict[str, Any]]:
    pool = sorted((item for item in items if eligible_for_shortlist(item, config)), key=final_selection_score, reverse=True)
    chosen: list[dict[str, Any]] = []
    chosen_keys: set[str] = set()
    buckets: list[tuple[Any, str]] = [
        (
            is_non_academic_longform_operational_item,
            "Best available non-academic longform / investigative / operational-intelligence item",
        ),
        (is_research_psychology_item, "Best available directly relevant research / psychology / victimology item"),
        (is_longform_investigative_item, "Best available longform investigative / deep analysis item"),
        (
            lambda item: is_modus_infrastructure_item(item) or item.get("usefulness_category") == "Operational intelligence",
            "Best available scam infrastructure / modus-operandi / operational-intelligence item",
        ),
        (is_technical_platform_product_item, "Best available technical / platform / product / data-source item"),
    ]
    for predicate, reason in buckets:
        for item in pool:
            key = candidate_identity(item)
            if key in chosen_keys:
                continue
            if predicate(item):
                must_item = dict(item)
                must_item["must_include_if_available"] = True
                must_item["must_include_reason"] = reason
                chosen.append(must_item)
                chosen_keys.add(key)
                break
    return chosen


def ensure_must_include_in_shortlist(
    shortlist: list[dict[str, Any]],
    must_include: list[dict[str, Any]],
    shortlist_count: int,
) -> list[dict[str, Any]]:
    updated = [dict(item) for item in shortlist]
    for must_item in must_include:
        must_key = candidate_identity(must_item)
        matched = False
        for index, item in enumerate(updated):
            if candidate_identity(item) == must_key:
                merged = dict(item)
                merged["must_include_if_available"] = True
                merged["must_include_reason"] = must_item.get("must_include_reason")
                updated[index] = merged
                matched = True
                break
        if matched:
            continue

        candidate = dict(must_item)
        if len(dedupe_final_items(updated + [candidate])) == len(updated):
            continue
        if len(updated) < shortlist_count:
            updated.append(candidate)
            continue

        replacement_index = next(
            (
                index
                for index, item in sorted(
                    enumerate(updated),
                    key=lambda pair: (
                        bool(pair[1].get("must_include_if_available")),
                        final_selection_score(pair[1]),
                    ),
                )
                if not item.get("must_include_if_available")
            ),
            None,
        )
        if replacement_index is not None and final_selection_score(candidate) > final_selection_score(updated[replacement_index]):
            updated[replacement_index] = candidate

    return dedupe_final_items(updated)[:shortlist_count]


def build_pre_gemini_shortlist(
    ranked_candidates: list[dict[str, Any]],
    shortlist_count: int,
    config: dict[str, Any],
    stats: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    deduped_candidates = dedupe_near_duplicates(ranked_candidates, stats, "pre_gemini")
    shortlist = build_quality_shortlist(deduped_candidates, shortlist_count, config)
    must_include = identify_must_include_candidates(deduped_candidates, config)
    shortlist = ensure_must_include_in_shortlist(shortlist, must_include, shortlist_count)
    category_predicates: dict[str, Any] = {
        "research_psychology": is_research_psychology_item,
        "non_academic_longform_operational": is_non_academic_longform_operational_item,
        "longform_investigative": is_longform_investigative_item,
        "modus_infrastructure": lambda item: is_modus_infrastructure_item(item) or item.get("usefulness_category") == "Operational intelligence",
        "technical_platform_product": is_technical_platform_product_item,
        "singapore_sea": is_local_sea_item,
    }
    stats["category_slot_fill_counts"] = {
        name: sum(1 for item in shortlist if predicate(item))
        for name, predicate in category_predicates.items()
    }
    stats["category_candidate_available_counts"] = {
        name: sum(1 for item in deduped_candidates if eligible_for_shortlist(item, config) and predicate(item))
        for name, predicate in category_predicates.items()
    }
    stats["research_candidates_available_count"] = stats["category_candidate_available_counts"].get("research_psychology", 0)
    stats["non_academic_longform_operational_candidates_available_count"] = stats["category_candidate_available_counts"].get(
        "non_academic_longform_operational", 0
    )
    stats["longform_investigative_candidates_available_count"] = stats["category_candidate_available_counts"].get("longform_investigative", 0)
    stats["must_include_candidates"] = [
        {
            "title": display_title(item.get("title", "")),
            "url": item.get("canonical_url") or item.get("url") or "",
            "reason": item.get("must_include_reason"),
            "article_type": item.get("article_type", classify_article_type(item)),
            "usefulness_category": item.get("usefulness_category", classify_usefulness_category(item)),
        }
        for item in must_include
    ]
    return deduped_candidates, shortlist


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
    min_items = int(config.get("min_articles_to_send", 3))
    items = [corrected_final_item(item) for item in items]
    eligible_items = [
        item
        for item in items
        if is_strict_final_eligible(item, config) and int(item.get("quality_score") or 0) >= min_quality_score
    ]
    items = sorted(dedupe_final_items(eligible_items), key=final_selection_score, reverse=True)
    selected: list[dict[str, Any]] = []

    def can_add(item: dict[str, Any], *, strict: bool = True) -> bool:
        if item in selected:
            return False
        trial = dedupe_final_items(selected + [item])
        if len(trial) == len(selected):
            return False
        article_type = item.get("article_type", classify_article_type(item))
        if strict:
            if is_local_current_affairs_item(item) and sum(1 for selected_item in selected if is_local_current_affairs_item(selected_item)) >= 1:
                return False
            local_limit = 3 if is_sea_operational_intelligence_item(item) else 2
            if is_local_sea_item(item) and sum(1 for selected_item in selected if is_local_sea_item(selected_item)) >= local_limit:
                return False
            if article_type == "Enforcement report" and sum(
                1 for selected_item in selected if selected_item.get("article_type", classify_article_type(selected_item)) == "Enforcement report"
            ) >= 2:
                return False
            if (
                is_plain_news_item(item)
                and not is_high_value_product_radar_item(item)
                and sum(1 for selected_item in selected if is_plain_news_item(selected_item) and not is_high_value_product_radar_item(selected_item)) >= 2
            ):
                return False
            if is_company_profile_item(item) and sum(1 for selected_item in selected if is_company_profile_item(selected_item)) >= 1:
                return False
            if is_sponsored_vendor_item(item) and sum(1 for selected_item in selected if is_sponsored_vendor_item(selected_item)) >= 1:
                return False
            if is_sponsored_vendor_item(item) and not is_relevant_sponsored_vendor_item(item):
                return False
            if (
                is_research_item(item)
                and sum(1 for selected_item in selected if is_research_item(selected_item)) >= 2
                and not is_exceptional_research_item(item)
            ):
                return False
            if source_domain_cap_exceeded(trial):
                return False
        return True

    def add_match(predicate: Any, *, strict: bool = True) -> None:
        if len(selected) >= max_items:
            return
        if any(predicate(item) for item in selected):
            return
        match = next((item for item in items if predicate(item) and can_add(item, strict=strict)), None)
        if match:
            selected.append(match)

    add_match(is_non_academic_longform_operational_item)
    add_match(is_psychology_item)
    add_match(is_investigative_or_operational_item)
    add_match(is_direct_research_item)
    add_match(is_platform_product_item)
    add_match(is_modus_infrastructure_item)
    add_match(is_technical_item)
    add_match(is_deep_analysis_item)
    add_match(is_platform_product_item)
    add_match(is_scam_development_item)
    add_match(is_local_sea_item, strict=True)

    max_vendor_items = int(quality_config(config).get("max_vendor_blog_items_final", 1))
    vendor_count = sum(1 for item in selected if item.get("article_type", classify_article_type(item)) == "Vendor blog")
    plain_news_count = sum(1 for item in selected if is_plain_news_item(item) and not is_high_value_product_radar_item(item))
    enforcement_count = sum(
        1 for item in selected if item.get("article_type", classify_article_type(item)) == "Enforcement report"
    )
    local_current_affairs_count = sum(1 for item in selected if is_local_current_affairs_item(item))
    local_total_count = sum(1 for item in selected if is_local_sea_item(item))
    company_profile_count = sum(1 for item in selected if is_company_profile_item(item))
    sponsored_vendor_count = sum(1 for item in selected if is_sponsored_vendor_item(item))
    research_product_count = sum(1 for item in selected if is_research_or_product_idea_item(item))
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
        if not can_add(item, strict=True):
            continue
        if usefulness_category == "General context":
            continue
        if article_type == "Vendor blog":
            if vendor_count >= max_vendor_items or usefulness_category not in {
                "Technical abuse / vulnerability",
                "Product idea / data source",
                "Detection / analytics / engineering insight",
            }:
                continue
        if is_research_item(item) and research_count >= 2:
            if not is_exceptional_research_item(item):
                continue
        if is_research_or_product_idea_item(item) and research_product_count >= 2 and len(selected) < 5:
            continue
        if is_plain_news_item(item) and not is_high_value_product_radar_item(item) and plain_news_count >= 2:
            continue
        if article_type == "Enforcement report":
            if enforcement_count >= 2:
                continue
        if is_local_current_affairs_item(item):
            if local_current_affairs_count >= 1:
                continue
        if is_local_sea_item(item):
            local_limit = 3 if is_sea_operational_intelligence_item(item) else 2
            if local_total_count >= local_limit:
                continue
        if is_sponsored_vendor_item(item):
            if sponsored_vendor_count >= 1 or not is_relevant_sponsored_vendor_item(item):
                continue
        if is_company_profile_item(item):
            if company_profile_count >= 1:
                continue
        if source_domain_cap_exceeded(dedupe_final_items(selected + [item])):
            continue
        if article_type == "Vendor blog":
            vendor_count += 1
        if is_research_item(item):
            research_count += 1
        if is_research_or_product_idea_item(item):
            research_product_count += 1
        if is_plain_news_item(item) and not is_high_value_product_radar_item(item):
            plain_news_count += 1
        if article_type == "Enforcement report":
            enforcement_count += 1
        if is_local_current_affairs_item(item):
            local_current_affairs_count += 1
        if is_local_sea_item(item):
            local_total_count += 1
        if is_company_profile_item(item):
            company_profile_count += 1
        if is_sponsored_vendor_item(item):
            sponsored_vendor_count += 1
        if article_type == "Advisory / guidance" and usefulness_category == "General context":
            if generic_advisory_count >= 1:
                continue
            generic_advisory_count += 1
        selected.append(item)
        if len(selected) >= max_items:
            break

    return dedupe_final_items(selected)[:max_items]


def research_cap_exceeded(items: list[dict[str, Any]]) -> bool:
    research_items = [item for item in items if is_research_item(item)]
    if len(research_items) <= 2:
        return False
    return any(not is_exceptional_research_item(item) for item in research_items)


def short_research_product_cap_exceeded(items: list[dict[str, Any]]) -> bool:
    return 3 <= len(items) <= 5 and sum(1 for item in items if is_research_or_product_idea_item(item)) > 2


def source_domain_over_limit_groups(items: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    by_domain: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        domain = article_domain(item)
        if not domain:
            continue
        by_domain.setdefault(domain, []).append(item)

    too_many_non_research: set[str] = set()
    too_many_total: set[str] = set()
    for domain, domain_items in by_domain.items():
        if sum(1 for item in domain_items if not is_research_item(item)) > 1:
            too_many_non_research.add(domain)
        if len(domain_items) > 2:
            too_many_total.add(domain)
    return too_many_non_research, too_many_total


def source_domain_cap_exceeded(items: list[dict[str, Any]]) -> bool:
    too_many_non_research, too_many_total = source_domain_over_limit_groups(items)
    return bool(too_many_non_research or too_many_total)


def final_cap_failures(items: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    if any(final_ineligibility_reason(item) for item in items):
        failures.append("contains_final_ineligible_items")
    if any(item.get("usefulness_category", classify_usefulness_category(item)) == "General context" for item in items):
        failures.append("contains_general_context")
    if any(item.get("anti_scam_relevance") == "weak" for item in items):
        failures.append("contains_weak_anti_scam_relevance")
    if any(item.get("rejection_reason") for item in items):
        failures.append("contains_rejected_items")
    if sum(1 for item in items if is_local_current_affairs_item(item)) > 1:
        failures.append("too_many_singapore_current_affairs")
    if sum(1 for item in items if is_local_sea_item(item)) > 3 or (
        sum(1 for item in items if is_local_sea_item(item)) > 2
        and not any(is_sea_operational_intelligence_item(item) for item in items if is_local_sea_item(item))
    ):
        failures.append("too_many_singapore_sea_items")
    if sum(1 for item in items if item.get("article_type", classify_article_type(item)) == "Enforcement report") > 2:
        failures.append("too_many_enforcement_reports")
    if sum(1 for item in items if is_plain_news_item(item) and not is_high_value_product_radar_item(item)) > 2:
        failures.append("too_many_plain_news_reports")
    if sum(1 for item in items if is_company_profile_item(item)) > 1:
        failures.append("too_many_company_profiles")
    if sum(1 for item in items if is_sponsored_vendor_item(item)) > 1:
        failures.append("too_many_sponsored_vendor_items")
    if research_cap_exceeded(items):
        failures.append("too_many_research_items")
    if short_research_product_cap_exceeded(items):
        failures.append("too_many_research_or_product_idea_items_for_short_digest")
    if source_domain_cap_exceeded(items):
        failures.append("too_many_from_same_source_domain")
    return failures


def removal_score(item: dict[str, Any]) -> int:
    score = final_selection_score(item)
    if item.get("must_include_if_available"):
        score += 500
    if is_non_academic_longform_operational_item(item):
        score += 320
    elif is_longform_investigative_item(item):
        score += 280
    elif is_research_psychology_item(item):
        score += 170 if is_exceptional_research_item(item) else 110
    if is_modus_infrastructure_item(item) or is_technical_platform_product_item(item):
        score += 150
    if is_sea_operational_intelligence_item(item):
        score += 120
    if is_relevant_sponsored_vendor_item(item):
        score += 40
    if is_podcast_video_or_summary_item(item):
        score -= 220
    if is_company_profile_item(item):
        score -= 160
    if is_local_current_affairs_item(item):
        score -= 140
    if item.get("article_type", classify_article_type(item)) == "Enforcement report":
        score -= 120
    if is_plain_news_item(item) and not is_high_value_product_radar_item(item):
        score -= 80
    if is_sponsored_vendor_item(item):
        score -= 80 if is_relevant_sponsored_vendor_item(item) else 180
    if is_research_or_product_idea_item(item) and not is_exceptional_research_item(item):
        score -= 40
    return score


def remove_weakest_item(
    items: list[dict[str, Any]],
    protected_keys: set[str] | None = None,
    predicate: Any | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    protected_keys = protected_keys or set()
    removable = [
        item
        for item in items
        if candidate_identity(item) not in protected_keys and (predicate(item) if predicate else True)
    ]
    if not removable:
        return items, None
    weakest = min(removable, key=removal_score)
    return [item for item in items if item is not weakest], weakest


def make_room_for_candidate(
    selected: list[dict[str, Any]],
    candidate: dict[str, Any],
    max_items: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    candidate = dict(candidate)
    if len(dedupe_final_items(selected + [candidate])) == len(selected):
        return selected, []
    candidate_key = candidate_identity(candidate)
    trial = dedupe_final_items(selected + [candidate])
    removed: list[dict[str, Any]] = []
    while len(trial) > max_items or final_cap_failures(trial):
        trial, removed_item = remove_weakest_item(trial, {candidate_key})
        if removed_item is None:
            return selected, removed
        removed.append(removed_item)
        if candidate_key not in {candidate_identity(item) for item in trial}:
            return selected, removed
    return trial, removed


def trim_final_caps(items: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    trimmed = list(items)
    removed: list[dict[str, Any]] = []
    cap_rules: list[tuple[Any, int]] = [
        (is_local_current_affairs_item, 1),
        (lambda item: is_local_sea_item(item) and not is_sea_operational_intelligence_item(item), 2),
        (is_local_sea_item, 3),
        (lambda item: item.get("article_type", classify_article_type(item)) == "Enforcement report", 2),
        (lambda item: is_plain_news_item(item) and not is_high_value_product_radar_item(item), 2),
        (is_company_profile_item, 1),
        (is_sponsored_vendor_item, 1),
    ]
    for predicate, limit in cap_rules:
        while sum(1 for item in trimmed if predicate(item)) > limit:
            trimmed, removed_item = remove_weakest_item(trimmed, predicate=predicate)
            if removed_item is None:
                break
            removed.append(removed_item)

    while research_cap_exceeded(trimmed):
        trimmed, removed_item = remove_weakest_item(
            trimmed,
            predicate=lambda item: is_research_item(item) and not is_exceptional_research_item(item),
        )
        if removed_item is None:
            break
        removed.append(removed_item)

    while short_research_product_cap_exceeded(trimmed):
        trimmed, removed_item = remove_weakest_item(trimmed, predicate=is_research_or_product_idea_item)
        if removed_item is None:
            break
        removed.append(removed_item)

    while source_domain_cap_exceeded(trimmed):
        too_many_non_research, too_many_total = source_domain_over_limit_groups(trimmed)
        if too_many_non_research:
            trimmed, removed_item = remove_weakest_item(
                trimmed,
                predicate=lambda item: article_domain(item) in too_many_non_research and not is_research_item(item),
            )
        else:
            trimmed, removed_item = remove_weakest_item(
                trimmed,
                predicate=lambda item: article_domain(item) in too_many_total,
            )
        if removed_item is None:
            break
        removed.append(removed_item)
    return trimmed, removed


def preferred_final_max_items(config: dict[str, Any], max_items: int) -> int:
    return min(max_items, int(config.get("preferred_max_articles_to_send", 8)))


def trim_to_preferred_final_count(
    items: list[dict[str, Any]],
    config: dict[str, Any],
    available_items: list[dict[str, Any]],
    max_items: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    preferred_max = preferred_final_max_items(config, max_items)
    min_items = int(config.get("min_articles_to_send", 3))
    trimmed = list(items)
    removed: list[dict[str, Any]] = []
    while len(trimmed) > preferred_max and len(trimmed) > min_items:
        protected: set[str] = set()
        for predicate in (
            is_psychology_item,
            is_longform_investigative_item,
            is_modus_infrastructure_item,
            is_technical_platform_product_item,
        ):
            if any(predicate(item) for item in available_items):
                best_present = next((item for item in sorted(trimmed, key=final_selection_score, reverse=True) if predicate(item)), None)
                if best_present:
                    protected.add(candidate_identity(best_present))
        trial, removed_item = remove_weakest_item(trimmed, protected)
        if removed_item is None:
            break
        if final_mix_constraint_failures(trial, min_items, max_items, available_items):
            unprotected_trial, removed_item = remove_weakest_item(trimmed)
            if removed_item is None:
                break
            trial = unprotected_trial
        trimmed = trial
        removed.append(removed_item)
    return trimmed, removed


def repair_final_selection(
    selected_items: list[dict[str, Any]],
    available_items: list[dict[str, Any]],
    config: dict[str, Any],
    max_items: int,
    stats: dict[str, Any],
) -> list[dict[str, Any]]:
    min_quality_score = int(config.get("min_final_quality_score", 80))
    strict_available = sorted(
        dedupe_final_items(
            [
                corrected_final_item(item)
                for item in available_items
                if eligible_for_shortlist(item, config) and int(item.get("quality_score") or 0) >= min_quality_score
            ]
        ),
        key=final_selection_score,
        reverse=True,
    )
    relaxed_available = sorted(
        dedupe_final_items(
            [
                corrected_final_item(item)
                for item in available_items
                if eligible_for_shortlist(item, config, relaxed=True) and int(item.get("quality_score") or 0) >= min_quality_score
            ]
        ),
        key=final_selection_score,
        reverse=True,
    )
    available = strict_available
    corrected_selected = [corrected_final_item(item) for item in selected_items]
    invalid_selected: list[dict[str, Any]] = []
    valid_selected: list[dict[str, Any]] = []
    for item in corrected_selected:
        reason = final_ineligibility_reason(item, config)
        if reason:
            invalid_selected.append({**item, "final_ineligibility_reason": reason})
            continue
        valid_selected.append(item)
    stats["post_gemini_invalid_removed_count"] = stats.get("post_gemini_invalid_removed_count", 0) + len(invalid_selected)
    stats.setdefault("post_gemini_invalid_removed_examples", []).extend(
        {
            "title": display_title(item.get("title", "")),
            "reason": item.get("final_ineligibility_reason", "ineligible"),
            "url": item.get("canonical_url") or item.get("url") or "",
        }
        for item in invalid_selected[:5]
    )
    repaired = dedupe_final_items(valid_selected)
    inserted: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = invalid_selected[:]
    required_buckets: list[tuple[str, Any]] = [
        ("non_academic_longform_or_operational", is_non_academic_longform_operational_item),
        ("longform_or_investigative", is_longform_investigative_item),
        ("research_or_psychology", is_research_psychology_item),
        ("modus_or_infrastructure", lambda item: is_modus_infrastructure_item(item) or item.get("usefulness_category") == "Operational intelligence"),
        ("technical_platform_product", is_technical_platform_product_item),
    ]

    for label, predicate in required_buckets:
        if any(predicate(item) for item in repaired):
            continue
        candidate = next((item for item in available if predicate(item)), None)
        if not candidate:
            continue
        trial, removed_for_candidate = make_room_for_candidate(repaired, candidate, max_items)
        if {candidate_identity(item) for item in trial} != {candidate_identity(item) for item in repaired}:
            repaired = trial
            inserted.append({**candidate, "repair_reason": f"missing_{label}"})
            removed.extend(removed_for_candidate)

    min_items = int(config.get("min_articles_to_send", 3))
    refill_count = 0
    for pool_name, pool in (("strict_refill", strict_available), ("relaxed_refill", relaxed_available)):
        if len(repaired) >= min_items:
            break
        for candidate in pool:
            if len(repaired) >= min_items:
                break
            reason = final_ineligibility_reason(candidate, config, allow_adjacent=(pool_name == "relaxed_refill"))
            if reason:
                continue
            trial, removed_for_candidate = make_room_for_candidate(repaired, candidate, max_items)
            if {candidate_identity(item) for item in trial} != {candidate_identity(item) for item in repaired}:
                repaired = trial
                refill_count += 1
                inserted.append({**candidate, "repair_reason": pool_name})
                removed.extend(removed_for_candidate)

    repaired, cap_removed = trim_final_caps(repaired)
    removed.extend(cap_removed)
    repaired = dedupe_near_duplicates(repaired, stats, "final")
    repaired, preferred_removed = trim_to_preferred_final_count(repaired, config, available, max_items)
    removed.extend(preferred_removed)
    final_invalid = [
        {**item, "final_ineligibility_reason": final_ineligibility_reason(item, config) or ""}
        for item in repaired
        if final_ineligibility_reason(item, config)
    ]
    if final_invalid:
        repaired = [item for item in repaired if not final_ineligibility_reason(item, config)]
    stats["refill_candidates_added_count"] = stats.get("refill_candidates_added_count", 0) + refill_count
    stats["final_ineligible_items_count"] = len(final_invalid)
    stats["final_general_context_count"] = sum(1 for item in repaired if item.get("usefulness_category", classify_usefulness_category(item)) == "General context")
    stats["final_weak_relevance_count"] = sum(1 for item in repaired if item.get("anti_scam_relevance") == "weak")
    stats["final_rejected_item_count"] = sum(1 for item in repaired if item.get("rejection_reason"))
    stats["post_gemini_repair_applied"] = bool(inserted or removed)
    stats["post_gemini_repair_inserted"] = [
        {
            "title": display_title(item.get("title", "")),
            "reason": item.get("repair_reason"),
            "url": item.get("canonical_url") or item.get("url") or "",
        }
        for item in inserted
    ]
    stats["post_gemini_repair_removed"] = [
        {
            "title": display_title(item.get("title", "")),
            "url": item.get("canonical_url") or item.get("url") or "",
        }
        for item in removed
    ]
    return sorted(repaired, key=final_selection_score, reverse=True)[:max_items]


def limit_vendor_blog_items(items: list[dict[str, Any]], config: dict[str, Any], max_items: int) -> list[dict[str, Any]]:
    max_vendor_items = int(quality_config(config).get("max_vendor_blog_items_final", 1))
    selected: list[dict[str, Any]] = []
    vendor_count = 0

    for item in items:
        if is_sponsored_vendor_item(item):
            if vendor_count >= max_vendor_items:
                continue
            vendor_count += 1
        selected.append(item)
        if len(selected) >= max_items:
            break

    return selected


def recency_boost(item: dict[str, Any], now: datetime) -> int:
    if item.get("evergreen_reference"):
        return 0
    age_days = item_age_days(item, now)
    if age_days is None:
        return 0

    if age_days <= 7:
        return 9
    if age_days <= 30:
        return 6
    if age_days <= 90:
        return 3
    return 0


def score_item(item: dict[str, Any], now: datetime | None = None) -> int:
    title = item["title"].lower()
    score = sum(3 for keyword in SCAM_KEYWORDS if keyword in title)
    if now is not None:
        score += recency_boost(item, now)
    return score


def is_academic_or_research_recency_exception(item: dict[str, Any]) -> bool:
    domain = article_domain(item)
    article_type = item.get("article_type", classify_article_type(item))
    query_group = item.get("query_group", "")
    academic_domains = (
        "arxiv.org",
        "dl.acm.org",
        "ieee.org",
        "usenix.org",
        "ndss-symposium.org",
        "ssrn.com",
        "osf.io",
    )
    return (
        article_type == "Research paper"
        or query_group in {"academic", "psychology"}
        or any(domain.endswith(host) for host in academic_domains)
        or is_direct_research_item(item)
        or is_research_psychology_item(item)
    )


def is_investigative_longform_recency_exception(item: dict[str, Any]) -> bool:
    domain = article_domain(item)
    article_type = item.get("article_type", classify_article_type(item))
    usefulness_category = item.get("usefulness_category") or classify_usefulness_category(item)
    query_group = item.get("query_group", "")
    longform_domains = (
        "c4ads.org",
        "wired.com",
        "404media.co",
        "restofworld.org",
        "graphika.com",
        "bellingcat.com",
        "technologyreview.com",
        "datasociety.net",
        "cetas.turing.ac.uk",
        "therecord.media",
        "krebsonsecurity.com",
    )
    if article_type in {"News report", "Enforcement report", "Official report", "Advisory / guidance"}:
        return False
    return (
        article_type in {"Investigative report", "Deep analysis", "Policy analysis"}
        or (query_group == "investigative" and any(domain.endswith(host) for host in longform_domains))
        or (
            any(domain.endswith(host) for host in longform_domains)
            and (is_investigative_or_operational_item(item) or usefulness_category in {"Operational intelligence", "Technical abuse / vulnerability"})
        )
    )


def recency_window_days(
    item: dict[str, Any],
    config: dict[str, Any],
    lookback_days: int | None = None,
    max_article_age_days: int | None = None,
) -> int:
    default_window = int(max_article_age_days or config.get("max_article_age_days", 4))
    if lookback_days is not None:
        default_window = min(int(lookback_days), default_window)
    if item.get("evergreen_reference"):
        return int(config.get("evergreen_reference_max_article_age_days", 3650))
    if is_academic_or_research_recency_exception(item):
        return int(config.get("academic_research_max_article_age_days", 180))
    article_type = item.get("article_type", classify_article_type(item))
    if article_type == "Enforcement report" or is_local_current_affairs_item(item):
        return int(config.get("news_max_article_age_days", default_window))
    if is_platform_product_official_update_item(item):
        return int(config.get("platform_product_official_max_article_age_days", 30))
    if is_investigative_longform_recency_exception(item):
        return int(config.get("investigative_longform_max_article_age_days", 90))
    if article_type == "News report":
        return int(config.get("news_max_article_age_days", default_window))
    return default_window


def is_within_candidate_recency_window(
    item: dict[str, Any],
    config: dict[str, Any],
    now: datetime,
    debug: bool,
    lookback_days: int | None = None,
    max_article_age_days: int | None = None,
) -> bool:
    age_days = item_age_days(item, now)
    if age_days is None:
        return debug
    return age_days <= recency_window_days(item, config, lookback_days, max_article_age_days)


def category_recency_adjustment(item: dict[str, Any], config: dict[str, Any], now: datetime) -> int:
    if item.get("evergreen_reference"):
        return 0
    age_days = item_age_days(item, now)
    if age_days is None:
        return 0
    window_days = recency_window_days(item, config)
    if age_days > window_days:
        return -10_000

    if is_academic_or_research_recency_exception(item):
        if age_days <= 90:
            return 0
        return -6

    if is_investigative_longform_recency_exception(item):
        if age_days <= 30:
            return 0
        if age_days <= 60:
            return -4
        return -8

    if is_platform_product_official_update_item(item):
        return 0 if age_days <= 14 else -4

    if age_days > int(config.get("max_article_age_days", 4)):
        return -10_000
    return 0


def is_seen(candidate: dict[str, Any], seen: dict[str, dict[str, Any]]) -> bool:
    seen_urls = seen.get("urls", {})
    seen_titles = seen.get("titles", {})
    seen_stories = seen.get("stories", {})
    original_url = candidate.get("original_url", "")
    canonical_url = candidate.get("canonical_url") or candidate.get("url", "")
    fingerprint = candidate.get("title_fingerprint") or title_fingerprint(candidate.get("title", ""))
    story_key = candidate.get("same_story_key") or same_story_key(candidate)

    url_hashes = {candidate.get("canonical_url_hash"), candidate.get("original_url_hash")}
    if canonical_url:
        url_hashes.add(url_hash(canonical_url))
    if original_url:
        url_hashes.add(url_hash(original_url))

    if any(item_hash in seen_urls for item_hash in url_hashes if item_hash) or fingerprint in seen_titles or story_key in seen_stories:
        return True

    recent_cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    for record in list(seen_titles.values()) + list(seen_stories.values()):
        sent_at = record.get("sent_at")
        if sent_at:
            try:
                sent_at_datetime = date_parser.parse(sent_at)
                if sent_at_datetime.tzinfo is None:
                    sent_at_datetime = sent_at_datetime.replace(tzinfo=timezone.utc)
                if sent_at_datetime.astimezone(timezone.utc) < recent_cutoff:
                    continue
            except (TypeError, ValueError, OverflowError):
                pass
        seen_candidate = {
            "title": record.get("raw_title") or record.get("title") or record.get("normalised_title", ""),
            "canonical_url": record.get("url", ""),
            "original_url": record.get("original_url", ""),
            "parsed_date": record.get("parsed_date", ""),
            "source_domain": record.get("source_domain", ""),
        }
        if near_duplicate(candidate, seen_candidate):
            return True
    return False


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

    for story_key, record in seen.get("stories", {}).items():
        sent_at = record.get("sent_at")
        if not sent_at:
            pruned["stories"][story_key] = record
            continue
        try:
            sent_at_datetime = date_parser.parse(sent_at)
        except (TypeError, ValueError, OverflowError):
            pruned["stories"][story_key] = record
            continue
        if sent_at_datetime.tzinfo is None:
            sent_at_datetime = sent_at_datetime.replace(tzinfo=timezone.utc)
        if sent_at_datetime.astimezone(timezone.utc) >= cutoff:
            pruned["stories"][story_key] = record

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
        story_key = item.get("same_story_key") or same_story_key(item)
        source_domain = article_domain(item)
        parsed_date = parsed_date_key(item)

        for item_url in {canonical_url, original_url}:
            if not item_url:
                continue
            updated_seen["urls"][url_hash(item_url)] = {
                "url": item_url,
                "title": title,
                "normalised_title": normalised_title(title),
                "normalized_title_fingerprint": fingerprint,
                "same_story_key": story_key,
                "source_domain": source_domain,
                "parsed_date": parsed_date,
                "sent_at": sent_at,
                "article_type": article_type,
                "usefulness_category": usefulness_category,
            }

        updated_seen["titles"][fingerprint] = {
            "title": normalised_title(title),
            "raw_title": title,
            "normalised_title": normalised_title(title),
            "normalized_title_fingerprint": fingerprint,
            "same_story_key": story_key,
            "source_domain": source_domain,
            "parsed_date": parsed_date,
            "sent_at": sent_at,
            "article_type": article_type,
            "usefulness_category": usefulness_category,
        }
        updated_seen["stories"][story_key] = {
            "title": normalised_title(title),
            "raw_title": title,
            "normalised_title": normalised_title(title),
            "normalized_title_fingerprint": fingerprint,
            "same_story_key": story_key,
            "source_domain": source_domain,
            "parsed_date": parsed_date,
            "url": canonical_url,
            "original_url": original_url,
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
    queries = build_rss_queries(sources, config)
    max_queries = int(config.get("max_rss_queries_per_run", 120))
    request_timeout = int(config.get("request_timeout_seconds", 8))
    max_google_news_candidates = int(config.get("max_google_news_candidates", 3000))
    max_arxiv_candidates = int(config.get("max_arxiv_candidates", 300))
    max_reference_url_candidates = int(config.get("max_reference_url_candidates", config.get("max_watchlist_candidates", 50)))
    raw_candidate_count = 0
    date_filtered_count = 0
    seen_filtered_count = 0
    deduped_by_url: dict[str, dict[str, Any]] = {}
    now = datetime.now(timezone.utc)

    query_cap_reached = len(queries) > max_queries
    queries_to_run = queries[:max_queries]
    monitored_domains_queried = {
        match.group(1).lower().removeprefix("www.")
        for query in queries_to_run
        if query.get("priority") == "monitored_source"
        for match in [re.search(r"site:([^\s]+)", query.get("query", ""))]
        if match
    }
    cap_reached_by_fetcher = {
        "google_news": False,
        "arxiv": False,
        "reference_url": False,
    }

    reference_entries = [entry for entry in configured_reference_examples(config) if entry.get("include_as_candidate")]
    for entry in reference_entries[:max_reference_url_candidates]:
        raw_candidate_count += 1
        candidate = fetch_reference_url_candidate(entry, seen, max_article_age_days, debug, config)
        if not candidate:
            continue
        date_filtered_count += 1
        if candidate["canonical_url_hash"] in deduped_by_url:
            continue
        deduped_by_url[candidate["canonical_url_hash"]] = candidate
    if len(reference_entries) > max_reference_url_candidates:
        cap_reached_by_fetcher["reference_url"] = True

    for query in queries_to_run:
        try:
            feed = parse_feed(query["url"], request_timeout)
        except requests.RequestException as exc:
            print(f"RSS fetch failed for query '{query['query']}': {exc}")
            continue

        raw_candidate_count += len(feed.entries)

        for entry in feed.entries:
            parsed_date = entry_datetime(entry)
            if parsed_date is None and not debug:
                continue

            original_url = entry.get("link", query["url"])
            original_url_hash = url_hash(original_url)
            title = entry.get("title", "Untitled")
            query_text = query.get("query", "").lower()
            source_name, source_domain_value = google_news_entry_source(entry, query["name"])
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
                "source": source_name,
                "source_name": source_name,
                "source_domain": source_domain_value,
                "title": title,
                "normalised_title": normalised_title(title),
                "title_fingerprint": title_fingerprint(title),
                "summary": entry.get("summary", ""),
                "parsed_date": parsed_date,
                "fetcher": "arxiv" if "site:arxiv.org" in query_text else "google_news",
                "query_group": query_group_for_query(query.get("query", ""), query.get("priority", "")),
                "query": query.get("query", ""),
            }
            candidate["article_type"] = classify_article_type(candidate)
            candidate["usefulness_category"] = classify_usefulness_category(candidate)
            if not is_within_candidate_recency_window(candidate, config, now, debug, lookback_days, max_article_age_days):
                continue
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
        "reference_url_candidate_cap_reached": int(cap_reached_by_fetcher["reference_url"]),
        "reference_examples_loaded_count": len(configured_reference_examples(config)),
        "reference_urls_included_as_candidates_count": len(reference_entries),
        "monitored_sources_queried_count": len(monitored_domains_queried),
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


PRIORITY_RESOLUTION_QUERY_GROUPS = {
    "targeted",
    "psychology",
    "academic",
    "investigative",
    "international",
    "platform_product",
    "monitored_source",
    "singapore_sea",
}


def should_prioritise_url_resolution(candidate: dict[str, Any]) -> bool:
    query_group = str(candidate.get("query_group", "")).lower()
    query = str(candidate.get("query", "")).lower()
    title = str(candidate.get("title", "")).lower()
    if query_group in PRIORITY_RESOLUTION_QUERY_GROUPS:
        return True
    if '"' in query or "site:" in query:
        return True
    if any(domain in query for domain in HIGH_VALUE_INVESTIGATIVE_DOMAINS + HIGH_VALUE_PRODUCT_DOMAINS):
        return True
    return any(term in title for term in STRONG_SCAM_ANCHOR_TERMS) and any(
        term in title for term in TECHNOLOGY_MODUS_TERMS
    )


def url_resolution_priority(candidate: dict[str, Any], now: datetime) -> tuple[int, int, int, str]:
    query_group = str(candidate.get("query_group", "")).lower()
    query = str(candidate.get("query", "")).lower()
    group_weight = {
        "targeted": 120,
        "psychology": 110,
        "academic": 105,
        "investigative": 105,
        "international": 100,
        "platform_product": 95,
        "monitored_source": 90,
        "singapore_sea": 70,
    }.get(query_group, 0)
    exact_or_site_weight = 20 if ('"' in query or "site:" in query) else 0
    return (
        group_weight + exact_or_site_weight,
        score_item(candidate, now),
        recency_boost(candidate, now),
        str(candidate.get("title", "")),
    )


def canonicalise_top_candidates(
    ranked: list[dict[str, Any]],
    limit: int = 50,
    max_google_news_to_resolve: int | None = None,
    stats: dict[str, int] | None = None,
    url_cache: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    canonicalised: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    max_resolutions = max_google_news_to_resolve or limit
    selected_indexes = set(range(min(limit, len(ranked))))
    priority_indexes = sorted(
        (
            (url_resolution_priority(item, now), index)
            for index, item in enumerate(ranked)
            if index not in selected_indexes
            and is_google_news_url(item.get("url") or item.get("canonical_url") or "")
            and should_prioritise_url_resolution(item)
        ),
        reverse=True,
    )
    for _priority, index in priority_indexes:
        if len(selected_indexes) >= max_resolutions:
            break
        selected_indexes.add(index)
    if stats is not None:
        stats["google_news_url_resolution_budget"] = max_resolutions
        stats["google_news_priority_resolution_candidate_count"] = len(priority_indexes)
        stats["google_news_url_selected_for_resolution_count"] = len(selected_indexes)

    for index, item in enumerate(ranked):
        candidate = dict(item)
        if index in selected_indexes:
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
            if not candidate.get("source_domain"):
                candidate["source_domain"] = domain_from_url(candidate["canonical_url"])
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
    config = pipeline.get("config", {})

    cache_info = pipeline.get("cache_info", {})
    print(f"candidate_cache_used: {bool(cache_info.get('used_candidate_cache', False))}")
    print(f"candidate_cache_age_minutes: {cache_info.get('candidate_cache_age_minutes')}")
    print(f"candidate_cache_candidate_count: {cache_info.get('candidate_cache_candidate_count', 0)}")
    print(f"fetch_skipped: {bool(cache_info.get('fetch_skipped', False))}")
    print(f"cache_fallback_used: {bool(cache_info.get('cache_fallback_used', False))}")
    print(f"cache_fallback_allowed: {bool(cache_info.get('cache_fallback_allowed', True))}")
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
    print(f"pre_gemini_duplicates_removed_count: {stats.get('pre_gemini_duplicates_removed_count', 0)}")
    print(f"post_gemini_duplicates_removed_count: {stats.get('post_gemini_duplicates_removed_count', 0)}")
    print(f"final_duplicates_removed_count: {stats.get('final_duplicates_removed_count', 0)}")
    print(f"duplicate_podcast_or_summary_removed_count: {stats.get('duplicate_podcast_or_summary_removed_count', 0)}")
    print(f"reference examples loaded count: {stats.get('reference_examples_loaded_count', len(configured_reference_examples(config)))}")
    print(f"monitored sources queried count: {stats.get('monitored_sources_queried_count', len(configured_monitored_sources(config)))}")
    print(f"reference URLs included as candidates count: {stats.get('reference_urls_included_as_candidates_count', 0)}")
    for item in [item for item in ranked_candidates if item.get("reference_url_candidate")][:5]:
        print(
            "reference_url_candidate: "
            f"title={display_title(item.get('title', ''))} | reason=include_as_candidate_true_and_passed_filters | "
            f"url={item.get('canonical_url') or item.get('url')}"
        )
    print(f"category slot fill counts: {stats.get('category_slot_fill_counts', {})}")
    print(f"research candidates available: {stats.get('research_candidates_available_count', 0)}")
    print(
        "non-academic longform/operational candidates available: "
        f"{stats.get('non_academic_longform_operational_candidates_available_count', 0)}"
    )
    print(f"longform/investigative candidates available: {stats.get('longform_investigative_candidates_available_count', 0)}")
    for prefix in ("pre_gemini", "post_gemini", "final"):
        examples = stats.get(f"{prefix}_duplicate_examples", [])
        for example in examples[:5]:
            print(
                f"{prefix}_duplicate_example: removed_title={example.get('removed_title')} | "
                f"kept_title={example.get('kept_title')} | reason={example.get('reason')}"
            )
    print("category slot candidates:")
    for item in stats.get("must_include_candidates", []):
        print(
            f"category_slot_candidate: title={item.get('title')} | reason={item.get('reason')} | "
            f"article_type={item.get('article_type')} | usefulness_category={item.get('usefulness_category')} | url={item.get('url')}"
        )
    print(f"post_gemini_repair_applied: {bool(stats.get('post_gemini_repair_applied', False))}")
    for item in stats.get("post_gemini_repair_inserted", []):
        print(f"post_gemini_repair_inserted: title={item.get('title')} | reason={item.get('reason')} | url={item.get('url')}")
    for item in stats.get("post_gemini_repair_removed", []):
        print(f"post_gemini_repair_removed: title={item.get('title')} | url={item.get('url')}")
    print(f"query cap reached: {bool(stats.get('query_cap_reached', 0))}")
    print(
        "candidate caps reached by fetcher: "
        f"google_news={bool(stats.get('google_news_candidate_cap_reached', 0))}, "
        f"arxiv={bool(stats.get('arxiv_candidate_cap_reached', 0))}, "
        f"reference_url={bool(stats.get('reference_url_candidate_cap_reached', 0))}"
    )
    print(f"fetch runtime seconds: {timing.get('fetch_runtime_seconds', 0):.2f}")
    print(f"URL resolution runtime seconds: {timing.get('url_resolution_runtime_seconds', 0):.2f}")
    print(f"quality inspection runtime seconds: {timing.get('quality_inspection_runtime_seconds', 0):.2f}")
    resolved = stats.get("google_news_url_resolved_count", 0)
    attempted = stats.get("google_news_url_decode_attempt_count", 0)
    print(f"Google News URLs resolved: {resolved}/{attempted}")
    print(f"unresolved_google_news_url: {stats.get('unresolved_google_news_url_count', 0)}")
    print(f"Shortlist count: {len(pipeline['shortlist'])}")
    print(f"query group distribution before shortlist: {query_group_distribution(ranked_candidates)}")
    print(f"source domain distribution before shortlist: {source_domain_distribution(ranked_candidates)}")
    print(f"source domain distribution in shortlist: {source_domain_distribution(pipeline['shortlist'])}")
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
    print(f"psychology_victim_persuasion_count: {sum(1 for item in pipeline['shortlist'] if is_psychology_item(item))}")
    print(f"longform_analysis_count: {sum(1 for item in pipeline['shortlist'] if is_investigative_or_operational_item(item))}")
    print(f"international_scam_infrastructure_count: {sum(1 for item in pipeline['shortlist'] if is_modus_infrastructure_item(item) and not is_local_sea_item(item))}")
    print(f"singapore_sea_current_affairs_count: {sum(1 for item in pipeline['shortlist'] if is_local_current_affairs_item(item))}")
    print(f"enforcement_report_count: {sum(1 for item in pipeline['shortlist'] if item.get('article_type', classify_article_type(item)) == 'Enforcement report')}")
    print(f"paywalled_high_reputation_kept_count: {count_paywalled_high_reputation(pipeline['shortlist'], config)}")
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
            f"research_reputation_signals={item.get('research_reputation_signals', [])} | "
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
        print(f"{index}. [{article_type} · {usefulness_category}] {display_title(item['title'])}")
        print(item["canonical_url"])


def print_must_include_final_status(
    stats: dict[str, Any],
    selected_items: list[dict[str, Any]],
    cost_data: dict[str, Any],
) -> None:
    selected_titles = {normalize_title_for_dedupe(item.get("title", "")) for item in selected_items}
    selected_urls = {canonicalize_url_text(item.get("canonical_url") or item.get("url") or "") for item in selected_items}
    rejected = {
        normalize_title_for_dedupe(item.get("title", "")): item.get("reason", "")
        for item in cost_data.get("rejected_must_include", [])
        if isinstance(item, dict)
    }
    for item in stats.get("must_include_candidates", []):
        title_key = normalize_title_for_dedupe(item.get("title", ""))
        url_key = canonicalize_url_text(item.get("url", ""))
        made_final = title_key in selected_titles or url_key in selected_urls
        reason = "included" if made_final else rejected.get(title_key, "not selected; category repair may have preferred another non-duplicate item")
        print(f"category_slot_final_status: title={item.get('title')} | made_final={made_final} | reason={reason}")


CALIBRATION_CANDIDATE_PATTERNS = (
    ("Profiling User Vulnerability to Phishing Through Psychological and Behavioral Factors", ("profiling user vulnerability to phishing",)),
    ("Cybersecurity Risks of Online Piracy Websites in Malaysia", ("cybersecurity risks of online piracy websites in malaysia",)),
    ("US charges 2 Chinese nationals with managing cyberscam compound in Myanmar", ("chinese nationals", "cyberscam compound", "myanmar")),
    ("HELLO BOSS 404 Media article", ("hello boss", "chinese realtime deepfake")),
    ("Malaysia visa-exemption policy exploited by global scam rings", ("visa-exemption", "global scam rings")),
    ("Deepfakes on Demand / Fraud as a Service", ("deepfakes on demand", "fraud as a service")),
)


def high_value_candidate_diagnostics(selected_items: list[dict[str, Any]], available_items: list[dict[str, Any]]) -> list[dict[str, str]]:
    selected_ids = {candidate_identity(item) for item in selected_items}
    diagnostics: list[dict[str, str]] = []
    for label, patterns in CALIBRATION_CANDIDATE_PATTERNS:
        matches = [
            item
            for item in available_items
            if all(pattern in candidate_signal_text(item) for pattern in patterns)
        ]
        if not matches:
            diagnostics.append({"label": label, "status": "not_in_candidate_pool", "reason": "not discovered or filtered before ranking"})
            continue
        best = max(matches, key=final_selection_score)
        if candidate_identity(best) in selected_ids:
            diagnostics.append({"label": label, "status": "selected", "reason": "included in final output"})
            continue
        reason = str(best.get("rejection_reason") or best.get("hard_rejection_reason") or "not selected after scoring/Gemini/repair")
        if any(near_duplicate(best, selected) for selected in selected_items):
            reason = "near_duplicate_of_selected_item"
        diagnostics.append(
            {
                "label": label,
                "status": "dropped",
                "reason": reason,
                "title": display_title(best.get("title", "")),
                "url": best.get("canonical_url") or best.get("url") or "",
            }
        )
    return diagnostics


def clean_summary_text(summary: Any, limit: int = 500) -> str:
    raw_text = str(summary or "")
    text = BeautifulSoup(raw_text, "html.parser").get_text(" ", strip=True) if "<" in raw_text and ">" in raw_text else raw_text
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= limit:
        return text
    truncated = text[:limit].rsplit(" ", 1)[0].rstrip(" ,;:-")
    return truncated + "..."


GENERIC_TAKEAWAY_PATTERNS = (
    "comment loader",
    "save story",
    "actionable insight",
    "actionable insights",
    "offers insights",
    "provides insights",
    "useful for building",
    "useful for designing",
    "technical blueprint",
    "important implications",
    "proactive, user-facing",
)


def is_generic_takeaway(text: str) -> bool:
    lowered = text.lower()
    if any(pattern in lowered for pattern in GENERIC_TAKEAWAY_PATTERNS):
        return True
    if "provides a framework for evaluating how" in lowered:
        return True
    if "provides a framework" in lowered and not any(
        marker in lowered
        for marker in (
            "using",
            "with",
            "combines",
            "includes",
            "measures",
            "tests",
            "detects",
            "compares",
            "agent",
            "browser",
            "dataset",
            "metric",
            "policy",
            "intervention",
            "workflow",
        )
    ):
        return True
    return False


def clean_takeaway_text(raw_value: Any) -> str:
    text = clean_summary_text(raw_value, 260)
    text = re.sub(r"^\s*(?:[-*•]|\d+[.)])\s*", "", text).strip()
    text = text.strip(" \t\r\n\"'`,;")
    text = re.sub(r"\s+[a-z]{1,2}$", "", text).strip(" ,;:-")
    text = re.sub(r"\s+(?:and|or|to|for|with|of|in|on|by)$", "", text, flags=re.IGNORECASE).strip(" ,;:-")
    if text and text[-1] not in ".!?)]":
        text += "."
    return text


def normalize_key_takeaways(raw_takeaways: Any, max_bullets: int = 3) -> list[str]:
    if isinstance(raw_takeaways, str):
        raw_values = re.split(r"(?:\r?\n)+", raw_takeaways)
    elif isinstance(raw_takeaways, list):
        raw_values = raw_takeaways
    else:
        raw_values = []

    takeaways: list[str] = []
    for raw_value in raw_values:
        text = clean_takeaway_text(raw_value)
        if not text:
            continue
        if is_generic_takeaway(text):
            continue
        if text not in takeaways:
            takeaways.append(text)
        if len(takeaways) >= max_bullets:
            break
    return takeaways


def build_gemini_prompt(items: list[dict[str, Any]], sent_count: int) -> str:
    candidates = json.dumps(
        [
            {
                "id": item["id"],
                "title": item["title"],
                "url": item["canonical_url"],
                "source": item["source"],
                "summary": clean_summary_text(item.get("summary", "")),
                "article_excerpt": clean_summary_text(item.get("article_excerpt", ""), 1400),
                "parsed_date": parsed_date_text(item),
                "article_type": item.get("article_type", classify_article_type(item)),
                "usefulness_category": item.get("usefulness_category", classify_usefulness_category(item)),
                "anti_scam_relevance": item.get("anti_scam_relevance"),
                "direct_relevance_terms_found": item.get("direct_relevance_terms_found", []),
                "technology_modus_terms_found": item.get("technology_modus_terms_found", []),
                "research_relevance_category": item.get("research_relevance_category"),
                "research_relevance_score": item.get("research_relevance_score"),
                "research_reputation_signals": item.get("research_reputation_signals", []),
                "downrank_reason": item.get("downrank_reason"),
                "word_count": item.get("word_count"),
                "quality_score": item.get("quality_score"),
                "access_status": item.get("access_status", "unknown"),
                "source_reputation": item.get("source_reputation", "medium"),
                "salesy_vendor_pitch": bool(item.get("salesy_vendor_pitch", False)),
                "sponsored_vendor_content": is_sponsored_vendor_item(item),
                "relevant_sponsored_vendor_content": is_relevant_sponsored_vendor_item(item),
                "category_slot_candidate": bool(item.get("must_include_if_available", False)),
                "category_slot_reason": item.get("must_include_reason"),
                "reference_url_candidate": bool(item.get("reference_url_candidate", False)),
            }
            for item in items
        ],
        ensure_ascii=True,
    )
    return (
        "You are selecting articles for a product leader building national-scale anti-scam products. "
        "You are not producing a local scam current-affairs digest. You are producing a balanced adversarial product radar for anti-scam product work. "
        "Do not optimise for general newsworthiness. Optimise for product-relevant adversarial intelligence: "
        "scam developments, attacker methods, technical vulnerabilities, research, operational intelligence, "
        "platform changes, local Singapore/Southeast Asia developments, product ideas, and data-source opportunities. "
        "Select 1 to 5 genuinely strong articles, with 3 to 4 as the ideal daily digest size. Do not pad the list. Do not over-select enforcement/current-affairs stories. Singapore and Southeast Asia items are useful, but they must not dominate. "
        "Prioritise scammer modus operandi, scam infrastructure, victim psychology, scam methodology, LLM adverse-use research, academic studies, deep investigations, platform/telco/bank controls, and product-relevant technical insights. "
        "Prefer one excellent WIRED / C4ADS / 404 Media / arXiv / academic item over several similar local enforcement updates. "
        "If there are multiple Singapore enforcement stories, choose only the most operationally useful or novel one. Leave room for research, investigations, platform/product changes, and methodology pieces. "
        "You are not choosing the safest or most recent news items. You are curating a balanced adversarial product radar for anti-scam work. "
        "You must preserve category diversity. If directly relevant academic research or longform investigative reporting is present in the shortlist, include at least one unless it is genuinely weak or duplicative. "
        "Do not drop research simply because it is less newsy. Do not over-select Singapore/current-affairs/enforcement stories. Prefer articles that reveal scammer methods, victim psychology, technical abuse, scam infrastructure, platform controls, or product-relevant insights. "
        "The reference examples are examples of desired editorial quality and relevance. They are not mandatory URLs. Do not include a reference example merely because it appears in the config. Select current, relevant, non-duplicate articles from the candidate pool. "
        "Items marked category_slot_candidate are the current best representatives of category diversity; they are not mandatory URLs, but dropping an entire category when strong candidates are available is a failed mix constraint. "
        "Select for direct anti-scam product relevance. Do not select generic AI/cybersecurity articles unless they clearly help understand scammer modus operandi, victim manipulation, monetary-loss fraud, account takeover, scam infrastructure, platform/telco/bank controls, or technologies used by scammers to scale. "
        "You must not select generic AI/cybersecurity context items. Every final item must be directly useful for anti-scam product work. "
        "Never select an item with usefulness_category='General context', anti_scam_relevance='weak', or rejection_reason set. Do not let category quotas rescue these items. "
        "Do not fill category quotas with weak items. If only 1 or 2 strong fresh items exist, return only those. A balanced list with weak items is worse than a shorter list of strong items. "
        "Do not assign items to a specialist section unless the item actually matches that section. Generic AI cybersecurity does not belong under Deepfakes, synthetic identity & impersonation. "
        "Reject healthcare/radiology/enterprise-security/generic-cyber items unless they have a direct scam/fraud/social-engineering link. "
        "Do not select research merely because it is technical or about fraud generally. Research should be selected only if it directly helps anti-scam product work: scammer methods, victim psychology, harmful persuasion, LLM-enabled scam abuse, scam detection, scam intervention, deepfake scams, synthetic identity, social engineering, or adverse-use benchmarks. "
        "Research reputation signals such as strong venues or affiliation domains are tie-breakers only; never select a paper solely because it has a prestigious venue or institution signal. "
        "Exclude generic cybersecurity, generic enterprise agent security, generic fraud ML, or unrelated technical domains unless there is a direct scam/social-engineering link. "
        f"You may select between 1 and {sent_count} articles. Aim for 3 to 4 when enough strong fresh items exist, and never select more than 5. Do not always select the maximum. Select only articles that are genuinely relevant to anti-scam product work. "
        "Do not pad the list with weak or generic items. If only 4 strong items exist, return 4. Never include duplicates or near-duplicates. Prefer direct anti-scam relevance over general AI/cyber news. "
        "Do not select duplicate or near-duplicate stories. If two items are from the same publisher, same date, and cover the same event, select only the stronger one. For example, two TechCrunch articles about scammers abusing a Microsoft email/account to send spam links are the same story; pick one. "
        "A good digest usually has 3 to 4 high-signal items, never more than 5. It should feel balanced across victim psychology or persuasion research, empirical scam-risk research, operational intelligence on scam compounds/syndicates/infrastructure, longform investigations into scam-enabling technology, technical or platform abuse, and selected regional developments. "
        "Do not simply maximise research count or recency. Prefer 1-2 research/psychology items, 1-2 longform investigations or deep analyses, 1-2 operational intelligence/scam infrastructure items, one technical/platform/product/data-source item, and 0-2 Singapore/Southeast Asia items unless the SEA items reveal operational patterns. "
        "Do not over-select simple local arrest stories. But do not drop Southeast Asia items if they reveal operational patterns, scam infrastructure, visa/travel policy abuse, compounds, mule networks, call centres, fake-official impersonation workflows, or syndicate migration. "
        "Cap final research papers at two unless a third is clearly exceptional direct anti-scam research. When selecting only 3 to 5 articles, do not let research papers or product-idea items take most of the slots. "
        "If a non-academic longform investigation, deep analysis, or operational-intelligence item is available, include at least one. Prefer that over adding another research/product-idea item. "
        "Sponsored/vendor content is not automatically banned, but select at most one and only when it is directly relevant to scam methods, fraud-as-a-service, deepfake abuse, phishing kits, identity fraud, platform abuse, or scam infrastructure. Label it honestly as Sponsored / vendor content. Do not use sponsored content to satisfy the investigative-report slot. "
        "Do not select both a podcast/video/summary and the full article about the same investigation. Prefer the full original article, especially for longform investigations. "
        "Hard balance targets: maximum 2 Singapore/Southeast Asia current-affairs items, maximum 3 Singapore/Southeast Asia items only when the extra item is operationally useful, maximum 1 sponsored/vendor item, maximum 2 enforcement reports, maximum 2 plain news reports. Include at least one deep investigation/deep analysis/operational intelligence item if available, one directly relevant academic research paper if available, one psychology/persuasion/victimology/scam-methodology item if available, one technical/platform/product/data-source item if available, and one scam modus-operandi/infrastructure item if available. "
        "Correct any wrong article labels. Do not label enforcement or arrest stories as Technical articles unless they contain technical mechanisms. "
        "Prioritise articles like 'Victim as a Service' that reveal novel anti-scam product ideas, research methods, scam engagement systems, detection approaches, or engineering workflows. "
        "Avoid vendor pitch, product announcements without anti-scam or engineering relevance, thin posts, and generic consumer advice. "
        "Include at least one technical/threat-intelligence item if available. "
        "Include at least one deep analysis/investigative/research item if available. "
        "For each selected item, write no more than 3 concise key_takeaways bullets based only on the provided candidate title, source, date, summary, article_excerpt, labels, and signal terms. Do not invent details. "
        "When article_excerpt is present, use it as the primary evidence for the bullets; do not merely restate the title, publication, or source. If article_excerpt is missing or too thin, write fewer bullets rather than filler. "
        "Never turn scraped boilerplate such as comment loaders, save-story prompts, newsletter prompts, navigation text, or author interview filler into key_takeaways. "
        "Make every key_takeaways bullet specific enough that a product or policy teammate can decide whether to open the article. Avoid generic phrases such as 'actionable insights', 'technical blueprint', 'proactive user-facing features', or 'provides a framework' unless you name the actual mechanism, data, components, evaluation setup, actors, workflow, or policy lever. "
        "At least one bullet per item must state the product or policy relevance concretely: for example, what detection signal to instrument, what intervention/control to test, what abuse workflow to monitor, what data source to collect, what enforcement/policy gap is exposed, or what user-risk segment is implicated. "
        "Keep product/policy relevance grounded in the article evidence. Do not infer unsupported deployment ideas such as risk-scoring origins, traffic attribution, or model tuning unless the candidate text supports them. "
        "For research or technical items, explain what the framework/model/evaluation contains, such as agents, browser hooks, datasets, metrics, prompts, controls, attack stages, or measured failure modes. For investigations, name the operational pattern, infrastructure, actors, geography, victim pipeline, money/mule movement, or enforcement gap. "
        f"Return JSON only with this shape: "
        f'{{"items":[{{"rank":1,"section":"Scam trends","article_type":"News report","usefulness_category":"Scam development","title":"Article title","url":"https://example.com","key_takeaways":["Short takeaway"]}}],"mix_constraints_satisfied":true,"failed_constraints":[]}}. '
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


def safe_request_error(exc: requests.RequestException) -> str:
    status_code = exc.response.status_code if exc.response is not None else None
    if status_code is not None:
        return f"{exc.__class__.__name__}: HTTP {status_code}"
    return exc.__class__.__name__


def gemini_retry_delay_seconds(attempt_index: int) -> float:
    return min(8.0, 2.0 ** max(0, attempt_index - 1))


def rank_with_gemini(
    items: list[dict[str, Any]],
    sent_count: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    model = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
    max_output_tokens = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "1100"))
    max_cost = float(os.getenv("MAX_DAILY_GEMINI_COST_USD", "0.02"))
    max_attempts = max(1, int(os.getenv("GEMINI_MAX_ATTEMPTS", "3")))
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
        "gemini_attempts": 0,
        "gemini_max_attempts": max_attempts,
        "gemini_failed_attempts": [],
    }

    if estimated_cost_usd > max_cost:
        print(f"Gemini cost cap exceeded: estimated ${estimated_cost_usd:.6f} > cap ${max_cost:.6f}.")
        return items, cost_data

    if not os.getenv("GEMINI_API_KEY"):
        print("Gemini skipped: GEMINI_API_KEY is not set.")
        return items, cost_data

    payload: dict[str, Any] = {"items": []}
    usage: dict[str, Any] | None = None
    text = ""
    for attempt in range(1, max_attempts + 1):
        cost_data["gemini_attempts"] = attempt
        try:
            print(f"Gemini attempt {attempt}/{max_attempts}")
            text, usage = call_gemini(prompt, model, max_output_tokens)
        except requests.RequestException as exc:
            error = safe_request_error(exc)
            cost_data["gemini_failed_attempts"].append({"attempt": attempt, "reason": error})
            print(f"Gemini attempt {attempt}/{max_attempts} failed: {error}")
            if attempt < max_attempts:
                time.sleep(gemini_retry_delay_seconds(attempt))
                continue
            print("Gemini skipped after all request attempts failed.")
            return items, cost_data

        cost_data["used_llm"] = True
        try:
            parsed_payload = json.loads(text)
        except json.JSONDecodeError:
            cost_data["gemini_failed_attempts"].append({"attempt": attempt, "reason": "invalid_json"})
            print(f"Gemini attempt {attempt}/{max_attempts} returned invalid JSON.")
            if attempt < max_attempts:
                time.sleep(gemini_retry_delay_seconds(attempt))
                continue
            payload = {"items": []}
            break

        if not isinstance(parsed_payload, dict):
            cost_data["gemini_failed_attempts"].append({"attempt": attempt, "reason": "non_object_json"})
            print(f"Gemini attempt {attempt}/{max_attempts} returned non-object JSON.")
            if attempt < max_attempts:
                time.sleep(gemini_retry_delay_seconds(attempt))
                continue
            payload = {"items": []}
            break

        payload = parsed_payload
        break

    if not cost_data["used_llm"]:
        return items, cost_data

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

    cost_data["rejected_must_include"] = payload.get("rejected_must_include", []) if isinstance(payload, dict) else []
    cost_data["mix_constraints_satisfied"] = payload.get("mix_constraints_satisfied") if isinstance(payload, dict) else None
    cost_data["failed_constraints"] = payload.get("failed_constraints", []) if isinstance(payload, dict) else []

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
        updated_item["key_takeaways"] = normalize_key_takeaways(gemini_item.get("key_takeaways"))
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
    pipeline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    run = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "mode": mode,
        **cost_data,
        "candidate_count": candidate_count,
        "shortlist_count": shortlist_count,
        "sent_count": sent_count,
    }
    if pipeline:
        cache_info = pipeline.get("cache_info", {})
        stats = pipeline.get("stats", {})
        run.update(
            {
                "candidate_cache_used": bool(cache_info.get("used_candidate_cache", False)),
                "cache_fallback_used": bool(cache_info.get("cache_fallback_used", False)),
                "cache_fallback_allowed": bool(cache_info.get("cache_fallback_allowed", True)),
                "fetch_skipped": bool(cache_info.get("fetch_skipped", False)),
                "rss_queries_run": stats.get("rss_queries_run", 0),
                "raw_candidate_count": stats.get("raw_candidate_count", candidate_count),
                "date_filtered_candidate_count": stats.get("date_filtered_candidate_count", candidate_count),
                "ranked_unseen_candidate_count": stats.get("ranked_unseen_candidate_count", candidate_count),
            }
        )
    return run


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
        f"- Gemini attempts: {run.get('gemini_attempts', 0)}/{run.get('gemini_max_attempts', 1)}",
        f"- Estimated tokens: {run['estimated_input_tokens']} input, {run['estimated_output_tokens']} output",
        f"- Estimated cost: ${run['estimated_cost_usd']:.6f}",
        f"- Actual tokens: {run['actual_prompt_tokens']} input, {run['actual_output_tokens']} output, {run['actual_thoughts_tokens']} thoughts, {run['actual_total_tokens']} total",
        f"- Actual cost: {run['actual_cost_usd']}",
        f"- Counts: {run['candidate_count']} candidates, {run['shortlist_count']} shortlisted, {run['sent_count']} sent",
        f"- Candidate cache used: {run.get('candidate_cache_used', False)}",
        f"- Cache fallback used: {run.get('cache_fallback_used', False)}",
        f"- Fetch skipped: {run.get('fetch_skipped', False)}",
        f"- RSS queries run: {run.get('rss_queries_run', 'unknown')}",
        f"- Raw candidates fetched: {run.get('raw_candidate_count', 'unknown')}",
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
    if usefulness_category == "General context":
        return "🧨 SCAM TRENDS"
    if any(term in terms for term in ("grooming", "persuasion", "manipulation", "deception", "trust-building", "harmful persuasion")) or is_psychology_item(item):
        return "🧠 VICTIM PSYCHOLOGY & PERSUASION"
    if usefulness_category == "Research / novel method" or is_direct_research_item(item):
        return "📚 RESEARCH & NOVEL METHODS"
    if usefulness_category == "Operational intelligence" or article_type == "Investigative report":
        return "🕵️ INVESTIGATIONS & OPERATIONAL INTELLIGENCE"
    if usefulness_category == "Deepfakes, synthetic identity & impersonation" or any(
        term in terms
        for term in ("deepfake scam", "voice cloning scam", "synthetic identity fraud", "impersonation scam", "voice clone", "synthetic identity", "deepfake video call")
    ):
        return "🧬 DEEPFAKES, SYNTHETIC IDENTITY & IMPERSONATION"
    if usefulness_category == "Scam development":
        return "🧨 SCAM TRENDS"
    if usefulness_category in {"Technical abuse / vulnerability", "Detection / analytics / engineering insight"} or article_type == "Technical article":
        return "🛠️ TECHNICAL ABUSE & VULNERABILITIES"
    if usefulness_category == "Platform policy / product change":
        return "📱 PLATFORM, TELCO & BANK CONTROLS"
    if usefulness_category == "Product idea / data source":
        return "🧰 PRODUCT IDEAS & DATA SOURCES"
    if usefulness_category == "Local Singapore / Southeast Asia relevance":
        return "🇸🇬 SINGAPORE / SOUTHEAST ASIA"
    if article_type in {"Advisory / guidance", "Enforcement report", "Official report"}:
        return "🚨 ADVISORIES & ENFORCEMENT"
    return "🧨 SCAM TRENDS"


def grouped_items_by_section(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {section: [] for section in SECTION_ORDER}
    for item in sorted(items, key=lambda value: int(value.get("quality_score") or 0), reverse=True):
        grouped.setdefault(telegram_section(item), []).append(item)
    return {section: grouped.get(section, []) for section in SECTION_ORDER if grouped.get(section)}


def item_key_takeaways(item: dict[str, Any]) -> list[str]:
    takeaways = normalize_key_takeaways(item.get("key_takeaways"))
    if takeaways:
        return takeaways

    fallback_text = clean_summary_text(item.get("article_excerpt", ""), 900)
    if not fallback_text:
        fallback_text = clean_summary_text(item.get("summary", ""), 500)
    if not fallback_text:
        return []

    title_tokens = title_token_set(item.get("title", ""))
    fallback_tokens = title_token_set(fallback_text)
    if title_tokens and fallback_tokens and len(fallback_tokens - title_tokens) < 6:
        return []

    source = str(item.get("source", "")).lower()
    if source and fallback_text.lower().endswith(source) and len(fallback_tokens) < 18:
        return []

    sentence_candidates = re.split(r"(?<=[.!?])\s+", fallback_text)
    return normalize_key_takeaways(sentence_candidates)


def section_distribution(items: list[dict[str, Any]]) -> dict[str, int]:
    return {section: len(section_items) for section, section_items in grouped_items_by_section(items).items()}


def source_domain_distribution(items: list[dict[str, Any]]) -> dict[str, int]:
    distribution: dict[str, int] = {}
    for item in items:
        domain = article_domain(item) or "unknown"
        distribution[domain] = distribution.get(domain, 0) + 1
    return dict(sorted(distribution.items()))


def query_group_distribution(items: list[dict[str, Any]]) -> dict[str, int]:
    distribution: dict[str, int] = {}
    for item in items:
        group = item.get("query_group", "unknown")
        distribution[group] = distribution.get(group, 0) + 1
    return dict(sorted(distribution.items()))


def count_paywalled_high_reputation(items: list[dict[str, Any]], config: dict[str, Any]) -> int:
    return sum(
        1
        for item in items
        if item.get("access_status") == "paywalled_or_login" and is_high_reputation_source(item, config)
    )


def final_mix_constraint_failures(
    items: list[dict[str, Any]],
    min_items: int,
    max_items: int,
    available_items: list[dict[str, Any]] | None = None,
) -> list[str]:
    failures: list[str] = []
    available = available_items or items
    if len(items) < min_items:
        failures.append(f"below_min_articles:{len(items)}<{min_items}")
    if len(items) > max_items:
        failures.append(f"above_max_articles:{len(items)}>{max_items}")
    if any(final_ineligibility_reason(item) for item in items):
        failures.append("contains_final_ineligible_items")
    if any(item.get("usefulness_category", classify_usefulness_category(item)) == "General context" for item in items):
        failures.append("contains_general_context")
    if any(item.get("anti_scam_relevance") == "weak" for item in items):
        failures.append("contains_weak_anti_scam_relevance")
    if any(item.get("rejection_reason") for item in items):
        failures.append("contains_rejected_items")
    if sum(1 for item in items if is_local_current_affairs_item(item)) > 1:
        failures.append("too_many_singapore_sea_current_affairs")
    if sum(1 for item in items if is_local_sea_item(item)) > 3 or (
        sum(1 for item in items if is_local_sea_item(item)) > 2
        and not any(is_sea_operational_intelligence_item(item) for item in items if is_local_sea_item(item))
    ):
        failures.append("too_many_singapore_sea_items")
    if sum(1 for item in items if item.get("article_type", classify_article_type(item)) == "Enforcement report") > 2:
        failures.append("too_many_enforcement_reports")
    if sum(1 for item in items if is_plain_news_item(item) and not is_high_value_product_radar_item(item)) > 2:
        failures.append("too_many_plain_news_reports")
    if sum(1 for item in items if is_company_profile_item(item)) > 1:
        failures.append("too_many_company_profiles")
    if sum(1 for item in items if is_sponsored_vendor_item(item)) > 1:
        failures.append("too_many_sponsored_vendor_items")
    if research_cap_exceeded(items):
        failures.append("too_many_research_items")
    if short_research_product_cap_exceeded(items):
        failures.append("too_many_research_or_product_idea_items_for_short_digest")
    if source_domain_cap_exceeded(items):
        failures.append("too_many_from_same_source_domain")
    if any(is_longform_investigative_item(item) for item in available) and not any(is_longform_investigative_item(item) for item in items):
        failures.append("missing_investigation_deep_analysis_or_operational_intelligence_if_available")
    if any(is_non_academic_longform_operational_item(item) for item in available) and not any(
        is_non_academic_longform_operational_item(item) for item in items
    ):
        failures.append("missing_non_academic_longform_investigative_or_operational_if_available")
    if any(is_research_psychology_item(item) for item in available) and not any(is_research_psychology_item(item) for item in items):
        failures.append("missing_research_psychology_or_victimology_if_available")
    if any(is_platform_product_item(item) or is_technical_item(item) for item in available) and not any(is_platform_product_item(item) or is_technical_item(item) for item in items):
        failures.append("missing_technical_platform_product_or_data_source_if_available")
    if any(is_modus_infrastructure_item(item) for item in available) and not any(is_modus_infrastructure_item(item) for item in items):
        failures.append("missing_modus_operandi_or_infrastructure_if_available")
    return failures


def load_ranking_runs() -> dict[str, list[dict[str, Any]]]:
    if not RANKING_RUNS_PATH.exists():
        return {"runs": []}
    try:
        with RANKING_RUNS_PATH.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (json.JSONDecodeError, OSError):
        return {"runs": []}
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
        return {"runs": []}
    return data


def save_ranking_run(pipeline: dict[str, Any], selected_items: list[dict[str, Any]], failures: list[str]) -> None:
    cache_info = pipeline.get("cache_info", {})
    run = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "used_candidate_cache": bool(cache_info.get("used_candidate_cache", False)),
        "candidate_cache_age_minutes": cache_info.get("candidate_cache_age_minutes"),
        "candidate_count": len(pipeline.get("ranked_candidates", [])),
        "shortlist_count": len(pipeline.get("shortlist", [])),
        "query_group_distribution": query_group_distribution(pipeline.get("ranked_candidates", [])),
        "source_domain_distribution": source_domain_distribution(pipeline.get("shortlist", [])),
        "article_type_distribution": article_type_distribution(selected_items),
        "usefulness_category_distribution": usefulness_category_distribution(selected_items),
        "final_mix_constraints_satisfied": not failures,
        "failed_constraints": failures,
    }
    data = load_ranking_runs()
    data["runs"].append(run)
    data["runs"] = data["runs"][-50:]
    RANKING_RUNS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with RANKING_RUNS_PATH.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, sort_keys=True)
        file.write("\n")


def format_digest(items: list[dict[str, Any]]) -> str:
    today_datetime = datetime.now(timezone.utc)
    today = today_datetime.strftime("%d %b %Y")
    lines = [
        "🕵️ AI Abuse & Scam Radar",
        today,
        "",
    ]

    item_number = 1
    grouped_sections = grouped_items_by_section(items)
    for section_index, (section, section_items) in enumerate(grouped_sections.items()):
        if section_index > 0 and lines[-1] != "":
            lines.append("")
        lines.append(f"{SECTION_MARKER} {section}")
        lines.append("")
        for item in section_items:
            article_type = item.get("article_type", classify_article_type(item))
            usefulness_category = item.get("usefulness_category", classify_usefulness_category(item))
            lines.append(f"{item_number}. 【{article_type} · {usefulness_category}】")
            lines.append(display_title(item["title"]))
            lines.append(item["canonical_url"])
            for takeaway in item_key_takeaways(item):
                lines.append(f"{TAKEAWAY_MARKER} {takeaway}")
            lines.append("")
            item_number += 1

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


def send_telegram_message(message: str) -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID") or os.environ.get("TELEGRAM_CHANNEL_ID")

    if not token:
        raise ValueError("Missing TELEGRAM_BOT_TOKEN")
    if not chat_id:
        raise ValueError("Missing TELEGRAM_CHAT_ID")

    print(f"Telegram message length: {len(message)} characters")

    url = f"https://api.telegram.org/bot{token}/sendMessage"

    payload = {
        "chat_id": chat_id,
        "text": message,
        "disable_web_page_preview": False,
    }

    response = requests.post(url, json=payload, timeout=30)

    if not response.ok:
        print("Telegram API error status:", response.status_code)
        print("Telegram API error body:", response.text)

    response.raise_for_status()
    try:
        response_data = response.json()
    except ValueError as exc:
        raise ValueError("Telegram API returned non-JSON response") from exc

    if not response_data.get("ok"):
        raise ValueError(f"Telegram API returned ok=false: {response_data}")

    result = response_data.get("result") or {}
    delivered_chat = result.get("chat") or {}
    print(f"Telegram API ok: {response_data.get('ok')}")
    print(f"Telegram delivered message_id: {result.get('message_id')}")
    print(f"Telegram delivered chat id: {delivered_chat.get('id')}")
    print(f"Telegram delivered chat type: {delivered_chat.get('type')}")
    print(f"Telegram delivered chat title: {delivered_chat.get('title')}")
    print(f"Telegram delivered chat username: {delivered_chat.get('username')}")


def rerank_cached_candidates(
    cached_candidates: list[dict[str, Any]],
    config: dict[str, Any],
    seen: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    stats = {
        "rss_queries_run": 0,
        "raw_candidate_count": len(cached_candidates),
        "date_filtered_candidate_count": len(cached_candidates),
        "seen_filtered_candidate_count": 0,
        "ranked_unseen_candidate_count": 0,
        "query_cap_reached": 0,
        "queries_available_count": 0,
        "google_news_candidate_cap_reached": 0,
        "arxiv_candidate_cap_reached": 0,
        "reference_url_candidate_cap_reached": 0,
        "reference_examples_loaded_count": len(configured_reference_examples(config)),
        "reference_urls_included_as_candidates_count": 0,
        "monitored_sources_queried_count": len(configured_monitored_sources(config)),
    }
    filtered: list[dict[str, Any]] = []
    reranked_all: list[dict[str, Any]] = []
    for cached in cached_candidates:
        candidate = candidate_from_cache(cached)
        if is_seen(candidate, seen):
            stats["seen_filtered_candidate_count"] += 1
            continue
        candidate["article_type"] = classify_article_type(candidate)
        candidate["usefulness_category"] = classify_usefulness_category(candidate)
        candidate["source_reputation"] = source_reputation(candidate, config)
        cached_relevance = {
            key: candidate.get(key)
            for key in (
                "anti_scam_relevance",
                "strong_scam_anchor_terms_found",
                "title_scam_anchor_terms_found",
                "weak_generic_terms_found",
                "direct_relevance_terms_found",
                "technology_modus_terms_found",
                "direct_scam_relevance_terms_found",
                "research_relevance_category",
                "research_relevance_score",
                "downrank_reason",
                "hard_rejected",
                "hard_rejection_reason",
            )
        }
        updated_relevance = relevance_fields(candidate)
        candidate.update(updated_relevance)
        for key in (
            "strong_scam_anchor_terms_found",
            "title_scam_anchor_terms_found",
            "weak_generic_terms_found",
            "direct_relevance_terms_found",
            "technology_modus_terms_found",
            "direct_scam_relevance_terms_found",
        ):
            cached_values = [] if candidate.get("hard_rejected") else (cached_relevance.get(key) or [])
            merged = list(dict.fromkeys((candidate.get(key) or []) + cached_values))
            candidate[key] = merged[:12]
        if cached_relevance.get("anti_scam_relevance") == "direct" and not candidate.get("hard_rejected"):
            candidate["anti_scam_relevance"] = "direct"
        current_research_category = candidate.get("research_relevance_category")
        cached_research_category = cached_relevance.get("research_relevance_category")
        if (
            current_research_category in {None, "irrelevant_or_adjacent", "generic_fraud_ml", "generic_cybersecurity", "generic_ai_security"}
            and cached_research_category
            and cached_research_category
            not in {"irrelevant_or_adjacent", "generic_fraud_ml", "generic_cybersecurity", "generic_ai_security"}
        ):
            candidate["research_relevance_category"] = cached_relevance["research_relevance_category"]
            candidate["research_relevance_score"] = cached_relevance.get("research_relevance_score")
        if cached_relevance.get("hard_rejected"):
            candidate["hard_rejected"] = cached_relevance.get("hard_rejected")
            candidate["hard_rejection_reason"] = cached_relevance.get("hard_rejection_reason")
        candidate["original_score"] = score_item(candidate, datetime.now(timezone.utc))
        candidate["quality_score"] = compute_quality_score(candidate, config)
        rejection_reason = quality_rejection_reason(candidate, config)
        candidate["quality_rejected"] = bool(rejection_reason)
        if rejection_reason:
            candidate["rejection_reason"] = rejection_reason
            if not soft_final_rejection_allowed(candidate, config):
                candidate["quality_score"] = -999
            stats["quality_rejected_candidate_count"] = stats.get("quality_rejected_candidate_count", 0) + 1
        else:
            candidate["rejection_reason"] = None
            final_reason = final_ineligibility_reason(candidate, config, allow_adjacent=True)
            if final_reason:
                candidate["final_ineligibility_reason"] = final_reason
                candidate["rejection_reason"] = final_reason
                candidate["quality_rejected"] = True
                candidate["quality_score"] = -999
                stats["quality_rejected_candidate_count"] = stats.get("quality_rejected_candidate_count", 0) + 1
            else:
                candidate["quality_rejected"] = False
                filtered.append(candidate)
        reranked_all.append(candidate)

    pre_gemini_deduped = dedupe_near_duplicates(filtered, stats, "pre_gemini")
    ranked = sorted(
        pre_gemini_deduped,
        key=lambda item: (int(item.get("quality_score", 0)), int(item.get("original_score", 0)), item.get("title", "")),
        reverse=True,
    )
    quality_ranked = sorted(
        reranked_all,
        key=lambda item: (int(item.get("quality_score", 0)), int(item.get("original_score", 0)), item.get("title", "")),
        reverse=True,
    )
    stats["ranked_unseen_candidate_count"] = len(ranked)
    return ranked, quality_ranked, stats


def run_pipeline(
    config: dict[str, Any],
    seen: dict[str, dict[str, Any]],
    resolve_urls: bool = True,
    debug: bool = False,
    use_cache: bool = False,
    refresh_cache: bool = False,
    rerank_cache: bool = False,
    allow_cache_fallback: bool = True,
) -> dict[str, Any]:
    lookback_days = int(os.getenv("LOOKBACK_DAYS", config.get("lookback_days", "30")))
    max_article_age_days = int(os.getenv("MAX_ARTICLE_AGE_DAYS", config.get("max_article_age_days", "4")))
    shortlist_count = int(os.getenv("DIGEST_SHORTLIST_COUNT", config.get("max_candidates_for_llm", "20")))
    inspect_count = int(quality_config(config).get("inspect_top_n_candidates", 80))
    sources = load_sources(config)

    timing: dict[str, float] = {}
    cache_info: dict[str, Any] = {
        "used_candidate_cache": False,
        "candidate_cache_age_minutes": None,
        "candidate_cache_candidate_count": 0,
        "fetch_skipped": False,
        "cache_fallback_used": False,
        "cache_fallback_allowed": allow_cache_fallback,
    }
    if rerank_cache or (use_cache and not refresh_cache):
        cached_candidates, loaded_cache_info = load_candidate_cache(config, require_fresh=not rerank_cache)
        cache_info.update(loaded_cache_info)
        if cached_candidates:
            cache_info["fetch_skipped"] = True
            rerank_started = time.monotonic()
            ranked_candidates, quality_ranked_candidates, stats = rerank_cached_candidates(cached_candidates, config, seen)
            timing["fetch_runtime_seconds"] = 0.0
            timing["url_resolution_runtime_seconds"] = 0.0
            timing["quality_inspection_runtime_seconds"] = time.monotonic() - rerank_started
            ranked_candidates, shortlist = build_pre_gemini_shortlist(
                ranked_candidates,
                shortlist_count,
                config,
                stats,
            )
            if resolve_urls and shortlist:
                resolve_started = time.monotonic()
                url_cache = load_cache(URL_CACHE_PATH)
                shortlist = canonicalise_top_candidates(
                    shortlist,
                    limit=len(shortlist),
                    max_google_news_to_resolve=len(shortlist),
                    stats=stats,
                    url_cache=url_cache,
                )
                timing["url_resolution_runtime_seconds"] = time.monotonic() - resolve_started
                save_cache(URL_CACHE_PATH, url_cache)
            stats["ranked_unseen_candidate_count"] = len(ranked_candidates)
            return {
                "rss_queries_run": 0,
                "raw_candidates": cached_candidates,
                "date_filtered_candidates": cached_candidates,
                "seen_filtered_count": stats["seen_filtered_candidate_count"],
                "ranked_candidates": ranked_candidates,
                "quality_ranked_candidates": quality_ranked_candidates,
                "shortlist": shortlist,
                "stats": stats,
                "timing": timing,
                "cache_info": cache_info,
                "config": config,
            }
        if rerank_cache:
            print(f"Candidate cache unavailable for rerank: {cache_info.get('reason')}")
            stats = {
                "rss_queries_run": 0,
                "raw_candidate_count": 0,
                "date_filtered_candidate_count": 0,
                "seen_filtered_candidate_count": 0,
                "ranked_unseen_candidate_count": 0,
                "query_cap_reached": 0,
                "queries_available_count": 0,
                "google_news_candidate_cap_reached": 0,
                "arxiv_candidate_cap_reached": 0,
                "reference_url_candidate_cap_reached": 0,
                "reference_examples_loaded_count": len(configured_reference_examples(config)),
                "reference_urls_included_as_candidates_count": 0,
                "monitored_sources_queried_count": len(configured_monitored_sources(config)),
            }
            return {
                "rss_queries_run": 0,
                "raw_candidates": [],
                "date_filtered_candidates": [],
                "seen_filtered_count": 0,
                "ranked_candidates": [],
                "quality_ranked_candidates": [],
                "shortlist": [],
                "stats": stats,
                "timing": {
                    "fetch_runtime_seconds": 0.0,
                    "url_resolution_runtime_seconds": 0.0,
                    "quality_inspection_runtime_seconds": 0.0,
                },
                "cache_info": cache_info,
                "config": config,
            }

    fetch_started = time.monotonic()
    try:
        ranked_candidates, stats = fetch_candidates(sources, seen, lookback_days, max_article_age_days, debug, config)
    except Exception as exc:
        if not allow_cache_fallback:
            print(f"Fresh fetch failed and candidate cache fallback is disabled: {exc}")
            raise
        cached_candidates, loaded_cache_info = load_candidate_cache(config, require_fresh=True)
        if not cached_candidates:
            raise
        print(f"Fresh fetch failed; using fresh candidate cache fallback: {exc}")
        cache_info.update(loaded_cache_info)
        cache_info["fetch_skipped"] = True
        cache_info["cache_fallback_used"] = True
        ranked_candidates, quality_ranked_candidates, stats = rerank_cached_candidates(cached_candidates, config, seen)
        timing["fetch_runtime_seconds"] = time.monotonic() - fetch_started
        timing["url_resolution_runtime_seconds"] = 0.0
        timing["quality_inspection_runtime_seconds"] = 0.0
        ranked_candidates, shortlist = build_pre_gemini_shortlist(
            ranked_candidates,
            shortlist_count,
            config,
            stats,
        )
        if resolve_urls and shortlist:
            resolve_started = time.monotonic()
            url_cache = load_cache(URL_CACHE_PATH)
            shortlist = canonicalise_top_candidates(
                shortlist,
                limit=len(shortlist),
                max_google_news_to_resolve=len(shortlist),
                stats=stats,
                url_cache=url_cache,
            )
            timing["url_resolution_runtime_seconds"] = time.monotonic() - resolve_started
            save_cache(URL_CACHE_PATH, url_cache)
        stats["ranked_unseen_candidate_count"] = len(ranked_candidates)
        return {
            "rss_queries_run": 0,
            "raw_candidates": cached_candidates,
            "date_filtered_candidates": cached_candidates,
            "seen_filtered_count": stats["seen_filtered_candidate_count"],
            "ranked_candidates": ranked_candidates,
            "quality_ranked_candidates": quality_ranked_candidates,
            "shortlist": shortlist,
            "stats": stats,
            "timing": timing,
            "cache_info": cache_info,
            "config": config,
        }
    timing["fetch_runtime_seconds"] = time.monotonic() - fetch_started
    raw_candidates = list(ranked_candidates)

    url_cache = load_cache(URL_CACHE_PATH)
    quality_cache = load_cache(QUALITY_CACHE_PATH)
    if resolve_urls:
        resolve_started = time.monotonic()
        max_google_news_to_resolve = int(
            os.getenv(
                "MAX_GOOGLE_NEWS_URLS_TO_RESOLVE",
                config.get("max_google_news_urls_to_resolve", max(160, inspect_count * 4)),
            )
        )
        ranked_candidates = canonicalise_top_candidates(
            ranked_candidates,
            limit=max(50, inspect_count),
            max_google_news_to_resolve=max_google_news_to_resolve,
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
    quality_started = time.monotonic()
    ranked_candidates, quality_ranked_candidates = apply_quality_filters(ranked_candidates, config, stats, quality_cache)
    timing["quality_inspection_runtime_seconds"] = time.monotonic() - quality_started
    save_cache(QUALITY_CACHE_PATH, quality_cache)
    ranked_candidates, shortlist = build_pre_gemini_shortlist(ranked_candidates, shortlist_count, config, stats)
    if resolve_urls and shortlist:
        shortlist = canonicalise_top_candidates(
            shortlist,
            limit=len(shortlist),
            max_google_news_to_resolve=len(shortlist),
            stats=stats,
            url_cache=url_cache,
        )
        save_cache(URL_CACHE_PATH, url_cache)
    stats["ranked_unseen_candidate_count"] = len(ranked_candidates)
    save_candidate_cache(quality_ranked_candidates, config)

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
        "cache_info": cache_info,
        "config": config,
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
    refresh_cache = "--refresh-cache" in sys.argv
    rerank_cache = "--rerank-cache" in sys.argv
    use_cache = "--use-cache" in sys.argv
    disable_cache_fallback = "--no-cache-fallback" in sys.argv or os.getenv("DISABLE_CANDIDATE_CACHE_FALLBACK", "").lower() in {
        "1",
        "true",
        "yes",
    }
    if rerank_cache or (refresh_cache and not dry_run_with_llm):
        dry_run = True
        dry_run_with_llm = False
    debug = "--debug" in sys.argv or os.getenv("DEBUG", "").lower() in {"1", "true", "yes"}
    max_items = min(5, int(os.getenv("MAX_ARTICLES_TO_SEND", config.get("max_articles_to_send", "5"))))
    min_items = min(max_items, int(os.getenv("MIN_ARTICLES_TO_SEND", config.get("min_articles_to_send", "1"))))
    seen_retention_days = int(os.getenv("SEEN_RETENTION_DAYS", config.get("seen_retention_days", "365")))
    seen = prune_seen(load_seen(), seen_retention_days)
    pipeline = run_pipeline(
        config,
        seen,
        resolve_urls=not dry_run_no_resolve,
        debug=debug,
        use_cache=use_cache,
        refresh_cache=refresh_cache,
        rerank_cache=rerank_cache,
        allow_cache_fallback=not disable_cache_fallback,
    )
    ranked_candidates = pipeline["ranked_candidates"]
    shortlist = pipeline["shortlist"]

    if dry_run and not dry_run_with_llm:
        print_pipeline_report(pipeline)
        failures = final_mix_constraint_failures([], min_items, max_items, pipeline.get("ranked_candidates", []))
        save_ranking_run(pipeline, [], failures)
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
    pipeline["stats"]["gemini_selected_count"] = len(ranked_items)
    selected_items = select_final_items(ranked_items, config, max_items)
    selected_items = dedupe_near_duplicates(selected_items, pipeline["stats"], "post_gemini")
    selected_items = repair_final_selection(selected_items, pipeline.get("ranked_candidates", ranked_items), config, max_items, pipeline["stats"])
    selected_items = dedupe_near_duplicates(selected_items, pipeline["stats"], "final")
    duplicate_pairs = near_duplicate_pairs(selected_items)
    if duplicate_pairs:
        first_pair = duplicate_pairs[0]
        raise ValueError(
            "Final duplicate guard failed: "
            f"{first_pair['left_title']} / {first_pair['right_title']} ({first_pair['reason']})"
        )
    final_dedupe_count = pipeline["stats"].get("post_gemini_duplicates_removed_count", 0) + pipeline["stats"].get(
        "final_duplicates_removed_count", 0
    )

    if dry_run_with_llm:
        run = build_cost_run(
            "dry-run-with-llm",
            cost_data,
            candidate_count=len(ranked_candidates),
            shortlist_count=len(shortlist),
            sent_count=len(selected_items),
            pipeline=pipeline,
        )
        save_cost_log(run)
        print_pipeline_report(pipeline)
        final_failures = final_mix_constraint_failures(selected_items, min_items, max_items, pipeline.get("ranked_candidates", ranked_items))
        print(f"final article count: {len(selected_items)}")
        print(f"number of final selected articles: {len(selected_items)}")
        print(f"final article_type distribution: {article_type_distribution(selected_items)}")
        print(f"final usefulness_category distribution: {usefulness_category_distribution(selected_items)}")
        print(f"article count below min: {len(selected_items) < min_items}")
        print(f"article count above max: {len(selected_items) > max_items}")
        print(f"final section distribution: {section_distribution(selected_items)}")
        print(f"final source domain distribution: {source_domain_distribution(selected_items)}")
        print(
            "final enforcement report count: "
            f"{sum(1 for item in selected_items if item.get('article_type', classify_article_type(item)) == 'Enforcement report')}"
        )
        print(f"final Singapore / Southeast Asia item count: {sum(1 for item in selected_items if is_local_sea_item(item))}")
        print(f"final research paper count: {sum(1 for item in selected_items if is_research_item(item))}")
        print(f"final news report count: {sum(1 for item in selected_items if is_plain_news_item(item))}")
        print(f"final psychology / persuasion / victimology item count: {sum(1 for item in selected_items if is_psychology_item(item))}")
        print(f"final investigative/deep analysis item count: {sum(1 for item in selected_items if is_investigative_or_operational_item(item))}")
        print(f"final platform/product/data-source item count: {sum(1 for item in selected_items if is_platform_product_item(item))}")
        print(f"final reference URL candidate count: {sum(1 for item in selected_items if item.get('reference_url_candidate'))}")
        print(
            "final research/longform organic discovery count: "
            f"{sum(1 for item in selected_items if (is_research_psychology_item(item) or is_longform_investigative_item(item)) and not item.get('reference_url_candidate'))}"
        )
        print(f"final_research_count: {sum(1 for item in selected_items if is_research_item(item))}")
        print(f"final_victim_psychology_count: {sum(1 for item in selected_items if is_psychology_item(item))}")
        print(f"final_longform_investigative_count: {sum(1 for item in selected_items if is_longform_investigative_item(item))}")
        print(f"final_non_academic_longform_operational_count: {sum(1 for item in selected_items if is_non_academic_longform_operational_item(item))}")
        print(f"final_operational_intelligence_count: {sum(1 for item in selected_items if item.get('usefulness_category', classify_usefulness_category(item)) == 'Operational intelligence')}")
        print(f"final_sea_operational_intelligence_count: {sum(1 for item in selected_items if is_sea_operational_intelligence_item(item))}")
        print(f"final_sponsored_vendor_count: {sum(1 for item in selected_items if is_sponsored_vendor_item(item))}")
        print(f"duplicate_podcast_or_summary_removed_count: {pipeline['stats'].get('duplicate_podcast_or_summary_removed_count', 0)}")
        print(f"gemini_selected_count: {pipeline['stats'].get('gemini_selected_count', 0)}")
        print(f"post_gemini_invalid_removed_count: {pipeline['stats'].get('post_gemini_invalid_removed_count', 0)}")
        for item in pipeline["stats"].get("post_gemini_invalid_removed_examples", []):
            print(f"post_gemini_invalid_removed_example: title={item.get('title')} | reason={item.get('reason')} | url={item.get('url')}")
        print(f"refill_candidates_added_count: {pipeline['stats'].get('refill_candidates_added_count', 0)}")
        print(f"final_ineligible_items_count: {pipeline['stats'].get('final_ineligible_items_count', 0)}")
        print(f"final_general_context_count: {pipeline['stats'].get('final_general_context_count', 0)}")
        print(f"final_weak_relevance_count: {pipeline['stats'].get('final_weak_relevance_count', 0)}")
        print(f"final_rejected_item_count: {pipeline['stats'].get('final_rejected_item_count', 0)}")
        print(f"post_gemini_repair_applied: {bool(pipeline['stats'].get('post_gemini_repair_applied', False))}")
        for item in pipeline["stats"].get("post_gemini_repair_inserted", []):
            print(f"item_inserted_by_repair: title={item.get('title')} | reason={item.get('reason')} | url={item.get('url')}")
        for item in pipeline["stats"].get("post_gemini_repair_removed", []):
            print(f"item_removed_by_repair: title={item.get('title')} | url={item.get('url')}")
        for item in high_value_candidate_diagnostics(selected_items, pipeline.get("quality_ranked_candidates") or pipeline.get("ranked_candidates", [])):
            print(
                "high_value_candidate_status: "
                f"label={item.get('label')} | status={item.get('status')} | reason={item.get('reason')} | "
                f"title={item.get('title', '')} | url={item.get('url', '')}"
            )
        print_must_include_final_status(pipeline["stats"], selected_items, cost_data)
        print(f"final mix constraints satisfied: {not final_failures}")
        if final_failures:
            print(f"final mix constraint failures: {', '.join(final_failures)}")
        save_ranking_run(pipeline, selected_items, final_failures)
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
        pipeline=pipeline,
    )
    save_cost_log(run)
    write_github_summary(run)
    print_pipeline_report(pipeline)
    final_failures = final_mix_constraint_failures(selected_items, min_items, max_items, pipeline.get("ranked_candidates", ranked_items))
    save_ranking_run(pipeline, selected_items, final_failures)

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
