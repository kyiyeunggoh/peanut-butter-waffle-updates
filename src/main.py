from __future__ import annotations

import hashlib
import html
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import feedparser
import requests
import yaml
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]
SOURCES_PATH = ROOT / "config" / "sources.yml"
SEEN_PATH = ROOT / "data" / "seen.json"
COST_LOG_PATH = ROOT / "data" / "cost_log.json"
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


def load_sources() -> list[dict[str, Any]]:
    with SOURCES_PATH.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file) or {}
    return [source for source in config.get("sources", []) if source.get("enabled", True)]


def load_seen() -> set[str]:
    if not SEEN_PATH.exists():
        return set()

    with SEEN_PATH.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, dict):
        return set(data.get("items", []))
    return set()


def save_seen(seen: set[str]) -> None:
    SEEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    with SEEN_PATH.open("w", encoding="utf-8") as file:
        json.dump({"items": sorted(seen)}, file, indent=2)
        file.write("\n")


def item_id(entry: Any) -> str:
    raw_id = entry.get("id") or entry.get("link") or entry.get("title", "")
    return hashlib.sha256(raw_id.encode("utf-8")).hexdigest()


def collect_new_items(sources: list[dict[str, Any]], seen: set[str], limit: int) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []

    for source in sources:
        feed = feedparser.parse(source["url"])
        for entry in feed.entries:
            digest_id = item_id(entry)
            if digest_id in seen:
                continue

            items.append(
                {
                    "id": digest_id,
                    "source": source["name"],
                    "title": entry.get("title", "Untitled"),
                    "link": entry.get("link", source["url"]),
                }
            )

            if len(items) >= limit:
                return items

    return items


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def estimate_cost(input_tokens: int, output_tokens: int) -> float:
    input_price = float(os.getenv("GEMINI_INPUT_PRICE_PER_1M", "0.25"))
    output_price = float(os.getenv("GEMINI_OUTPUT_PRICE_PER_1M", "1.50"))
    return (input_tokens / 1_000_000 * input_price) + (output_tokens / 1_000_000 * output_price)


def rule_rank_items(items: list[dict[str, str]]) -> list[dict[str, str]]:
    def score(item: dict[str, str]) -> tuple[int, str]:
        title = item["title"].lower()
        keyword_score = sum(3 for keyword in SCAM_KEYWORDS if keyword in title)
        return keyword_score, item["title"]

    return sorted(items, key=score, reverse=True)


def build_gemini_prompt(items: list[dict[str, str]], sent_count: int) -> str:
    candidates = "\n".join(
        f'{index}. id={item["id"]} title="{item["title"]}" link="{item["link"]}"'
        for index, item in enumerate(items, start=1)
    )
    return (
        "Rank these candidate articles for an AI abuse and scam radar digest. "
        "Prioritize concrete reports about AI-enabled fraud, scams, abuse, cyber misuse, "
        "impersonation, deepfakes, platform abuse, safety research, and enforcement. "
        f"Return only the top {sent_count} article ids, one id per line, with no commentary.\n\n"
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
    items: list[dict[str, str]],
    sent_count: int,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    model = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
    max_output_tokens = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "600"))
    max_cost = float(os.getenv("MAX_DAILY_GEMINI_COST_USD", "0.10"))
    prompt = build_gemini_prompt(items, sent_count)
    estimated_input_tokens = estimate_tokens(prompt)
    estimated_output_tokens = max_output_tokens
    estimated_cost_usd = estimate_cost(estimated_input_tokens, estimated_output_tokens)

    print(
        "Gemini estimate: "
        f"input_tokens={estimated_input_tokens}, "
        f"output_tokens={estimated_output_tokens}, "
        f"estimated_cost_usd={estimated_cost_usd:.6f}, "
        f"max_daily_cost_usd={max_cost:.6f}"
    )

    cost_data: dict[str, Any] = {
        "model": model,
        "used_llm": False,
        "estimated_input_tokens": estimated_input_tokens,
        "estimated_output_tokens": estimated_output_tokens,
        "estimated_cost_usd": round(estimated_cost_usd, 6),
        "actual_prompt_tokens": None,
        "actual_output_tokens": None,
        "actual_total_tokens": None,
        "actual_cost_usd": None,
    }

    if estimated_cost_usd > max_cost:
        print("Gemini skipped: estimated cost exceeds MAX_DAILY_GEMINI_COST_USD.")
        return rule_rank_items(items), cost_data

    if not os.getenv("GEMINI_API_KEY"):
        print("Gemini skipped: GEMINI_API_KEY is not set.")
        return rule_rank_items(items), cost_data

    try:
        text, usage = call_gemini(prompt, model, max_output_tokens)
    except requests.RequestException as exc:
        print(f"Gemini skipped after request failure: {exc}")
        return rule_rank_items(items), cost_data

    cost_data["used_llm"] = True
    if usage:
        prompt_tokens = usage.get("promptTokenCount")
        output_tokens = usage.get("candidatesTokenCount")
        total_tokens = usage.get("totalTokenCount")
        cost_data["actual_prompt_tokens"] = prompt_tokens
        cost_data["actual_output_tokens"] = output_tokens
        cost_data["actual_total_tokens"] = total_tokens

        if prompt_tokens is not None and output_tokens is not None:
            cost_data["actual_cost_usd"] = round(estimate_cost(prompt_tokens, output_tokens), 6)

        print(
            "Gemini actual usage: "
            f"prompt_tokens={prompt_tokens}, "
            f"output_tokens={output_tokens}, "
            f"total_tokens={total_tokens}"
        )

    ranked_ids = re.findall(r"\b[0-9a-f]{64}\b", text)
    items_by_id = {item["id"]: item for item in items}
    ranked = [items_by_id[item_id] for item_id in ranked_ids if item_id in items_by_id]
    ranked.extend(item for item in rule_rank_items(items) if item["id"] not in ranked_ids)
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


def write_github_summary(run: dict[str, Any]) -> None:
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    lines = [
        "## Gemini cost summary",
        "",
        f"- Date: {run['date']}",
        f"- Model: {run['model']}",
        f"- Used Gemini: {run['used_llm']}",
        f"- Estimated tokens: {run['estimated_input_tokens']} input, {run['estimated_output_tokens']} output",
        f"- Estimated cost: ${run['estimated_cost_usd']:.6f}",
        f"- Actual tokens: {run['actual_prompt_tokens']} input, {run['actual_output_tokens']} output, {run['actual_total_tokens']} total",
        f"- Actual cost: {run['actual_cost_usd']}",
        f"- Counts: {run['candidate_count']} candidates, {run['shortlist_count']} shortlisted, {run['sent_count']} sent",
        "",
    ]

    with Path(summary_path).open("a", encoding="utf-8") as file:
        file.write("\n".join(lines))


def format_digest(items: list[dict[str, str]]) -> str:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = ["<b>AI Abuse &amp; Scam Radar</b>", f"Date: {today}", ""]

    for index, item in enumerate(items, start=1):
        title = html.escape(item["title"])
        link = html.escape(item["link"], quote=True)
        lines.append(f"{index}. <b>{title}</b>")
        lines.append(f'<a href="{link}">{link}</a>')
        lines.append("")

    lines.append(html.escape(ACCESS_NOTE))

    return "\n".join(lines)


def send_telegram_message(text: str) -> None:
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    channel_id = os.getenv("TELEGRAM_CHANNEL_ID") or os.environ["TELEGRAM_CHAT_ID"]
    url = f"https://api.telegram.org/bot{token}/sendMessage"

    response = requests.post(
        url,
        json={
            "chat_id": channel_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": False,
        },
        timeout=30,
    )
    response.raise_for_status()


def main() -> None:
    load_dotenv(ROOT / ".env")

    max_items = int(os.getenv("DIGEST_MAX_ITEMS", "10"))
    candidate_count = int(os.getenv("DIGEST_CANDIDATE_COUNT", "50"))
    shortlist_count = int(os.getenv("DIGEST_SHORTLIST_COUNT", "20"))
    seen = load_seen()
    sources = load_sources()
    candidates = collect_new_items(sources, seen, candidate_count)
    shortlist = rule_rank_items(candidates)[:shortlist_count]

    if not shortlist:
        print("No new items to send.")
        return

    ranked_items, cost_data = rank_with_gemini(shortlist, max_items)
    selected_items = ranked_items[:max_items]
    run = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        **cost_data,
        "candidate_count": len(candidates),
        "shortlist_count": len(shortlist),
        "sent_count": len(selected_items),
    }

    send_telegram_message(format_digest(selected_items))

    for item in selected_items:
        seen.add(item["id"])
    save_seen(seen)
    save_cost_log(run)
    write_github_summary(run)

    print(f"Sent {len(selected_items)} item(s) to the Telegram channel.")


if __name__ == "__main__":
    main()
