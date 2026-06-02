# AI Abuse & Scam Radar

A one-way Telegram Channel bot that monitors scam, fraud, and AI-abuse signals across news, research, investigations, official sources, developer updates, and targeted search queries.

The bot is designed as a lightweight adversarial product radar for anti-scam work. It prioritises articles that reveal scammer methods, victim psychology, scam infrastructure, deepfake and impersonation abuse, phishing and social-engineering techniques, platform/telco/bank controls, and product-relevant research.

It posts a daily digest to a configured Telegram Channel and records sent items so the same story is not repeated.

Default freshness policy: news, enforcement, and current-affairs items must be 0-4 days old; platform/product/official updates can be up to 30 days old; research papers can be up to 180 days old; investigative/deep longform can be up to 90 days old.

## What it does

- Fetches candidates from Google News RSS, arXiv-style research sources, monitored domains, and configured source queries.
- Filters for recency, source quality, anti-scam relevance, and duplicate stories.
- Ranks items by usefulness for anti-scam product work.
- Uses Gemini only as a final selector over a compact shortlist.
- Sends a plain-text Telegram message grouped by article category, capped at 5 articles and ideally 3-4.
- Adds up to 3 concise key-takeaway bullets per article.
- Tracks sent URLs and title fingerprints in `data/seen.json`.
- Logs Gemini cost estimates and usage metadata in `data/cost_log.json`.
- Supports cached reranking so ranking changes can be tested without repeatedly refetching the web.

## Example output

```text
🕵️ AI Abuse & Scam Radar
24 May 2026

━━━━━━━━━━━━━━━━
🧠 VICTIM PSYCHOLOGY & PERSUASION
━━━━━━━━━━━━━━━━
1. 【Research paper · Research / novel method】
Profiling User Vulnerability to Phishing Through Psychological and Behavioral Factors
https://arxiv.org/abs/2605.21246
- Identifies psychological and behavioral factors linked to phishing susceptibility.
- Useful for designing scam-warning and intervention features.

━━━━━━━━━━━━━━━━
🕵️ INVESTIGATIONS & OPERATIONAL INTELLIGENCE
━━━━━━━━━━━━━━━━
2. 【News report · Operational intelligence】
Sri Lanka becomes next hub for scam networks
https://...
- Highlights scam-network migration patterns.
- Useful signal for regional monitoring and risk triage.

Access note: If a link has access issues, try the official source, author-hosted copy, institutional repository, arXiv/SSRN/OSF version, or reputable secondary coverage.
