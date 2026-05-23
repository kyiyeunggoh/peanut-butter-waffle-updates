# Telegram Channel Digest Bot

A simple one-way Telegram Channel digest bot. It reads RSS/Atom feeds from `config/sources.yml`, posts new items to one Telegram channel, and records sent items in `data/seen.json`.

There is no subscriber management. The bot only sends messages to the configured channel.

## Setup

1. Create a Telegram bot with BotFather.
2. Add the bot as an admin in your Telegram channel.
3. Copy `.env.example` to `.env` and fill in:

```env
TELEGRAM_BOT_TOKEN=123456:replace_me
TELEGRAM_CHANNEL_ID=@your_channel_username
GEMINI_API_KEY=replace_me
MAX_DAILY_GEMINI_COST_USD=0.10
DIGEST_MAX_ITEMS=8
```

4. Add or enable feeds in `config/sources.yml`.
5. Install dependencies and run:

```bash
pip install -r requirements.txt
python src/main.py
```

## GitHub Actions

`.github/workflows/daily.yml` runs once per day at `01:00 UTC` and can also be started manually.

Add these repository secrets:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHANNEL_ID`
- `GEMINI_API_KEY`

Optional repository variables:

- `DIGEST_MAX_ITEMS`
- `MAX_DAILY_GEMINI_COST_USD`
- `GEMINI_MODEL`
- `GEMINI_INPUT_PRICE_PER_1M`
- `GEMINI_OUTPUT_PRICE_PER_1M`
- `GEMINI_MAX_OUTPUT_TOKENS`
- `DIGEST_CANDIDATE_COUNT`
- `DIGEST_SHORTLIST_COUNT`

The workflow commits updates to `data/seen.json` so already-sent links are skipped on future runs. It also commits `data/cost_log.json`, keeping only the latest 180 runs.

Gemini cost estimates and usage metadata are logged to the console and summarized in the GitHub Actions job summary. Cost details are not included in the Telegram channel message.
