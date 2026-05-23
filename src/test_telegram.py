import os
import requests
from dotenv import load_dotenv

load_dotenv()

bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
chat_id = os.getenv("TELEGRAM_CHAT_ID")

if not bot_token:
    raise ValueError("Missing TELEGRAM_BOT_TOKEN in .env")

if not chat_id:
    raise ValueError("Missing TELEGRAM_CHAT_ID in .env")

url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

payload = {
    "chat_id": chat_id,
    "text": "Test post from AI Abuse & Scam Radar bot ✅",
    "disable_web_page_preview": True,
}

response = requests.post(url, json=payload, timeout=30)

print(response.status_code)
print(response.text)

response.raise_for_status()
