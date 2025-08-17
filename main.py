import os
import re
import asyncio
import base64
from telethon.sync import TelegramClient
from telethon.sessions import StringSession
from dotenv import load_dotenv

load_dotenv()

# --- تنظیمات اصلی ---
API_ID = os.environ.get("API_ID")
API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")
CHANNEL_USERNAMES = [channel.strip() for channel in os.environ.get("CHANNEL_USERNAMES", "").split(',')]
MESSAGE_LIMIT_PER_CHANNEL = 50
OUTPUT_FILE = "subscription.txt"

# --- Regex نهایی و اصلاح شده ---
# این نسخه اصلاح شده، گروه capturing را حذف می‌کند تا findall کل لینک را برگرداند
config_pattern = re.compile(r'\b(?:vless|vmess|trojan)://[^\s<>"\'`]+')

async def main():
    all_configs = set()
    async with TelegramClient(StringSession(SESSION_STRING), API_ID, API_HASH) as client:
        print("✅ کلاینت تلگرام با موفقیت متصل شد.")
        for channel in CHANNEL_USERNAMES:
            print(f"\n🔎 در حال بررسی کانال: {channel}")
            try:
                async for message in client.iter_messages(channel, limit=MESSAGE_LIMIT_PER_CHANNEL):
                    if message.text:
                        found_configs = config_pattern.findall(message.text)
                        # پاک‌سازی لینک‌ها از کاراکترهای ناخواسته احتمالی در انتها
                        cleaned_configs = [config.strip() for config in found_configs]
                        all_configs.update(cleaned_configs)
            except Exception as e:
                print(f"❌ خطا در خواندن پیام‌های کانال {channel}: {e}")

    print(f"\n✅ استخراج تمام شد. تعداد کل کانفیگ‌های پیدا شده: {len(all_configs)}")

    if all_configs:
        # تست کانفیگ‌ها حذف شده است. تمام کانفیگ‌های پیدا شده مستقیماً استفاده می‌شوند.
        final_configs = list(all_configs)
        print(f"✅ تست حذف شد. تعداد {len(final_configs)} کانفیگ برای افزودن به لینک آماده شد.")

        subscription_content = "\n".join(final_configs)
        subscription_base64 = base64.b64encode(subscription_content.encode('utf-8')).decode('utf-8')
        
        with open(OUTPUT_FILE, "w") as f:
            f.write(subscription_base64)
        print(f"\n🚀 لینک سابسکریپشن با موفقیت در فایل '{OUTPUT_FILE}' ایجاد شد.")
    else:
        print("هیچ کانفیگی در کانال‌ها یافت نشد.")

if __name__ == "__main__":
    if not API_ID or not API_HASH:
        print("❌ خطا: لطفاً مقادیر API_ID و API_HASH را در فایل .env تنظیم کنید.")
    elif not SESSION_STRING:
        print("⚠️ Session String یافت نشد. برای ساخت آن وارد شوید.")
        with TelegramClient(StringSession(), int(API_ID), API_HASH) as client:
            session_str = client.session.save()
            print("\n✅ Session String شما ایجاد شد. آن را کپی کنید:")
            print("-" * 50)
            print(session_str)
            print("-" * 50)
    else:
        asyncio.run(main())