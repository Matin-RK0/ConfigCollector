import os
import re
import asyncio
import base64
import json  # <-- کتابخانه جدید برای کار با JSON
import subprocess
from telethon.sync import TelegramClient
from telethon.sessions import StringSession
from dotenv import load_dotenv

load_dotenv()

# --- تنظیمات اصلی (بدون تغییر) ---
API_ID = os.environ.get("API_ID")
API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")
CHANNEL_USERNAMES = [channel.strip() for channel in os.environ.get("CHANNEL_USERNAMES", "").split(',')]
MESSAGE_LIMIT_PER_CHANNEL = 50
OUTPUT_FILE = "subscription.txt"

config_pattern = re.compile(r'(vless|vmess|trojan)://[a-zA-Z0-9+/=_-]+(?:\?[^\s]+)?(?:#[^\s]+)?')

# --- تابع تست بهبود یافته ---
async def test_config(config: str) -> bool:
    """یک کانفیگ را با تست پینگ به سرور آن بررسی می‌کند. (نسخه هوشمندتر)"""
    server_address = ""
    try:
        # حالت اول: کانفیگ vmess (معمولاً Base64 است)
        if config.startswith('vmess://'):
            try:
                b64_part = config.split('vmess://')[1]
                # اطمینان از اینکه طول رشته برای base64 معتبر است
                b64_part += '=' * (-len(b64_part) % 4)
                decoded_json = base64.b64decode(b64_part).decode('utf-8')
                config_data = json.loads(decoded_json)
                server_address = config_data.get('add', '')
            except Exception as e:
                print(f"[!] خطا در کدگشایی vmess: {e}")
                return False

        # حالت دوم: کانفیگ‌های vless و trojan (آدرس معمولاً مستقیم است)
        else:
            match = re.search(r'@([^:]+):', config)
            if match:
                server_address = match.group(1)

        if not server_address:
            print(f"[!] آدرس سرور در کانفیگ یافت نشد: {config[:30]}...")
            return False

        print(f"[*] تست پینگ: {server_address}...")
        
        command = f"ping -c 1 -W 2 {server_address}" if os.name != 'nt' else f"ping -n 1 -w 2000 {server_address}"
        
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.communicate()

        if proc.returncode == 0:
            print(f"[+] پینگ موفق: {server_address}")
            return True
        else:
            print(f"[-] پینگ ناموفق: {server_address}")
            return False
            
    except Exception as e:
        print(f"[!] خطای کلی در تست کانفیگ: {e}")
        return False

# --- تابع اصلی (بدون تغییر) ---
async def main():
    """تابع اصلی برای اجرای کل فرآیند."""
    all_configs = set()

    async with TelegramClient(StringSession(SESSION_STRING), API_ID, API_HASH) as client:
        print("✅ کلاینت تلگرام با موفقیت متصل شد.")
        for channel in CHANNEL_USERNAMES:
            print(f"\n🔎 در حال بررسی کانال: {channel}")
            try:
                async for message in client.iter_messages(channel, limit=MESSAGE_LIMIT_PER_CHANNEL):
                    if message.text:
                        found_configs = config_pattern.findall(message.text)
                        all_configs.update(found_configs)
            except Exception as e:
                print(f"❌ خطا در خواندن پیام‌های کانال {channel}: {e}")

    print(f"\n✅ استخراج تمام شد. تعداد کل کانفیگ‌های پیدا شده: {len(all_configs)}")
    if not all_configs:
        return
        
    print("\n⏳ شروع تست کانفیگ‌ها...")
    
    tasks = [test_config(config) for config in all_configs]
    results = await asyncio.gather(*tasks)
    working_configs = [config for config, is_working in zip(all_configs, results) if is_working]
    
    print(f"\n✅ تست تمام شد. تعداد کانفیگ‌های سالم: {len(working_configs)}")

    if working_configs:
        subscription_content = "\n".join(working_configs)
        subscription_base64 = base64.b64encode(subscription_content.encode('utf-8')).decode('utf-8')
        with open(OUTPUT_FILE, "w") as f:
            f.write(subscription_base64)
        print(f"\n🚀 لینک سابسکریپشن با موفقیت در فایل '{OUTPUT_FILE}' ایجاد شد.")
    else:
        print("هیچ کانفیگ سالمی یافت نشد.")

if __name__ == "__main__":
    if not API_ID or not API_HASH:
        print("❌ خطا: لطفاً مقادیر API_ID و API_HASH را در فایل .env تنظیم کنید.")
    elif not SESSION_STRING:
        print("⚠️ هشدار: SESSION_STRING یافت نشد. برای ساخت آن، برنامه از شما مشخصات اکانت را خواهد پرسید.")
        with TelegramClient(StringSession(), int(API_ID), API_HASH) as client:
            session_str = client.session.save()
            print("\n✅ Session String شما ایجاد شد. آن را کپی کرده و در فایل .env و GitHub Secrets قرار دهید:")
            print("-" * 50)
            print(session_str)
            print("-" * 50)
    else:
        asyncio.run(main())