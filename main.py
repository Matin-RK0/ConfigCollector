import os
import re
import asyncio
import base64
import json
import subprocess
import requests
import uuid
from urllib.parse import urlparse, parse_qs, unquote
from telethon.sync import TelegramClient
from telethon.sessions import StringSession

# --- تنظیمات اولیه ---
# این بخش‌ها از متغیرهای محیطی خوانده می‌شوند
API_ID = os.environ.get("API_ID")
API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")
CHANNEL_USERNAMES = [channel.strip() for channel in os.environ.get("CHANNEL_USERNAMES", "").split(',')]
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")
MESSAGE_LIMIT_PER_CHANNEL = 75  # کمی بیشتر جستجو می‌کنیم
OUTPUT_FILE = "subscription.txt"
XRAY_PATH = "./xray"  # مسیر فایل اجرایی Xray
CONFIG_TEST_TIMEOUT = 15 # ثانیه

# Regex برای پیدا کردن کل لینک کانفیگ
config_pattern = re.compile(r'\b(?:vless|vmess|trojan)://[^\s<>"\'`]+')

def parse_config_to_xray_json(config_url: str):
    """
    لینک کانفیگ را به یک دیکشنری JSON برای outbound در Xray تبدیل می‌کند.
    این تابع از ساختار پیچیده کانفیگ‌ها پشتیبانی می‌کند.
    """
    try:
        if config_url.startswith("vmess://"):
            # اطمینان از اینکه طول رشته برای base64 معتبر است
            b64_part = config_url[8:]
            b64_part += '=' * (-len(b64_part) % 4)
            decoded_part = base64.b64decode(b64_part).decode('utf-8')
            vmess_data = json.loads(decoded_part)
            return {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": vmess_data.get("add"),
                        "port": int(vmess_data.get("port")),
                        "users": [{"id": vmess_data.get("id"), "alterId": int(vmess_data.get("aid")), "security": vmess_data.get("scy", "auto")}]
                    }]
                },
                "streamSettings": {
                    "network": vmess_data.get("net"),
                    "security": vmess_data.get("tls"),
                    "wsSettings": {"path": vmess_data.get("path"), "headers": {"Host": vmess_data.get("host")}} if vmess_data.get("net") == "ws" else None
                },
                "tag": "proxy"
            }

        parsed = urlparse(config_url)
        params = parse_qs(parsed.query)
        
        config = {
            "protocol": parsed.scheme,
            "settings": {},
            "streamSettings": {
                "network": params.get("type", [None])[0],
                "security": params.get("security", ["none"])[0],
                "tlsSettings": {"serverName": params.get("sni", [None])[0] or params.get("host", [None])[0]},
                "wsSettings": {"path": params.get("path", ["/"])[0], "headers": {"Host": params.get("host", [None])[0]}} if params.get("type") == ["ws"] else None,
                "grpcSettings": {"serviceName": params.get("serviceName", [None])[0]} if params.get("type") == ["grpc"] else None
            },
            "tag": "proxy"
        }

        if parsed.scheme in ["vless", "trojan"]:
            user_info = parsed.username
            if parsed.scheme == "vless":
                config["settings"]["vnext"] = [{"address": parsed.hostname, "port": parsed.port, "users": [{"id": user_info, "flow": params.get("flow", [None])[0]}]}]
            else: # trojan
                config["settings"]["servers"] = [{"address": parsed.hostname, "port": parsed.port, "password": user_info}]
        
        # پاک‌سازی مقادیر None
        if config["streamSettings"]["security"] == "none":
            config["streamSettings"]["security"] = ""
        if "tlsSettings" in config["streamSettings"] and not config["streamSettings"]["tlsSettings"]["serverName"]:
            del config["streamSettings"]["tlsSettings"]

        return config
    except Exception as e:
        print(f"[!] خطا در پارس کردن کانفیگ: {config_url[:30]}... | خطا: {e}")
        return None

async def test_config_with_xray(config_url: str) -> bool:
    """
    یک کانفیگ را با استفاده از Xray -test تست می‌کند (تست تاخیر واقعی).
    """
    outbound_config = parse_config_to_xray_json(config_url)
    if not outbound_config:
        return False

    # ساخت فایل کانفیگ موقت برای تست
    test_config_json = {
        "inbounds": [],
        "outbounds": [outbound_config],
        "routing": {
            "rules": [{"type": "field", "outboundTag": "proxy", "domain": ["google.com"]}]
        }
    }
    
    # استفاده از یک نام فایل منحصر به فرد برای جلوگیری از تداخل در اجرای همزمان
    temp_filename = f"temp_config_{uuid.uuid4()}.json"
    with open(temp_filename, 'w') as f:
        json.dump(test_config_json, f)

    try:
        print(f"[*] تست تاخیر واقعی: {unquote(urlparse(config_url).fragment or 'N/A')}...")
        
        # اجرای Xray برای تست کانفیگ با یک مهلت زمانی مشخص
        process = await asyncio.create_subprocess_exec(
            XRAY_PATH, '-test', temp_filename,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=CONFIG_TEST_TIMEOUT)
        
        output = stdout.decode('utf-8')
        if "Success" in output:
            delay = re.search(r'\((\d+)\s*ms\)', output)
            print(f"[+] موفقیت‌آمیز ({delay.group(1) if delay else 'N/A'} ms)")
            return True
        else:
            print(f"[-] ناموفق")
            return False
    except asyncio.TimeoutError:
        print("[-] ناموفق (تایم‌اوت)")
        return False
    except Exception as e:
        print(f"[-] ناموفق (خطای اجرایی: {e})")
        return False
    finally:
        # پاک کردن فایل کانفیگ موقت
        if os.path.exists(temp_filename):
            os.remove(temp_filename)

async def main():
    # بخش ۱: خواندن کانفیگ‌های قدیمی
    existing_configs = set()
    if GITHUB_REPOSITORY:
        repo_url = f"https://raw.githubusercontent.com/{GITHUB_REPOSITORY}/main/{OUTPUT_FILE}"
        try:
            print(f"در حال خواندن کانفیگ‌های قدیمی از: {repo_url}")
            response = requests.get(repo_url, timeout=10)
            if response.status_code == 200 and response.text:
                decoded_content = base64.b64decode(response.text).decode('utf-8')
                existing_configs.update(line for line in decoded_content.splitlines() if line.strip())
                print(f"✅ {len(existing_configs)} کانفیگ قبلی بارگیری شد.")
        except Exception as e:
            print(f"⚠️ خواندن کانفیگ‌های قبلی ممکن نبود: {e}")

    # بخش ۲: استخراج کانفیگ‌های جدید
    newly_fetched_configs = set()
    async with TelegramClient(StringSession(SESSION_STRING), API_ID, API_HASH) as client:
        print("\n✅ کلاینت تلگرام متصل شد.")
        for channel in CHANNEL_USERNAMES:
            print(f"🔎 در حال بررسی کانال: {channel}")
            try:
                async for message in client.iter_messages(channel, limit=MESSAGE_LIMIT_PER_CHANNEL):
                    if message.text:
                        newly_fetched_configs.update(config.strip() for config in config_pattern.findall(message.text))
            except Exception as e:
                print(f"❌ خطا در خواندن کانال {channel}: {e}")
    
    print(f"\n✅ استخراج تمام شد. {len(newly_fetched_configs)} کانفیگ جدید پیدا شد.")

    # بخش ۳: ترکیب و تست همه کانفیگ‌ها
    all_configs_to_test = existing_configs.union(newly_fetched_configs)
    print(f"✅ تعداد کل کانفیگ‌ها برای تست (جدید و قدیم): {len(all_configs_to_test)}")

    if not all_configs_to_test:
        print("هیچ کانفیگی برای تست وجود ندارد.")
        return
        
    print("\n⏳ شروع تست تاخیر واقعی تمام کانفیگ‌ها...")
    tasks = [test_config_with_xray(config) for config in all_configs_to_test]
    results = await asyncio.gather(*tasks)
    working_configs = [config for config, is_working in zip(all_configs_to_test, results) if is_working]
    
    # مرتب‌سازی بر اساس نام برای داشتن خروجی یکسان
    working_configs.sort()
    
    print(f"\n✅ تست تمام شد. تعداد نهایی کانفیگ‌های سالم: {len(working_configs)}")

    # بخش ۴: ذخیره کردن لیست نهایی
    if working_configs:
        subscription_content = "\n".join(working_configs)
        subscription_base64 = base64.b64encode(subscription_content.encode('utf-8')).decode('utf-8')
        with open(OUTPUT_FILE, "w") as f: f.write(subscription_base64)
        print(f"\n🚀 لینک سابسکریپشن با موفقیت آپدیت شد.")
    else:
        with open(OUTPUT_FILE, "w") as f: f.write("")
        print("هیچ کانفیگ سالمی یافت نشد. فایل سابسکریپشن خالی شد.")

if __name__ == "__main__":
    if not all([API_ID, API_HASH, SESSION_STRING]):
        print("❌ متغیرهای محیطی API_ID, API_HASH, یا SESSION_STRING تنظیم نشده‌اند.")
    else:
        asyncio.run(main())
