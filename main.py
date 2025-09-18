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
import aiohttp
from aiohttp_socks import ProxyConnector

# --- تنظیمات اولیه ---
API_ID = os.environ.get("API_ID")
API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")
CHANNEL_USERNAMES = [channel.strip() for channel in os.environ.get("CHANNEL_USERNAMES", "").split(',')]
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")
MESSAGE_LIMIT_PER_CHANNEL = 75
OUTPUT_FILE = "subscription.txt"
XRAY_PATH = "./xray"
CONFIG_TEST_TIMEOUT = 15  # افزایش مهلت زمانی
MAX_CONCURRENT_TESTS = 10 

# Regex برای پیدا کردن کل لینک کانفیگ
config_pattern = re.compile(r'\b(?:vless|vmess|trojan)://[^\s<>"\'`]+')

def parse_config_to_xray_json(uri: str):
    """
    لینک کانفیگ را به فرمت JSON قابل فهم برای Xray تبدیل می‌کند.
    این نسخه بازنویسی شده و بسیار مقاوم‌تر است.
    """
    try:
        if uri.startswith("vmess://"):
            decoded = json.loads(base64.b64decode(uri[8:]).decode())
            outbound = {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": decoded.get("add"),
                        "port": int(decoded.get("port")),
                        "users": [{"id": decoded.get("id"), "alterId": int(decoded.get("aid")), "security": decoded.get("scy", "auto")}]
                    }]
                },
                "streamSettings": {
                    "network": decoded.get("net"),
                    "security": decoded.get("tls"),
                    "tlsSettings": {"serverName": decoded.get("sni")} if decoded.get("tls") == "tls" else None,
                    "wsSettings": {"path": decoded.get("path"), "headers": {"Host": decoded.get("host")}} if decoded.get("net") == "ws" else None,
                }
            }
            return outbound

        parsed_uri = urlparse(uri)
        params = parse_qs(parsed_uri.query)
        
        outbound = {
            "protocol": parsed_uri.scheme,
            "settings": {},

            "streamSettings": {
                "network": params.get("type", ["tcp"])[0],
                "security": params.get("security", ["none"])[0],
                "tlsSettings": {"serverName": params.get("sni", [params.get("host", [None])[0]])[0]},
                "realitySettings": {"publicKey": params.get("pbk", [None])[0], "shortId": params.get("sid", [None])[0]},
                "wsSettings": {"path": params.get("path", ["/"])[0], "headers": {"Host": params.get("host", [None])[0]}},
                "grpcSettings": {"serviceName": params.get("serviceName", [None])[0]},
            }
        }

        if parsed_uri.scheme == "vless":
            outbound["settings"]["vnext"] = [{
                "address": parsed_uri.hostname,
                "port": parsed_uri.port,
                "users": [{"id": parsed_uri.username, "flow": params.get("flow", [""])[0], "encryption": params.get("encryption", ["none"])[0]}]
            }]
        elif parsed_uri.scheme == "trojan":
            outbound["settings"]["servers"] = [{
                "address": parsed_uri.hostname,
                "port": parsed_uri.port,
                "password": parsed_uri.username
            }]

        # --- پاک‌سازی و بهینه‌سازی ---
        stream_settings = outbound["streamSettings"]
        if stream_settings["security"] != "tls": del stream_settings["tlsSettings"]
        if stream_settings["security"] != "reality": del stream_settings["realitySettings"]
        if stream_settings["network"] != "ws": del stream_settings["wsSettings"]
        if stream_settings["network"] != "grpc": del stream_settings["grpcSettings"]
        if stream_settings["security"] == "none": stream_settings["security"] = ""

        return outbound

    except Exception as e:
        print(f"[!] خطا در پارس کردن کانفیگ: {uri[:40]}... | خطا: {e}")
        return None


async def test_config_with_xray(config_url: str, port: int):
    """یک اتصال واقعی از طریق کانفیگ روی یک پورت مشخص برقرار کرده و تاخیر آن را اندازه‌گیری می‌کند."""
    outbound_config = parse_config_to_xray_json(config_url)
    if not outbound_config: return None
    
    outbound_config["tag"] = "proxy"
    test_config_json = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [outbound_config]
    }
    
    temp_filename = f"temp_config_{uuid.uuid4()}.json"
    with open(temp_filename, 'w') as f: json.dump(test_config_json, f)

    process = None
    try:
        config_name = unquote(urlparse(config_url).fragment or 'N/A')
        print(f"[*] تست اتصال واقعی '{config_name}'...")

        process = await asyncio.create_subprocess_exec(
            XRAY_PATH, '-c', temp_filename,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        await asyncio.sleep(3) # افزایش زمان برای بالا آمدن Xray

        if process.returncode is not None:
              error_output = (await process.stderr.read()).decode('utf-8').strip()
              print(f"[-] ناموفق. Xray هنگام اجرا با خطا مواجه شد. لاگ: {error_output}")
              # در صورت خطا، محتوای کانفیگ مشکل‌ساز را چاپ کن
              # print(f"کانفیگ مشکل‌ساز:\n{json.dumps(test_config_json, indent=2)}")
              return None

        connector = ProxyConnector.from_url(f'socks5://127.0.0.1:{port}')
        async with aiohttp.ClientSession(connector=connector) as session:
            start_time = asyncio.get_event_loop().time()
            async with session.head("http://www.gstatic.com/generate_204", timeout=CONFIG_TEST_TIMEOUT) as response:
                end_time = asyncio.get_event_loop().time()
                if response.status == 204:
                    latency = int((end_time - start_time) * 1000)
                    print(f"[+] موفقیت‌آمیز ({latency} ms) - {config_name}")
                    return (latency, config_url)
                else:
                    print(f"[-] ناموفق (کد وضعیت: {response.status}) - {config_name}")
                    return None
    except Exception as e:
        print(f"[-] ناموفق (خطا: {type(e).__name__}) - {config_name}")
        return None
    finally:
        if process and process.returncode is None:
            process.terminate()
            await process.wait()
        if os.path.exists(temp_filename): os.remove(temp_filename)

async def worker(config, port, semaphore):
    """یک worker برای اجرای تست با محدودیت همزمانی."""
    async with semaphore:
        return await test_config_with_xray(config, port)

async def main():
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

    all_configs_to_test = list(existing_configs.union(newly_fetched_configs))
    print(f"✅ تعداد کل کانفیگ‌ها برای تست (جدید و قدیم): {len(all_configs_to_test)}")

    if not all_configs_to_test:
        print("هیچ کانفیگی برای تست وجود ندارد.")
        return
        
    print(f"\n⏳ شروع تست اتصال واقعی (حداکثر {MAX_CONCURRENT_TESTS} تست همزمان)...")
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TESTS)
    tasks = []
    base_port = 10810
    for i, config in enumerate(all_configs_to_test):
        tasks.append(worker(config, base_port + i, semaphore))

    results = await asyncio.gather(*tasks)
    
    # نتایج موفق را فیلتر کرده و بر اساس تاخیر (کم به زیاد) مرتب می‌کند
    successful_results = sorted([res for res in results if res is not None])
    
    print(f"\n✅ تست تمام شد. {len(successful_results)} کانفیگ سالم پیدا شد.")

    # ----> تغییر اصلی در اینجا اعمال شده است <----
    # 50 کانفیگ برتر (با کمترین تاخیر) را انتخاب می‌کند
    top_50_configs = successful_results[:100]
    
    # فقط لینک کانفیگ‌ها را استخراج می‌کند
    working_configs = [res[1] for res in top_50_configs]
    
    print(f"✅ {len(working_configs)} کانفیگ برتر برای فایل نهایی انتخاب شد.")


    if working_configs:
        subscription_content = "\n".join(working_configs)
        subscription_base64 = base64.b64encode(subscription_content.encode('utf-8')).decode('utf-8')
        with open(OUTPUT_FILE, "w") as f: f.write(subscription_base64)
        print(f"\n🚀 لینک سابسکریپشن با موفقیت با {len(working_configs)} کانفیگ آپدیت شد.")
    else:
        with open(OUTPUT_FILE, "w") as f: f.write("")
        print("هیچ کانفیگ سالمی یافت نشد. فایل سابسکریپشن خالی شد.")

if __name__ == "__main__":
    if not all([API_ID, API_HASH, SESSION_STRING]):
        print("❌ متغیرهای محیطی API_ID, API_HASH, یا SESSION_STRING تنظیم نشده‌اند.")
    else:
        asyncio.run(main())