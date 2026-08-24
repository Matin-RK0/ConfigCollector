import os
import re
import io
import shutil
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
MAX_CONFIGS_IN_SUBSCRIPTION = 100  # حداکثر تعداد کانفیگ فایل نهایی
MAX_MEDIA_FILE_SIZE = 8 * 1024 * 1024  # حداکثر حجم فایل ضمیمه برای بررسی (۸ مگابایت)
TESSERACT_BIN = shutil.which("tesseract")  # برای خواندن کانفیگ داخل عکس (اختیاری)

# --- الگوهای استخراج ---
# Regex برای پیدا کردن لینک کانفیگ از همه پروتکل‌های رایج
config_pattern = re.compile(
    r'\b(?:vless|vmess|trojan|ssr|ss|hysteria2|hysteria|hy2|tuic|juicity|naive\+https?|wireguard)'
    r'://[^\s<>"\'`\u200b-\u200f\u202a-\u202e\u2060\ufeff]+'
)

# پروتکل‌هایی که هسته Xray پشتیبانی می‌کند و قابل تست هستند
XRAY_SUPPORTED_SCHEMES = {"vless", "vmess", "trojan", "ss"}

# کاراکترهای نامرئی که کانال‌ها برای دور زدن فیلتر داخل متن می‌گذارند
invisible_chars_re = re.compile(r'[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060\ufeff]')

# بلوک‌های بزرگ Base64 (مثلاً سابسکریپشن کامل که انکود شده داخل متن پست می‌شود)
base64_blob_pattern = re.compile(r'[A-Za-z0-9+/\-_]{24,}={0,2}')

# علائم نگارشی انتهای لینک که باید پاک شوند (مثل «vless://....» یا «vless://...,»)
TRAILING_JUNK = ".,;:!?)\\]}>'\"`»«…|*\\"

# فرمت‌های فایل ضمیمه که متنی هستند و قابل اسکن
TEXT_MIME_PREFIXES = ("text/", "application/json", "application/yaml", "application/x-yaml")
TEXT_FILE_EXTS = (".txt", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".log", ".list", ".sub")

_ocr_unavailable_warned = False


def get_config_scheme(uri: str) -> str:
    return uri.split("://", 1)[0].lower()


def b64_decode_padded(data: str):
    """دیکود Base64 با اصلاح خودکار padding و پشتیبانی از URL-safe."""
    data = ''.join(data.split()).replace('-', '+').replace('_', '/')
    if len(data) % 4:
        data += '=' * (4 - len(data) % 4)
    return base64.b64decode(data)


def clean_config_link(candidate: str) -> str:
    """کاراکترهای مخفی و علائم نگارشی اضافه انتهای لینک را حذف می‌کند."""
    link = invisible_chars_re.sub('', candidate).strip()
    while link and link[-1] in TRAILING_JUNK:
        link = link[:-1].rstrip()
    return link


def try_decode_base64_text(chunk: str):
    """یک بلوک Base64 را دیکود می‌کند؛ فقط اگر خروجی متنی خوانا باشد برگردانده می‌شود."""
    try:
        decoded = b64_decode_padded(chunk).decode('utf-8')
    except Exception:
        return None
    if not decoded:
        return None
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in '\r\n\t')
    if printable / len(decoded) < 0.95:
        return None
    return decoded


def extract_configs_from_text(raw_text, sink: set):
    """
    متن پیام را از سه حالت استخراج می‌کند:
    ۱) متن معمولی  ۲) لینکی که وسطش اینتر/خط جدید خورده  ۳) بلوک‌های Base64 انکود شده
    """
    if not raw_text:
        return
    text = invisible_chars_re.sub('', raw_text)

    sources = [
        text,
        text.replace('\r', '').replace('\n', ''),  # چسباندن خطوط برای لینک‌های چندخطی
    ]
    for blob in base64_blob_pattern.findall(text):
        decoded = try_decode_base64_text(blob)
        if decoded and '://' in decoded:
            sources.append(decoded)

    for source in sources:
        for match in config_pattern.findall(source):
            link = clean_config_link(match)
            if len(link) > 10:
                sink.add(link)


def extract_configs_from_buttons(message, sink: set):
    """کانفیگ‌هایی که داخل دکمه‌های شیشه‌ای (Inline/Reply Keyboard) قرار دارند را استخراج می‌کند."""
    markup = getattr(message, 'reply_markup', None)
    if not markup:
        return
    rows = getattr(markup, 'rows', None)
    if not rows:
        return
    for row in rows:
        for button in getattr(row, 'buttons', None) or []:
            for value in (getattr(button, 'url', None),
                          getattr(button, 'text', None),
                          getattr(button, 'query', None)):
                if value and '://' in str(value):
                    extract_configs_from_text(str(value), sink)


async def extract_configs_from_image(image_bytes: bytes, sink: set):
    """با OCR متن داخل تصویر (اسکرین‌شات کانفیگ) را می‌خواند؛ در نبود Tesseract رد می‌شود."""
    global _ocr_unavailable_warned
    if not TESSERACT_BIN:
        if not _ocr_unavailable_warned:
            print("⚠️ Tesseract نصب نیست؛ تصاویر بررسی نشدند (برای OCR آن را نصب کنید).")
            _ocr_unavailable_warned = True
        return
    try:
        from PIL import Image
        import pytesseract
    except ImportError:
        if not _ocr_unavailable_warned:
            print("⚠️ کتابخانه‌های Pillow/pytesseract نصب نیستند؛ تصاویر بررسی نشدند.")
            _ocr_unavailable_warned = True
        return
    try:
        image = Image.open(io.BytesIO(image_bytes))
        loop = asyncio.get_event_loop()
        text = await loop.run_in_executor(None, pytesseract.image_to_string, image)
        extract_configs_from_text(text, sink)
    except Exception as e:
        print(f"[!] خطا در OCR تصویر: {e}")


async def extract_configs_from_media(message, sink: set):
    """فایل‌های ضمیمه متنی (.txt و مشابه) و تصاویر (با OCR) را بررسی می‌کند."""
    document = message.document
    if document and (document.size or 0) <= MAX_MEDIA_FILE_SIZE:
        mime = document.mime_type or ""
        filename = ""
        for attr in document.attributes:
            filename = getattr(attr, 'file_name', '') or filename
        lower_name = filename.lower()

        if mime.startswith('image/'):
            data = await message.download_media(file=bytes)
            if data:
                await extract_configs_from_image(data, sink)
        elif any(mime.startswith(p) for p in TEXT_MIME_PREFIXES) or lower_name.endswith(TEXT_FILE_EXTS):
            data = await message.download_media(file=bytes)
            if data:
                extract_configs_from_text(data.decode('utf-8', errors='ignore'), sink)
                print(f"[*] فایل ضمیمه '{filename or 'بدون‌نام'}' اسکن شد.")
    elif message.photo:
        data = await message.download_media(file=bytes)
        if data:
            await extract_configs_from_image(data, sink)


def parse_ss_uri(uri: str):
    """لینک Shadowsocks را (هم فرمت legacy کاملاً انکود شده و هم SIP002) پارس می‌کند."""
    try:
        main_part = uri[5:].split('#', 1)[0]
        main_part = main_part.split('?', 1)[0]

        if '@' in main_part:
            userinfo, hostport = main_part.rsplit('@', 1)
            userinfo = unquote(userinfo)
            if ':' not in userinfo:
                decoded = try_decode_base64_text(userinfo) or ''
                if ':' not in decoded:
                    return None
                userinfo = decoded
        else:
            decoded = b64_decode_padded(main_part).decode('utf-8', errors='ignore')
            if '@' not in decoded:
                return None
            userinfo, hostport = decoded.rsplit('@', 1)

        method, password = userinfo.split(':', 1)
        host, port = hostport.rsplit(':', 1)
        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": host.strip('[]'),
                    "port": int(port),
                    "method": method,
                    "password": password
                }]
            },
            "streamSettings": {"network": "tcp", "security": ""}
        }
    except Exception as e:
        print(f"[!] خطا در پارس کردن کانفیگ: {uri[:40]}... | خطا: {e}")
        return None


def parse_config_to_xray_json(uri: str):
    """
    لینک کانفیگ را به فرمت JSON قابل فهم برای Xray تبدیل می‌کند.
    این نسخه بازنویسی شده و بسیار مقاوم‌تر است.
    """
    try:
        if uri.startswith("vmess://"):
            decoded = json.loads(b64_decode_padded(uri[8:]).decode())
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

        if uri.startswith("ss://"):
            return parse_ss_uri(uri)

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
                    # ۱) متن پیام یا کپشن مدیا (متن ساده، لینک چندخطی و بلوک Base64)
                    extract_configs_from_text(message.text, newly_fetched_configs)
                    # ۲) دکمه‌های شیشه‌ای زیر پیام
                    extract_configs_from_buttons(message, newly_fetched_configs)
                    # ۳) فایل ضمیمه متنی یا تصویر (با OCR)
                    await extract_configs_from_media(message, newly_fetched_configs)
            except Exception as e:
                print(f"❌ خطا در خواندن کانال {channel}: {e}")
    
    # جدا کردن کانفیگ‌ها: آن‌ها که Xray می‌تواند تست کند و آن‌ها که خارج از توان Xray هستند
    all_found_configs = existing_configs.union(newly_fetched_configs)
    testable_configs = sorted(c for c in all_found_configs if get_config_scheme(c) in XRAY_SUPPORTED_SCHEMES)
    untestable_configs = sorted(c for c in all_found_configs if get_config_scheme(c) not in XRAY_SUPPORTED_SCHEMES)

    print(f"\n✅ استخراج تمام شد. مجموعاً {len(all_found_configs)} کانفیگ پیدا شد.")
    print(f"   ↳ {len(testable_configs)} عدد قابل تست با Xray | {len(untestable_configs)} عدد خارج از توان Xray (بدون تست اضافه می‌شوند)")

    if not all_found_configs:
        print("هیچ کانفیگی برای تست وجود ندارد.")
        return

    successful_results = []
    if testable_configs:
        print(f"\n⏳ شروع تست اتصال واقعی (حداکثر {MAX_CONCURRENT_TESTS} تست همزمان)...")
        
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_TESTS)
        tasks = []
        base_port = 10810
        for i, config in enumerate(testable_configs):
            tasks.append(worker(config, base_port + i, semaphore))

        results = await asyncio.gather(*tasks)
        
        # نتایج موفق را فیلتر کرده و بر اساس تاخیر (کم به زیاد) مرتب می‌کند
        successful_results = sorted([res for res in results if res is not None])
        
        print(f"\n✅ تست تمام شد. {len(successful_results)} کانفیگ سالم پیدا شد.")
    
    # کانفیگ‌های تست‌شده و سالم (مرتب بر اساس تاخیر) + کانفیگ‌های غیرقابل تست (hysteria، tuic و...)
    merged_configs = list(dict.fromkeys([res[1] for res in successful_results] + untestable_configs))
    final_configs = merged_configs[:MAX_CONFIGS_IN_SUBSCRIPTION]
    
    print(f"✅ {len(final_configs)} کانفیگ برای فایل نهایی انتخاب شد.")


    if final_configs:
        subscription_content = "\n".join(final_configs)
        subscription_base64 = base64.b64encode(subscription_content.encode('utf-8')).decode('utf-8')
        with open(OUTPUT_FILE, "w") as f: f.write(subscription_base64)
        print(f"\n🚀 لینک سابسکریپشن با موفقیت با {len(final_configs)} کانفیگ آپدیت شد.")
    else:
        with open(OUTPUT_FILE, "w") as f: f.write("")
        print("هیچ کانفیگ سالمی یافت نشد. فایل سابسکریپشن خالی شد.")

if __name__ == "__main__":
    if not all([API_ID, API_HASH, SESSION_STRING]):
        print("❌ متغیرهای محیطی API_ID, API_HASH, یا SESSION_STRING تنظیم نشده‌اند.")
    else:
        asyncio.run(main())
