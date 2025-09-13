import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from itertools import cycle
import multiprocessing
import os
from pathlib import Path
import platform
import re
import sys
import threading
import webbrowser
import winsound
import time
import json
import random
import string
import logging
import ctypes
import aiofiles
from camoufox import AsyncCamoufox
import requests
import httpx
import tls_client
from bs4 import BeautifulSoup
from colorama import Fore, Style
from pystyle import Center
from rich.console import Console
from rich.text import Text
from rich.spinner import Spinner
from rich.live import Live
from rich.align import Align
import warnings
import warnings
import asyncio
from logmagix import LogLevel
import imaplib
import email as em_parser
from email.header import decode_header
import ssl
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def anti_debug():
    is_debugger_present = ctypes.windll.kernel32.IsDebuggerPresent() != 0
    check_remote_debugger = ctypes.windll.kernel32.CheckRemoteDebuggerPresent
    debugger_found = ctypes.c_bool()
    check_remote_debugger(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(debugger_found))

    if is_debugger_present or debugger_found.value:
        print("Debugger detected. Exiting...")
        sys.exit()

LOCK = threading.Lock()

console = Console()
config_path = Path("input/config.json")

if not config_path.exists():
    raise FileNotFoundError(f"❌ config.json not found in input folder: {config_path}")

with open(config_path, "r", encoding="utf-8") as f:
    config = json.load(f)
def play_beep():
    if platform.system() == "Windows":
        winsound.Beep(1000, 500)
    else:
        print('\a')
        sys.stdout.flush()

def gradient_text(text, start_rgb, end_rgb):
    gradient = []
    steps = len(text)
    for i, char in enumerate(text):
        if char == " ":
            gradient.append(char)
            continue
        r = int(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * i / steps)
        g = int(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * i / steps)
        b = int(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * i / steps)
        gradient.append(f"\033[38;2;{r};{g};{b}m{char}")
    return ''.join(gradient) + "\033[0m"

server = config.get("ip_server")
password = config.get("ip_password")
username = config.get("ip_username")
DOMAIN = config.get("domain")
ADMIN_EMAIL = ""
ADMIN_PASSWORD = ""
MAILBOX_API = ""

banner_lines = [
"███████╗██████╗  █████╗ ██████╗ ██╗  ██╗██████╗  ██████╗  ██████╗ ███████╗████████╗███████╗",
"██╔════╝██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔════╝",
"███████╗██████╔╝███████║██████╔╝█████╔╝ ██████╔╝██║   ██║██║   ██║███████╗   ██║   ███████╗",
"╚════██║██╔═══╝ ██╔══██║██╔══██╗██╔═██╗ ██╔══██╗██║   ██║██║   ██║╚════██║   ██║   ╚════██║",
"███████║██║     ██║  ██║██║  ██║██║  ██╗██████╔╝╚██████╔╝╚██████╔╝███████║   ██║   ███████║",
"╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝"
]

def print_gradient_text(text, start_color=(255, 255, 0), end_color=(255, 255, 0)):
    lines = text.split('\n')
    total_lines = len(lines)
    for i, line in enumerate(lines):
        if not line.strip():
            print(line)
            continue
        factor = i / max(1, total_lines - 1)
        r = int(start_color[0] + (end_color[0] - start_color[0]) * factor)
        g = int(start_color[1] + (end_color[1] - start_color[1]) * factor)
        b = int(start_color[2] + (end_color[2] - start_color[2]) * factor)
        color_code = f"\033[38;2;{r};{g};{b}m"
        print(f"{color_code}{line}")

print_gradient_text(
    Center.XCenter('\n'.join(banner_lines)),
    start_color=(255, 255, 0),   
    end_color=(255, 255, 0)      
)

class ColoredFormatter(logging.Formatter):
    LEVEL_COLORS = {
        "info": "[dim cyan]",
        "INFO": "",
        "WARNING": "",
        "ERROR": "",
        "CRITICAL": "[bold red]",
    }

    def format(self, record):
        levelname = record.levelname
        color = self.LEVEL_COLORS.get(levelname, "")
        reset = "[/]" if color else ""
        record.levelname = f"{color}{levelname}{reset}"
        return super().format(record)

class Logger:
    def __init__(self, level: LogLevel = LogLevel.DEBUG):
        self.level = level
        self.prefix = "\033[38;5;82m[SparkBoosts]\033[0m "
        self.WHITE = "\u001b[37m"
        self.MAGENTA = "\033[38;5;97m"
        self.BRIGHT_MAGENTA = "\033[38;2;157;38;255m"
        self.LIGHT_CORAL = "\033[38;5;210m"
        self.RED = "\033[38;5;196m"
        self.GREEN = "\033[38;5;40m"
        self.YELLOW = "\033[38;5;220m"
        self.BLUE = "\033[38;5;21m"
        self.PINK = "\033[38;5;176m"
        self.CYAN = "\033[96m"
    def get_time(self):
        return datetime.now().strftime("%H:%M:%S")
    def _should_log(self, message_level: LogLevel) -> bool:
        return message_level.value >= self.level.value
    def _write(self, level_color, level_tag, message):
        print(f"{self.prefix}{level_color}{message}")
    def info(self, message: str):
        if self._should_log(LogLevel.INFO):
            self._write(self.CYAN, "!", message)
    def success(self, message: str):
        if self._should_log(LogLevel.SUCCESS):
            self._write(self.GREEN, "Success", message)
    def warning(self, message: str):
        if self._should_log(LogLevel.WARNING):
            self._write(self.YELLOW, "Warning", message)
    def error(self, message: str):
        if self._should_log(LogLevel.FAILURE):
            self._write(self.RED, "Error", message)
    def debug(self, message: str):
        if self._should_log(LogLevel.DEBUG):
            self._write(self.BLUE, "DEBUG", message)
    def failure(self, message: str):
        if self._should_log(LogLevel.FAILURE):
            self._write(self.RED, "Failure", message)
log = Logger()

def log_cli(message, icon=":green_circle:"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    console.print(f"[bold cyan][{timestamp}] {icon} {message}")

threads = config.get("Threads")

SUPABASE_URL = ""
SUPABASE_API_KEY = ""
HEADERS = {
    "apikey": SUPABASE_API_KEY,
    "Authorization": f"Bearer {SUPABASE_API_KEY}",
    "Content-Type": "application/json"
}

LICENSE_FILE = "license.key"

def get_hwid():
    return hashlib.sha256(os.getenv("COMPUTERNAME", "unknown").encode()).hexdigest()

async def fetch_keys():
    async with httpx.AsyncClient() as client:
        try:
            res = await client.get(f"{SUPABASE_URL}/rest/v1/key", headers=HEADERS)
            res.raise_for_status()
            keys = res.json()
            return {item['key']: item for item in keys}
        except Exception as e:
            log.error(f"Error fetching keys: {e}")
            return {}

async def get_ip():
    async with httpx.AsyncClient() as client:
        try:
            res = await client.get("https://api.ipify.org?format=json", timeout=5)
            return res.json().get("ip", "unknown")
        except Exception:
            return "unknown"

async def validate_key(input_key):
    key = await fetch_keys()
    hwid = get_hwid()

    if input_key in key:
        key_data = key[input_key]
        expiry_time = key_data.get("expiry")
        associated_hwid = key_data.get("hwid")

        try:
            expiry_date_ist = datetime.strptime(expiry_time, '%Y-%m-%dT%H:%M:%S')
            log.info(f"\033[95mKey expires on: {expiry_date_ist.strftime('%Y-%m-%d %H:%M:%S IST')}\033[0m")
        except (ValueError, TypeError):
            print("\033[91mInvalid expiry format in the database.\033[0m")
            return False

        if expiry_date_ist < datetime.now():
            print("\033[91mKey has expired.\033[0m")
            return False

        if associated_hwid and associated_hwid != hwid:
            print("\033[91mKey is associated with another HWID. Ask for a HWID reset.\033[0m")
            return False

        if not associated_hwid:
            IST = timezone(timedelta(hours=5, minutes=30))
            now_ist = datetime.now(IST)
            try:
                ip = await get_ip()
                ip_history = key_data.get("ip_history")
                ip_list = json.loads(ip_history) if ip_history else []
                if ip not in ip_list:
                    ip_list.append(ip)
                update_data = {
                    "hwid": hwid,
                    "ip": ip,
                    "last_login": now_ist.isoformat(),
                    "ip_count": len(ip_list),
                    "ip_history": json.dumps(ip_list)
                }
                async with httpx.AsyncClient() as client:
                    res = await client.patch(
                        f"{SUPABASE_URL}/rest/v1/key?key=eq.{input_key}",
                        headers=HEADERS,
                        data=json.dumps(update_data)
                    )
                    if res.status_code not in [200, 204]:
                        print(f"\033[91mFailed to bind HWID. {res.text}\033[0m")
            except Exception as e:
                print(f"\033[91mError updating HWID: {e}\033[0m")

        return True
    else:
        print("\033[91mInvalid key.\033[0m")
        return False

LICENSE_FILE = Path("input/license.key")

async def get_license_key():
    if LICENSE_FILE.exists():
        async with aiofiles.open(LICENSE_FILE, "r") as f:
            license_key = (await f.read()).strip()
            if license_key:

                return license_key

    license_key = input(
        f"{Fore.LIGHTMAGENTA_EX}[SparkBoosts] {Fore.RESET}{Fore.LIGHTYELLOW_EX}LICENSE{Fore.RESET} : "
    ).strip()

    LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)

    async with aiofiles.open(LICENSE_FILE, "w") as f:
        await f.write(license_key)

    return license_key

def generate_username(length=10):
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choices(chars, k=length))

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choices(chars, k=length))

def create_email_account():
    username = generate_username()
    password = generate_password()
    email = f"{username}@{DOMAIN}"

    url = ""
    data = {
        "email": email,
        "password": password,
        "privileges": "",   
        "quota": "0"        
    }

    try:
        log.debug(f"Creating {email} at {url} ...")
        response = requests.post(url, data=data, auth=(ADMIN_EMAIL, ADMIN_PASSWORD), verify=False)

        if response.status_code == 200:
            log.success(f"✅ Created email {email}")
            return email, password
        else:
            log.error(f"❌ Failed to create {email}: {response.status_code} {response.text}")
            return None, None

    except Exception as e:
        log.error(f"❌ Error creating {email}: {e}")
        return None, None

async def log_ev_to_supabase(ev, used_key):
    payload = {
        "ev": ev,
        "key": used_key
    }
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(
                f"{SUPABASE_URL}/rest/v1/evs",
                headers=HEADERS,
                data=json.dumps(payload)
            )
            return res.status_code in [200, 201]
    except Exception as e:
        return False

def timestamp():
    return f"{Fore.LIGHTBLACK_EX}[{datetime.now():%H:%M:%S %d-%m-%Y}]"

async def random_sleep(base=2, variation=3):
    await asyncio.sleep(base + random.uniform(0, variation))

def mask_token(token):
    return token[:20] + ".***.*****"

class Checker:

    def __init__(self, proxy=None):

        self.session = tls_client.Session(
            client_identifier="chrome_126",
            random_tls_extension_order=True
        )

        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        }

        self.session.proxies = {
            "http": "",
            "https": ""

        }

    def check_single_token(self, token: str):
        token = token.strip()
        masked_token = mask_token(token)
        self.session.headers["Authorization"] = token

        try:
            r = self.session.get("https://discord.com/api/v9/users/@me/guilds")

            if r.status_code == 200:
                log.info(f"✔ [green]VALID[/green]        {masked_token}")
                return "VALID"
            elif r.status_code == 403:
                log.warning(f"⚠ [yellow]LOCKED[/yellow]       {masked_token}")
                return "LOCKED"
            elif r.status_code == 401:
                log.error(f"✖ [red]INVALID[/red]      {masked_token}")
                return "INVALID"
            elif r.status_code == 429:
                log.warning(f"⏱ [magenta]RATE LIMITED[/magenta] {masked_token}")
                return "RATE LIMIT"
            else:
                log.info(f"❓ [cyan]UNKNOWN[/cyan]      {masked_token}")
                return "UNKNOWN"
        except Exception as e:
            log.failure(f"❓ [cyan]UNKNOWN[/cyan]      {masked_token} | Exception: {e}")

checker = Checker()
def check_token(token):
    with LOCK:
        return checker.check_single_token(token)

def poll_and_verify_email(email, password):
    host = ""
    port = 993

    context = ssl.create_default_context()

    try:
        with imaplib.IMAP4_SSL(host, port, ssl_context=context) as mail:
            mail.login(email, password)
            mail.select("inbox")

            log.info(f"\033[93mChecking inbox for mail= {email}...\033[0m")

            for _ in range(500):  
                status, messages = mail.search(None, 'UNSEEN')  
                if status != "OK":
                    time.sleep(1)
                    continue

                email_ids = messages[0].split()
                if not email_ids:
                    time.sleep(1)
                    continue

                for e_id in reversed(email_ids):  
                    res, msg_data = mail.fetch(e_id, "(RFC822)")
                    if res != "OK":
                        continue

                    raw_msg = msg_data[0][1]
                    msg = em_parser.message_from_bytes(raw_msg)

                    subject, encoding = decode_header(msg.get("Subject"))[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding or "utf-8", errors="ignore")

                    if "verify" not in subject.lower():
                        continue

                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            if content_type in ["text/plain", "text/html"]:
                                try:
                                    body = part.get_payload(decode=True).decode(errors="ignore")
                                except Exception:
                                    continue
                                break
                    else:
                        body = msg.get_payload(decode=True).decode(errors="ignore")

                    match = re.search(r'https://click\.discord\.com/[^\s"\']+', body)
                    if not match:
                        continue

                    link = match.group(0)

                    log.info("\033[93mFetching verification link...\033[0m")
                    webbrowser.open(link)

                    if proxy_setting != "enable":
                        log.warning("⏳ Waiting 90 seconds to avoid rate limit (no proxies)...")
                        time.sleep(90)
                    return True

                time.sleep(1)

    except Exception as e:
        log.error(f"❌ IMAP error for {email}: {e}")

    log.error("❌ Email verification failed or timed out.")
    return False

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

async def block_uselesss(page):
    async def block_useless(route, request):
        url = request.url.lower()
        if any(x in url for x in [
            "sentry", "google-analytics", "doubleclick", "tracking", "facebook", "cdn.jsdelivr.net/npm/@sentry"
        ]):
            await route.abort()
        else:
            await route.continue_()

    await page.route("**/*", block_useless)

async def fill_discord_register_form(display_name, username, inbox_id, inbox_token, input_key, proxy=None):
    log.info(f"\033[93mTemp mail: {inbox_id}\033[0m")
    try:
        async with AsyncCamoufox(
            headless=False,
            window=(900, 750),
            proxy=proxy,
            geoip=False,
            humanize=0.05,
            block_webrtc=True,
            i_know_what_im_doing=True,
            disable_coop=True
        ) as browser:
            context = await browser.new_context()
            page = await context.new_page()

            await page.add_style_tag(content="""
            * {
                transition: none !important;
                animation: none !important;
            }
            """)

            await page.goto("https://discord.com/register", wait_until="domcontentloaded", timeout=150000)

            await page.wait_for_selector('input[aria-label="Email"]', timeout=60000)
            await page.fill('input[aria-label="Email"]', inbox_id)
            await page.fill('input[aria-label="Display Name"]', display_name)
            await page.fill('input[aria-label="Username"]', username)
            await page.fill('input[aria-label="Password"]', inbox_token)
            await asyncio.sleep(0.6)

            await page.click('div[aria-label="Month"]')
            await page.click('//div[contains(@class,"option") and text()="March"]')

            await page.click('div[aria-label="Day"]')
            await page.click('//div[contains(@class,"option") and text()="20"]')

            await page.click('div[aria-label="Year"]')
            await page.click('//div[contains(@class,"option") and text()="2001"]')

            await asyncio.sleep(0.2)

            try:
                try:
                    await page.locator('button:has-text("Create")').click(timeout=5000)
                except:
                    await page.locator('button:has-text("Continue")').click(timeout=5000)

                log.info("✅ Clicked Create/Continue button")
                log.warning("\033[93mSolve CAPTCHA Manually...\033[0m")
                play_beep()

            except Exception as e:
                log.error(f"❌ Unexpected error when clicking create button: {e}")
                return

            log.info("\033[93mWaiting for account creation / redirect...\033[0m")
            for _ in range(900):  
                try:
                    current_url = await page.evaluate("window.location.href")
                except Exception:
                    current_url = ""
                if "https://discord.com/channels/@me" in current_url:
                    log.info("\033[93mAccount appears to be logged in (channels/@me).\033[0m")
                    break
                await asyncio.sleep(0.5)

            try:
                token = await page.evaluate("window.localStorage.getItem('token')")
                token = json.loads(token) if token else None
                if token:
                    log.info(f"\033[91mToken captured: {token[:10]}....\033[0m")
                else:
                    log.error("❌ Token not found.")
            except Exception as e:
                log.failure(f"⚠️ Error retrieving token: {e}")
                token = None

            log.info("\033[91mSending to Supa...\033[0m")
            ev_line = f'{inbox_id}:{inbox_token}:{token}\n'
            await log_ev_to_supabase(ev_line.strip(), input_key)

            await poll_and_verify_email(inbox_id, inbox_token)
            if token:
                log.info("🔍 Verifying token status post-email verification...")
                check_token(token)

    finally:
        try:
            await context.close()
        except Exception:
            pass
        try:
            await browser.close()
        except Exception:
            pass

def generate_random_string(length=15):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

proxy_setting = config.get("proxies", "disable").lower()

proxies_list = []
if proxy_setting == "enable":
    proxies_path = Path("input/proxies.txt")
    if not proxies_path.exists():
        raise FileNotFoundError("❌ proxies.txt not found in input folder (but proxies are enabled in config.json)")
    with open(proxies_path, "r") as f:
        proxies_list = [line.strip() for line in f if line.strip()]

def get_proxy():
    if proxy_setting != "enable" or not proxies_list:
        return None
    raw_proxy = random.choice(proxies_list)
    user_pass, server = raw_proxy.split("@")
    username, password = user_pass.split(":")
    return {
        "server": server,
        "username": username,
        "password": password
    }

async def worker(license_key):
    try:
        email, password = create_email_account()
        if not email or not password:
            log.error("❌ Failed to create email account. Skipping this task.")
            return

        display_name = generate_random_string()
        username = generate_random_string()

        await fill_discord_register_form(
            inbox_id=email,
            display_name=display_name,
            username=username,
            inbox_token=password,
            input_key=license_key,
            proxy=get_proxy() if proxy_setting == "enable" else None,
        )
    except Exception:
        pass

async def main():

    input_key = await get_license_key()

    if not await validate_key(input_key):
        sys.exit(1)

    clear_screen()
    print_gradient_text(Center.XCenter('\n'.join(banner_lines)), start_color=(255, 255, 0), end_color=(255, 255, 0))
    print("")
    line1 = f"[bright_yellow]🔧 Threads:[/bright_yellow] [magenta]{threads}[/magenta]  |  [bright_yellow]Mail:[/bright_yellow] SparkBoosts.in"
    console.print(Align.center(line1))
    print("\n")

    try:
        thread_count = int(config.get("Threads", 1))
    except ValueError:
        log.error("Invalid 'Threads' value in config.json.")
        return

    if proxy_setting != "enable" and thread_count > 1:
        log.error("❌ You are not using proxies. Only 1 thread allowed.")
        return

    console.print(f"[white]🚀 Starting {thread_count} Thread{'s' if thread_count > 1 else ''}[/white]")

    while True:
        tasks = [asyncio.create_task(worker(license_key=input_key)) for _ in range(thread_count)]
        await asyncio.gather(*tasks)
        await asyncio.sleep(1)

if __name__ == "__main__":
    warnings.filterwarnings("ignore", category=ResourceWarning)
    warnings.filterwarnings("ignore", message=".*geoip=True.*", category=Warning)

    def silence_asyncio_del_exceptions(loop):
        original_handler = loop.get_exception_handler()

        def handler(loop, context):
            msg = context.get("message")
            exception = context.get("exception")
            if msg and "unclosed transport" in msg:
                return
            if isinstance(exception, ValueError) and "closed pipe" in str(exception):
                return
            if original_handler:
                original_handler(loop, context)
            else:
                loop.default_exception_handler(context)

        loop.set_exception_handler(handler)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    silence_asyncio_del_exceptions(loop)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
    except asyncio.CancelledError:
        print("\n[!] loop cancelled.")
