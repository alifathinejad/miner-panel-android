import json, os, threading, time, requests, concurrent.futures, zipfile, datetime, socket, sys, ssl, secrets
from flask import Flask, render_template_string, request, jsonify, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# شماره‌ی نسخه‌ی برنامه -- تک منبع حقیقت؛ در هر تغییر/آپدیت فقط همین یک خط
# باید عوض شود و در همه‌جای برنامه (پنل، لاگین، بنر ترمینال) خودکار اعمال می‌شود.
APP_VERSION = "2.1"

app = Flask(__name__)
# secret_key به‌صورت پویا و یکتا برای هر نصب، کمی پایین‌تر (بعد از تعریف
# load_config/save_config) تنظیم می‌شود -- به همراه تنظیمات امنیتی کوکی سشن.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # جاوااسکریپت صفحه به کوکی سشن دسترسی نداشته باشد
    SESSION_COOKIE_SAMESITE="Lax",  # کاهش ریسک CSRF از طریق درخواست‌های cross-site
)

# --- تعیین مسیر پویا برای سازگاری با فایل EXE و سیستم‌عامل‌های مختلف ---
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_FILE = os.path.join(BASE_DIR, "miners_config.json")

DEFAULT_CONFIG = {
    "bot_token": "",
    "chat_id": "",
    "telegram_proxy": "",
    "admin_user": "admin",
    "admin_pass": "admin123",
    "panel_port": 2096,
    "miners": []
}

miner_states = {}
state_lock = threading.Lock()

# نوع اتصال فعلی سرور برای نمایش در پنل: "http" | "https" | "https_mtls"
# مقدار واقعی‌اش در انتهای فایل (بخش __main__) قبل از بالا آمدن سرور تنظیم می‌شود.
CONNECTION_MODE = "http"

def load_config():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "admin_user" not in data:
                    data["admin_user"] = "admin"
                if "panel_port" not in data:
                    data["panel_port"] = 2096
                for m in data.get("miners", []):
                    m["enabled"] = True
                    if "type" not in m:
                        m["type"] = "Whatsminer"
                    if "min_hashrate" not in m:
                        m["min_hashrate"] = 0
                return data
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)

def save_config(config):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=4)

# --- راه‌اندازی امنیتی اولیه (اجرا فقط یک‌بار در زمان بالا آمدن برنامه) ---
# ۱) اگر secret_key در فایل کانفیگ وجود نداشته باشد، یک مقدار تصادفی و یکتا
#    برای همین نصب مشخص تولید و ذخیره می‌شود (به‌جای مقدار ثابت هاردکدشده در
#    کد که در همه‌ی نسخه‌های توزیع‌شده‌ی برنامه یکسان بود).
# ۲) اگر رمز ادمین هنوز به‌صورت متن‌ساده (admin_pass) ذخیره شده باشد، به‌صورت
#    خودکار Hash می‌شود (admin_pass_hash) و نسخه‌ی متن‌ساده از فایل حذف می‌شود.
_bootstrap_cfg = load_config()
_bootstrap_needs_save = False
if not _bootstrap_cfg.get("secret_key"):
    _bootstrap_cfg["secret_key"] = secrets.token_hex(32)
    _bootstrap_needs_save = True
if "admin_pass_hash" not in _bootstrap_cfg:
    _bootstrap_cfg["admin_pass_hash"] = generate_password_hash(_bootstrap_cfg.get("admin_pass", "admin123") or "admin123")
    _bootstrap_cfg.pop("admin_pass", None)
    _bootstrap_needs_save = True
if _bootstrap_needs_save:
    save_config(_bootstrap_cfg)
app.secret_key = _bootstrap_cfg["secret_key"]

# --- محافظت CSRF ساده مبتنی بر توکن سشن ---
def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]

app.jinja_env.globals["csrf_token"] = get_csrf_token
app.jinja_env.globals["app_version"] = APP_VERSION

@app.before_request
def _csrf_protect():
    # فقط درخواست‌های تغییردهنده‌ی وضعیت (POST) بررسی می‌شوند؛ صفحه‌ی لاگین
    # چون هنوز سشنی وجود ندارد از این بررسی مستثنی است.
    if request.method == "POST" and request.endpoint != "login":
        token_in_session = session.get("csrf_token")
        token_in_request = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
        if not token_in_session or not token_in_request or not secrets.compare_digest(str(token_in_session), str(token_in_request)):
            if request.path in ("/backup", "/test_telegram"):
                return jsonify({"success": False, "message": "درخواست نامعتبر (CSRF). لطفاً صفحه را رفرش کنید."}), 400
            return "درخواست نامعتبر (CSRF). لطفاً صفحه را رفرش کرده و دوباره تلاش کنید.", 400

@app.after_request
def _set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response

# --- محدودسازی تعداد تلاش‌های ورود (جلوگیری از Brute-force روی صفحه‌ی لاگین) ---
LOGIN_ATTEMPTS = {}
LOGIN_ATTEMPTS_LOCK = threading.Lock()
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300

def send_telegram(msg):
    cfg = load_config()
    token = cfg.get("bot_token")
    chat_id = cfg.get("chat_id")
    proxy = cfg.get("telegram_proxy", "").strip()
    
    if not (token and chat_id):
        return False, "اطلاعات توکن یا چت‌آیدی کامل نیست."
        
    proxies = {"http": proxy, "https": proxy} if proxy else None

    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        res = requests.post(url, json={"chat_id": chat_id, "text": msg}, proxies=proxies, timeout=10)
        return (True, "پیام ارسال شد.") if res.status_code == 200 else (False, f"خطا: {res.text}")
    except Exception as e:
        return False, f"خطای ارتباط: {str(e)}"

# --- Whatsminer Parser (Luci Interface) ---
def get_whatsminer_luci_data(miner):
    raw_url = miner.get('url', '').strip()
    if not raw_url.startswith("http"):
        raw_url = "https://" + raw_url

    user = miner.get("username", "admin")
    pwd = miner.get("password", "")
    empty_res = {"status": "Offline", "elapsed": "--", "hashrate": "--", "power": "--", "fan_in": "--", "fan_out": "--", "temps": ["--", "--", "--"], "errors": "--"}

    browser_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
    }

    MAX_ATTEMPTS = 3
    last_exception = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            base_url = raw_url.rstrip('/')
            session_req = requests.Session()
            session_req.trust_env = False
            session_req.proxies = {}
            session_req.headers.update(browser_headers)

            # تایم‌اوت 12 ثانیه برای هر تلاش. علت اصلی retry اینجا این است که
            # این نوع آدرس (DDNS/رله مثل Synology QuickConnect) می‌تواند به‌طور
            # ذاتی و متناوب کند یا ناپایدار باشد -- یعنی گاهی یک درخواست به‌خودی‌خود
            # Timeout می‌خورد در حالی که چند ثانیه بعد همان درخواست کاملاً موفق
            # می‌شود. افزایش صرفِ عدد timeout این مشکل را حل نمی‌کند (چون گاهی
            # اتصال اصلاً برقرار نمی‌شود، نه اینکه فقط کند باشد)؛ آنچه واقعاً کمک
            # می‌کند این است که وقتی یک تلاش شکست خورد، به‌جای تسلیم فوری، دوباره
            # (تا سقف 3 بار) امتحان کنیم.
            session_req.post(f"{base_url}/cgi-bin/luci/", data={"luci_username": user, "luci_password": pwd}, verify=False, timeout=12)
            response = session_req.get(f"{base_url}/cgi-bin/luci/admin/status", verify=False, timeout=12)

            soup = BeautifulSoup(response.text, 'html.parser')
            tables = soup.find_all('table', class_='cbi-section-table')
            if len(tables) < 3:
                last_exception = "unexpected_html_structure"
                if attempt < MAX_ATTEMPTS:
                    time.sleep(2)
                    continue
                return empty_res

            summary_tds = tables[0].find('tr', class_='cbi-section-table-row').find_all('td')
            elapsed = summary_tds[0].find('input')['value']
            th_avg = summary_tds[1].find('input')['value']
            fan_in = summary_tds[4].find('input')['value']
            fan_out = summary_tds[5].find('input')['value']
            power = summary_tds[7].find('input')['value']

            temp_rows = tables[2].find_all('tr', class_='cbi-section-table-row')
            sm0 = temp_rows[0].find_all('td')[3].find('input')['value'] if len(temp_rows) > 0 else "--"
            sm1 = temp_rows[1].find_all('td')[3].find('input')['value'] if len(temp_rows) > 1 else "--"
            sm2 = temp_rows[2].find_all('td')[3].find('input')['value'] if len(temp_rows) > 2 else "--"

            error_val = "0"
            try:
                errors_tag = None
                for tag in soup.find_all(['legend', 'h2', 'h3', 'h4', 'h5']):
                    if tag.text and tag.text.strip().lower() == "errors":
                        errors_tag = tag
                        break

                if errors_tag:
                    err_table = errors_tag.find_next('table')
                    if err_table:
                        table_text = err_table.text.strip()
                        if "no values yet" in table_text.lower():
                            error_val = "0"
                        else:
                            rows = err_table.find_all('tr', class_='cbi-section-table-row')
                            err_list = []
                            for r in rows:
                                tds = r.find_all('td')
                                if len(tds) >= 1:
                                    code = tds[0].text.strip()
                                    cause = tds[1].text.strip() if len(tds) > 1 else ""
                                    if code and "no values" not in code.lower() and code.lower() != "errorcode":
                                        err_list.append(f"{code} ({cause})" if cause else code)
                            error_val = ", ".join(err_list) if err_list else "0"
            except Exception:
                error_val = "0"

            return {
                "status": "Online", "elapsed": elapsed, "hashrate": f"{th_avg} TH/s",
                "power": f"{power} W", "fan_in": fan_in, "fan_out": fan_out, "temps": [sm0, sm1, sm2],
                "errors": error_val
            }
        except Exception as e:
            last_exception = f"{type(e).__name__}: {e}"
            if attempt < MAX_ATTEMPTS:
                # فاصله‌ی کوتاه قبل از تلاش بعدی تا به یک اتصال ناپایدار/رله
                # فرصت بدهیم قبل از تلاش مجدد کمی آرام بگیرد.
                time.sleep(2)
                continue
            print(f"[Whatsminer fetch failed after {MAX_ATTEMPTS} attempts] {raw_url} -> {last_exception}")
            return empty_res

    return empty_res

# --- Socket API Query (Antminer / Avalon / Innosilicon) ---
def query_cgminer_socket(ip, port, command):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, int(port)))
        payload = json.dumps({"command": command}).encode('utf-8') + b'\n'
        s.sendall(payload)
        
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        s.close()
        
        raw_text = response.decode('utf-8', errors='ignore').replace('\x00', '').strip()
        return json.loads(raw_text)
    except Exception:
        return None

def parse_ip_port(raw_url, default_port=4028):
    clean = raw_url.replace("http://", "").replace("https://", "").strip().split('/')[0]
    if ":" in clean:
        parts = clean.split(":")
        return parts[0], int(parts[1])
    return clean, default_port

def format_elapsed_duration(seconds):
    """ثانیه را به فرمت 'XdXhXmXs' مشابه صفحه‌ی وب آنتماینر تبدیل می‌کند."""
    try:
        seconds = int(float(seconds))
    except Exception:
        return "--"
    if seconds < 0:
        return "--"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{days}d {hours}h {minutes}m {secs}s"

def get_cgminer_pools_info(ip, port):
    """اطلاعات Pool(ها) و درصد ریجکت را از طریق دستور 'pools' در API سوکت cgminer می‌گیرد."""
    pools = []
    rejection_rate = "--"
    result = query_cgminer_socket(ip, port, "pools")
    if result and "POOLS" in result and result["POOLS"]:
        for idx, p in enumerate(result["POOLS"], start=1):
            status_raw = str(p.get("Status", "")).strip().lower()
            pools.append({
                "index": idx,
                "url": str(p.get("URL", "--")),
                "user": str(p.get("User", "--")),
                "status": "Normal" if status_raw == "alive" else "Error",
                "diff": str(p.get("Diff", p.get("Stratum Difficulty", "--"))),
                "accepted": str(p.get("Accepted", "--")),
                "rejected": str(p.get("Rejected", "--")),
                "stale": str(p.get("Stale", "--")),
            })
            try:
                if rejection_rate == "--" or str(p.get("Priority", "")) in ("0", 0):
                    rejection_rate = round(float(p.get("Pool Rejected%", 0)), 2)
            except Exception:
                pass
    return pools, rejection_rate

def get_cgminer_api_data(miner):
    empty_res = {"status": "Offline", "elapsed": "--", "hashrate": "--", "avg_hashrate": "--",
                 "running_time_fmt": "--", "power": "--", "fan_in": "--", "fan_out": "--",
                 "temps": ["--", "--", "--"], "errors": "--", "pools": [], "pool_rejection_rate": "--"}
    ip, port = parse_ip_port(miner.get("url", ""), 4028)
    
    summary = query_cgminer_socket(ip, port, "summary")
    if not summary or "SUMMARY" not in summary or not summary["SUMMARY"]:
        return empty_res

    try:
        sum_data = summary["SUMMARY"][0]
        elapsed = str(sum_data.get("Elapsed", "--"))
        running_time_fmt = format_elapsed_duration(sum_data.get("Elapsed", "--"))
        ghs = float(sum_data.get("GHS 5s", sum_data.get("GHS av", sum_data.get("MHS 5s", 0) / 1000)))
        hashrate = f"{round(ghs / 1000, 2)} TH/s" if ghs > 0 else "--"
        ghs_avg = sum_data.get("GHS av")
        avg_hashrate = f"{round(float(ghs_avg) / 1000, 2)} TH/s" if ghs_avg not in (None, "--") and float(ghs_avg) > 0 else hashrate

        stats = query_cgminer_socket(ip, port, "stats")
        fan_in, fan_out = "--", "--"
        temps = ["--", "--", "--"]

        if stats and "STATS" in stats and len(stats["STATS"]) > 0:
            st = stats["STATS"][0] if len(stats["STATS"]) == 1 else stats["STATS"][1]
            
            f1 = st.get("fan1", st.get("fan_num", st.get("fan_speed1", "--")))
            f2 = st.get("fan2", st.get("fan_speed2", "--"))
            fan_in = str(f1) if f1 != 0 else "--"
            fan_out = str(f2) if f2 != 0 else "--"

            t_list = []
            for k in ["temp1", "temp2", "temp3", "temp_chip1", "temp_chip2", "temp_chip3", "temp_pcb1", "temp_pcb2", "temp_pcb3"]:
                if k in st and str(st[k]) not in ["0", "--", "None"]:
                    t_list.append(str(st[k]))
            if t_list:
                temps = (t_list + ["--", "--", "--"])[:3]

        pools, pool_rejection_rate = get_cgminer_pools_info(ip, port)

        return {
            "status": "Online", "elapsed": elapsed, "hashrate": hashrate, "avg_hashrate": avg_hashrate,
            "running_time_fmt": running_time_fmt, "power": "--", "fan_in": fan_in, "fan_out": fan_out,
            "temps": temps, "errors": "0", "pools": pools, "pool_rejection_rate": pool_rejection_rate
        }
    except Exception:
        return empty_res

def get_miner_data(miner):
    m_type = miner.get("type", "Whatsminer")
    if m_type == "Whatsminer":
        return get_whatsminer_luci_data(miner)
    elif m_type in ["Antminer", "Avalon", "Innosilicon"]:
        return get_cgminer_api_data(miner)
    else:
        res = get_cgminer_api_data(miner)
        return res if res["status"] == "Online" else get_whatsminer_luci_data(miner)

# --- Monitoring Thread ---
def monitor_loop():
    while True:
        try:
            cfg = load_config()
            miners = cfg.get("miners", [])
            if miners:
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    results = list(executor.map(get_miner_data, miners))
                
                current_time = time.time()
                for miner, data in zip(miners, results):
                    m_id = miner.get("url", "")
                    name = miner.get("name", m_id)
                    max_temp = float(miner.get("max_temp", 80))
                    max_fan = float(miner.get("max_fan", 7500))
                    min_fan = float(miner.get("min_fan", 1500))
                    min_hashrate = float(miner.get("min_hashrate", 0))

                    with state_lock:
                        if m_id not in miner_states:
                            miner_states[m_id] = {
                                "confirmed_status": data["status"], "last_data": data, "raw_status": data["status"],
                                "change_start_time": current_time, "temp_alert": False, "fan_high_alert": False, 
                                "fan_low_alert": False, "error_alert": False, "hash_alert": False
                            }
                        state = miner_states[m_id]

                    actual_status = data["status"]
                    if actual_status != state["confirmed_status"]:
                        if actual_status != state["raw_status"]:
                            state["raw_status"] = actual_status
                            state["change_start_time"] = current_time
                        elif current_time - state["change_start_time"] >= 45:
                            state["confirmed_status"] = actual_status
                            if actual_status == "Offline":
                                send_telegram(f"🚨 هشدار خاموشی\nدستگاه: {name}\nآدرس: {m_id}")
                            else:
                                send_telegram(f"✅ دستگاه آنلاین شد\nدستگاه: {name}")
                    else:
                        state["raw_status"] = actual_status
                        state["change_start_time"] = current_time

                    if state["confirmed_status"] == "Online":
                        # این دور از fetch واقعاً موفق بوده (نه فقط اینکه وضعیت
                        # تاییدشده هنوز "Online" مونده). اگر این دور خاص با
                        # Timeout/خطا مواجه شده باشد (مثلاً به‌خاطر یک اتصال
                        # ناپایدار/کند مثل DDNS)، آخرین داده‌ی معتبر قبلی را
                        # نگه می‌داریم به‌جای اینکه با مقادیر خالی "--"
                        # جایگزینش کنیم؛ این از چشمک‌زدن اطلاعات در پنل
                        # جلوگیری می‌کند در حالی که بج "آنلاین/آفلاین" مثل قبل
                        # از منطق ۴۵ ثانیه‌ای تبعیت می‌کند.
                        if data["status"] == "Online":
                            state["last_data"] = data

                            # --- Error Alert ---
                            err_val = str(data.get("errors", "0")).strip()
                            if err_val not in ["0", "--", ""] and not state.get("error_alert", False):
                                send_telegram(f"🚨 هشدار ارور ماینر\nدستگاه: {name}\nشماره و متن ارور: {err_val}")
                                state["error_alert"] = True
                            elif err_val in ["0", "--", ""]:
                                state["error_alert"] = False

                            # --- Low Hashrate Alert ---
                            try:
                                current_th = float(data.get("hashrate", "").replace("TH/s", "").strip())
                            except Exception:
                                current_th = None

                            if current_th is not None and min_hashrate > 0:
                                if current_th < min_hashrate and not state.get("hash_alert", False):
                                    send_telegram(f"⚠️ 🚨 هشدار افت تراهش (هش‌ریت)\nدستگاه: {name}\nتراهش فعلی: {current_th} TH/s\nحداقل مجاز: {min_hashrate} TH/s")
                                    state["hash_alert"] = True
                                elif current_th >= min_hashrate:
                                    state["hash_alert"] = False

                            # --- Temperature Alert ---
                            num_temps = [float(t) for t in data["temps"] if t != "--" and t.replace('.', '', 1).isdigit()]
                            if num_temps:
                                hi_temp = max(num_temps)
                                if hi_temp > max_temp and not state["temp_alert"]:
                                    send_telegram(f"🔥 هشدار دمای بالا\nدستگاه: {name}\nدما: {hi_temp}°C")
                                    state["temp_alert"] = True
                                elif hi_temp <= max_temp:
                                    state["temp_alert"] = False

                            # --- Fan Alert ---
                            try:
                                f_in = float(data["fan_in"])
                                if f_in > max_fan and not state["fan_high_alert"]:
                                    send_telegram(f"⚠️ هشدار دور فن بالا\nدستگاه: {name}\nفن: {f_in} RPM")
                                    state["fan_high_alert"] = True
                                elif f_in <= max_fan:
                                    state["fan_high_alert"] = False

                                if f_in < min_fan and not state["fan_low_alert"]:
                                    send_telegram(f"❄️ هشدار افت فن\nدستگاه: {name}\nفن: {f_in} RPM")
                                    state["fan_low_alert"] = True
                                elif f_in >= min_fan:
                                    state["fan_low_alert"] = False
                            except Exception:
                                pass
                        # else: این دور شکست خورد؛ last_data (آخرین مقدار معتبر) دست‌نخورده می‌ماند.
                    else:
                        state["last_data"] = {"status": "Offline", "elapsed": "--", "hashrate": "--", "power": "--", "fan_in": "--", "fan_out": "--", "temps": ["--", "--", "--"], "errors": "--"}
        except Exception:
            pass
        time.sleep(15)

threading.Thread(target=monitor_loop, daemon=True).start()

# --- Templates & Routes ---
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>ورود به پنل مانیتورینگ</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.rtl.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        body { background-color: #0d1117; color: #ffffff; font-family: Tahoma, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .login-card { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; width: 100%; max-width: 400px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
        .form-control { background-color: #0d1117 !important; border: 1px solid #484f58 !important; color: #ffffff !important; font-size: 0.9rem; }
        label { color: #f0f6fc; font-weight: bold; font-size: 0.85rem; margin-bottom: 5px; display: block; }
        .credit-footer { font-size: 0.75rem; }
        .credit-footer .credit-name { color: #8b949e; }
        .credit-footer .credit-phone { color: #f0f6fc; font-weight: bold; font-size: 0.95rem; letter-spacing: 0.5px; }
        .credit-footer .credit-icon { font-size: 1.05rem; margin: 0 4px; text-decoration: none; }
        .credit-footer .credit-email { color: #c9d1d9; text-decoration: none; }
        .credit-footer .credit-email:hover, .credit-footer .credit-phone:hover { text-decoration: underline; }
        .credit-icon.fa-square-phone, .credit-icon.fa-phone { color: #58a6ff; }
        .credit-icon.fa-whatsapp { color: #25D366; }
        .credit-icon.fa-telegram { color: #29A9EA; }
    </style>
</head>
<body>
<div class="login-card">
    <h4 class="text-center text-info mb-4">🔐 ورود به پنل ماینرها</h4>
    {% if error %}
        <div class="alert alert-danger py-2 small text-center">{{ error }}</div>
    {% endif %}
    <form method="post">
        <div class="mb-3">
            <label>نام کاربری:</label>
            <input type="text" name="username" class="form-control" required autofocus>
        </div>
        <div class="mb-3">
            <label>رمز عبور:</label>
            <input type="password" name="password" class="form-control" required>
        </div>
        <button type="submit" class="btn btn-primary w-100 fw-bold">ورود به سیستم</button>
    </form>
    <div class="text-center mt-3 pt-2 border-top border-secondary credit-footer">
        <div class="credit-name">Developed by Ali Fathinejad | v{{ app_version }}</div>
        <div class="mt-1">
            <a href="tel:+989163725383" class="credit-phone">09163725383</a>
            <a href="tel:+989163725383" class="credit-icon fa-solid fa-phone" title="تماس"></a>
            <a href="https://wa.me/989163725383" target="_blank" rel="noopener" class="credit-icon fa-brands fa-whatsapp" title="واتساپ"></a>
            <a href="https://t.me/+989163725383" target="_blank" rel="noopener" class="credit-icon fa-brands fa-telegram" title="تلگرام"></a>
        </div>
        <div class="mt-1">
            <a href="mailto:alifathinejad1980@gmail.com" class="credit-email">
                <i class="fa-solid fa-envelope me-1"></i>alifathinejad1980@gmail.com
            </a>
        </div>
    </div>
</div>
</body>
</html>
"""

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>داشبورد ماینرها</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.rtl.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        body { background-color: #0d1117; color: #ffffff; font-family: Tahoma, sans-serif; padding: 10px; font-size: 0.85rem; }
        .card { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 8px !important; margin-bottom: 8px; transition: all 0.3s ease; }
        .card-error { border: 2px solid #ff4d4d !important; background-color: #2b1113 !important; animation: cardPulse 1.5s infinite; }
        @keyframes cardPulse { 0% { box-shadow: 0 0 5px rgba(255, 77, 77, 0.4); } 50% { box-shadow: 0 0 15px rgba(255, 77, 77, 0.8); } 100% { box-shadow: 0 0 5px rgba(255, 77, 77, 0.4); } }
        .badge-online { background-color: #238636; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }
        .badge-offline { background-color: #da3633; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }
        .metric-box { background-color: #0d1117; border-radius: 6px; padding: 4px 6px; border: 1px solid #30363d; text-align: center; height: 100%; }
        .metric-title { font-size: 0.68rem; color: #8b949e; margin-bottom: 0px; }
        .metric-value { font-size: 0.85rem; font-weight: bold; color: #58a6ff; }
        .temp-board { font-size: 0.75rem; color: #f0f6fc; }
        .modal-content { background-color: #161b22; border: 1px solid #30363d; }
        label { color: #f0f6fc !important; font-weight: bold; font-size: 0.8rem; margin-bottom: 2px; display: block; }
        .form-control { background-color: #0d1117 !important; border: 1px solid #484f58 !important; color: #ffffff !important; font-size: 0.85rem; padding: 4px 8px; }
        .credit-footer { font-size: 0.75rem; }
        .credit-footer .credit-name { color: #8b949e; }
        .credit-footer .credit-phone { color: #f0f6fc; font-weight: bold; font-size: 0.95rem; letter-spacing: 0.5px; }
        .credit-footer .credit-icon { font-size: 1.05rem; margin: 0 4px; text-decoration: none; }
        .credit-footer .credit-email { color: #c9d1d9; text-decoration: none; }
        .credit-footer .credit-email:hover, .credit-footer .credit-phone:hover { text-decoration: underline; }
        .credit-icon.fa-phone { color: #58a6ff; }
        .credit-icon.fa-whatsapp { color: #25D366; }
        .credit-icon.fa-telegram { color: #29A9EA; }
        .table-dark { background-color: #0d1117; font-size: 0.85rem; }
        th { color: #58a6ff !important; font-weight: bold; }
        td { color: #ffffff !important; padding: 4px !important; }
        .text-danger-alert { color: #ff4d4d !important; font-weight: bold; }

        /* ===== Antminer-style circular status indicators (شبیه پنل وب آنتماینر) ===== */
        .ant-circle {
            width: 58px; height: 58px; border-radius: 50%;
            border: 5px solid #2ea043;
            display: flex; align-items: center; justify-content: center;
            margin: 0 auto; background-color: #0d1117;
        }
        .ant-circle span { font-size: 0.62rem; font-weight: bold; color: #2ea043; text-align: center; }
        .ant-circle.alert { border-color: #da3633; }
        .ant-circle.alert span { color: #da3633; }
        .ant-circle-label { font-size: 0.66rem; color: #8b949e; text-align: center; margin-top: 4px; }
        .pool-table-sm th, .pool-table-sm td { font-size: 0.65rem !important; padding: 3px !important; white-space: nowrap; }

        /* ===== Settings Modal: larger & better organized (visual only) ===== */
        #settingsModal .modal-content { border-radius: 10px; }
        #settingsModal .modal-header { padding: 1rem 1.25rem; }
        #settingsModal .modal-title { font-size: 1.15rem !important; }
        #settingsModal .modal-body { padding: 1.25rem 1.5rem; }
        .settings-section {
            background-color: #0d1117;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 16px 18px;
            margin-bottom: 18px;
        }
        .settings-section-title {
            font-size: 1rem !important;
            padding-bottom: 8px;
            margin-bottom: 14px !important;
            border-bottom: 1px solid #30363d;
        }
        #settingsModal label { font-size: 0.88rem; }
        #settingsModal .form-control, #settingsModal select.form-control {
            font-size: 0.92rem;
            padding: 8px 10px;
        }
        #settingsModal .btn { font-size: 0.85rem; padding: 7px 16px; }
        #settingsModal .table { font-size: 0.85rem; }
        #settingsModal .form-check-label { font-size: 0.85rem; }

        /* ===== مودال ویرایش دستگاه: ظاهر تمیز و منظم، هم‌سطح با مودال تنظیمات ===== */
        .edit-modal .modal-content { border-radius: 10px; }
        .edit-modal .modal-header { padding: 1rem 1.25rem; }
        .edit-modal .modal-body { padding: 1.25rem 1.5rem; }
        .edit-modal label { font-size: 0.88rem; margin-bottom: 4px; display: inline-block; }
        .edit-modal .form-control, .edit-modal select.form-control {
            font-size: 0.92rem;
            padding: 8px 10px;
        }
        .edit-modal .btn { font-size: 0.85rem; padding: 9px 16px; }
    </style>
</head>
<body>
<div class="container-fluid px-2">
    <div class="d-flex justify-content-between align-items-center mb-2 pb-2 border-bottom border-secondary">
        <h5 class="m-0 text-info">🖥️ مانیتورینگ ماینرها</h5>
        <span class="badge {{ 'bg-success' if connection_mode == 'https_mtls' else ('bg-primary' if connection_mode == 'https' else 'bg-warning text-dark') }}" style="font-size: 0.75rem; padding: 6px 10px;" title="نوع اتصال پنل">
            {% if connection_mode == 'https_mtls' %}🛡️ mTLS{% elif connection_mode == 'https' %}🔒 HTTPS{% else %}🌐 HTTP{% endif %}
        </span>
        <div>
            <button id="soundToggleBtn" onclick="toggleAudio()" class="btn btn-outline-danger btn-sm px-2 fw-bold me-1" style="font-size: 0.75rem;">🔇 قطع آلارم صوتی</button>
            <button class="btn btn-warning btn-sm px-3 fw-bold" data-bs-toggle="modal" data-bs-target="#settingsModal">⚙️ تنظیمات</button>
            <a href="/logout" class="btn btn-outline-secondary btn-sm px-2 fw-bold ms-1" style="font-size: 0.75rem;">🚪 خروج</a>
        </div>
    </div>

    {% if port_changed %}
    <div class="alert alert-warning py-2 px-3 mb-2 fw-bold" style="font-size: 0.85rem;">
        ✅ پورت پنل با موفقیت تغییر کرد. ⚠️ برای اعمال شدن تغییرات، لازم است برنامه را کامل ببندید و دوباره اجرا کنید (پنل فعلی تا آن زمان با پورت قبلی کار می‌کند).
    </div>
    {% endif %}
    {% if port_error %}
    <div class="alert alert-danger py-2 px-3 mb-2 fw-bold" style="font-size: 0.85rem;">
        ❌ پورت وارد شده نامعتبر است. لطفاً عددی بین 1 تا 65535 وارد کنید.
    </div>
    {% endif %}

    <div class="row g-2">
        {% for miner in config.miners %}
        <div class="col-xl-3 col-lg-4 col-md-6">
            <div class="card" id="card-{{ loop.index0 }}">
                <div class="d-flex justify-content-between align-items-center mb-1">
                    <h6 class="mb-0 text-warning" style="font-size: 0.9rem;">
                        {{ miner.name }}
                        <span class="badge bg-secondary text-light ms-1" style="font-size: 0.65rem;">{{ miner.get('type', 'Whatsminer') }}</span>
                    </h6>
                    <span class="badge badge-offline" id="status-badge-{{ loop.index0 }}">بررسی...</span>
                </div>
                <div class="text-light mb-2" style="font-size: 0.7rem;" dir="ltr">{{ miner.url }}</div>

                {% if miner.get('type', 'Whatsminer') in ['Antminer', 'Avalon', 'Innosilicon'] %}
                {# ===== چیدمان شبیه پنل وب آنتماینر (طبق عکس نمونه) ===== #}
                <div class="row g-1 mb-2 text-center">
                    <div class="col-3">
                        <div class="ant-circle" id="ant-hash-circle-{{ loop.index0 }}"><span>--</span></div>
                        <div class="ant-circle-label">Hashrate</div>
                    </div>
                    <div class="col-3">
                        <div class="ant-circle" id="ant-net-circle-{{ loop.index0 }}"><span>--</span></div>
                        <div class="ant-circle-label">Network</div>
                    </div>
                    <div class="col-3">
                        <div class="ant-circle" id="ant-fan-circle-{{ loop.index0 }}"><span>--</span></div>
                        <div class="ant-circle-label">Fan</div>
                    </div>
                    <div class="col-3">
                        <div class="ant-circle" id="ant-temp-circle-{{ loop.index0 }}"><span>--</span></div>
                        <div class="ant-circle-label">Temp</div>
                    </div>
                </div>

                <div class="row g-1 mb-1">
                    <div class="col-6">
                        <div class="metric-box">
                            <div class="metric-title">Real Time Hashrate</div>
                            <div class="metric-value text-info" id="ant-realtime-hash-{{ loop.index0 }}">--</div>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="metric-box">
                            <div class="metric-title">Average Hashrate</div>
                            <div class="metric-value text-info" id="ant-avg-hash-{{ loop.index0 }}">--</div>
                        </div>
                    </div>
                </div>

                <div class="row g-1 mb-1">
                    <div class="col-6">
                        <div class="metric-box">
                            <div class="metric-title">Pool Rejection Rate</div>
                            <div class="metric-value" id="ant-rejection-{{ loop.index0 }}">--</div>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="metric-box">
                            <div class="metric-title">Miner Running Time</div>
                            <div class="metric-value" id="ant-runtime-{{ loop.index0 }}">--</div>
                        </div>
                    </div>
                </div>

                <div class="mt-1">
                    <div class="metric-title mb-1">Pool</div>
                    <div class="table-responsive">
                        <table class="table table-dark table-bordered text-center align-middle pool-table-sm mb-0">
                            <thead><tr><th>#</th><th>Address</th><th>Worker</th><th>Status</th><th>Diff</th><th>Accepted</th><th>Rejected</th><th>Stale</th></tr></thead>
                            <tbody id="ant-pool-body-{{ loop.index0 }}"><tr><td colspan="8" class="text-center text-secondary">--</td></tr></tbody>
                        </table>
                    </div>
                </div>
                {% else %}
                {# ===== چیدمان اصلی/قبلی برای Whatsminer (بدون تغییر) ===== #}
                <div class="row g-1 mb-1">
                    <div class="col-6">
                        <div class="metric-box">
                            <div class="metric-title">زمان کارکرد</div>
                            <div class="metric-value text-success" id="elapsed-{{ loop.index0 }}">--</div>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="metric-box">
                            <div class="metric-title">تراهش (هش‌ریت)</div>
                            <div class="metric-value text-info" id="hr-{{ loop.index0 }}">--</div>
                        </div>
                    </div>
                </div>

                <div class="row g-1 mb-1">
                    <div class="col-6">
                        <div class="metric-box">
                            <div class="metric-title">فن ورودی</div>
                            <div class="metric-value" id="fan-in-{{ loop.index0 }}">--</div>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="metric-box">
                            <div class="metric-title">فن خروجی</div>
                            <div class="metric-value" id="fan-out-{{ loop.index0 }}">--</div>
                        </div>
                    </div>
                </div>

                <div class="row g-1 mb-1">
                    <div class="col-12">
                        <div class="metric-box">
                            <div class="metric-title">Error</div>
                            <div class="metric-value text-success fw-bold" id="errors-{{ loop.index0 }}">0</div>
                        </div>
                    </div>
                </div>

                <div class="row g-1">
                    <div class="col-12">
                        <div class="metric-box">
                            <div class="metric-title mb-1">
                                دما (°C) | توان: <span id="power-{{ loop.index0 }}">--</span>
                            </div>
                            <div class="d-flex justify-content-around temp-board">
                                <span>SM0: <strong id="temp0-{{ loop.index0 }}">--</strong></span>
                                <span>SM1: <strong id="temp1-{{ loop.index0 }}">--</strong></span>
                                <span>SM2: <strong id="temp2-{{ loop.index0 }}">--</strong></span>
                            </div>
                        </div>
                    </div>
                </div>
                {% endif %}

            </div>
        </div>
        {% endfor %}
    </div>
</div>

<div class="modal fade" id="settingsModal" tabindex="-1">
  <div class="modal-dialog modal-xl modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header border-secondary py-3">
        <h5 class="modal-title text-warning fw-bold">⚙️ مدیریت و تنظیمات</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">

        <div class="settings-section">
            <h6 class="text-info settings-section-title fw-bold">📦 پشتیبان‌گیری (بکاپ)</h6>
            <button type="button" onclick="createBackup()" class="btn btn-outline-info fw-bold">📥 ایجاد بکاپ فشرده</button>
            <div id="backup-result" class="mt-2 small"></div>
        </div>

        <form action="/update_credentials" method="post" class="settings-section">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <h6 class="text-info settings-section-title fw-bold">🔑 تغییر نام کاربری و رمز عبور پنل</h6>
            <div class="row g-3 mb-3">
                <div class="col-md-6">
                    <label>نام کاربری جدید:</label>
                    <input type="text" name="admin_user" class="form-control" value="{{ config.admin_user }}" required>
                </div>
                <div class="col-md-6">
                    <label>رمز عبور جدید:</label>
                    <input type="password" name="admin_pass" class="form-control" placeholder="برای عدم تغییر، خالی بگذارید" autocomplete="new-password">
                </div>
            </div>
            <button type="submit" class="btn btn-warning fw-bold">ذخیره نام کاربری و رمز عبور</button>
        </form>

        <form action="/update_port" method="post" class="settings-section">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <h6 class="text-info settings-section-title fw-bold">🔌 تغییر پورت پنل</h6>
            <div class="row g-3 mb-3 align-items-end">
                <div class="col-md-4">
                    <label>پورت پنل:</label>
                    <input type="number" min="1" max="65535" name="panel_port" class="form-control" value="{{ config.get('panel_port', 2096) }}" required>
                </div>
                <div class="col-md-8">
                    <div class="small text-warning">⚠️ توجه: بعد از تغییر و ذخیره‌ی پورت، برای اعمال شدن تغییرات باید برنامه را کامل ببندید و دوباره باز کنید.</div>
                </div>
            </div>
            <button type="submit" class="btn btn-warning fw-bold">ذخیره پورت</button>
        </form>

        <form action="/telegram" method="post" class="settings-section">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <h6 class="text-info settings-section-title fw-bold">📲 تنظیمات ربات تلگرام و هشدار</h6>
            <div class="row g-3 mb-3">
                <div class="col-md-4">
                    <label>توکن ربات:</label>
                    <input type="text" name="bot_token" class="form-control" value="{{ config.bot_token }}">
                </div>
                <div class="col-md-4">
                    <label>چت آیدی:</label>
                    <input type="text" name="chat_id" class="form-control" value="{{ config.chat_id }}">
                </div>
                <div class="col-md-4">
                    <label>پروکسی تلگرام (اختیاری):</label>
                    <input type="text" name="telegram_proxy" class="form-control" placeholder="http://127.0.0.1:8080" value="{{ config.telegram_proxy or '' }}">
                </div>
            </div>

            <div class="mb-3 form-check">
                <input type="checkbox" class="form-check-input" id="settingAudioAlarm" onchange="saveAudioSettingToStorage(this)">
                <label class="form-check-label text-warning" for="settingAudioAlarm" style="display: inline-block; cursor: pointer;">🔊 فعال‌سازی آلارم صوتی در صورت خطا، دما، افت تراهش یا دور فن غیرمجاز</label>
            </div>

            <div class="d-flex gap-2">
                <button type="submit" class="btn btn-primary fw-bold">ذخیره تنظیمات تلگرام</button>
                <button type="button" onclick="testTelegram()" class="btn btn-outline-warning fw-bold">🧪 ارسال پیام تست</button>
            </div>
            <div id="test-result" class="mt-2 small"></div>
        </form>

        <form action="/add" method="post" class="settings-section">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <h6 class="text-info settings-section-title fw-bold">➕ افزودن دستگاه</h6>
            <div class="row g-3 mb-3">
                <div class="col-md-3">
                    <label>نام دستگاه:</label>
                    <input type="text" name="name" class="form-control" required>
                </div>
                <div class="col-md-6">
                    <label>آدرس (IP:Port):</label>
                    <input type="text" name="url" class="form-control" placeholder="192.168.1.100 یا IP:4028" required>
                </div>
                <div class="col-md-3">
                    <label>نوع ماینر:</label>
                    <select name="type" class="form-control">
                        <option value="Whatsminer">Whatsminer</option>
                        <option value="Antminer">Antminer</option>
                        <option value="Avalon">Avalon</option>
                        <option value="Innosilicon">Innosilicon</option>
                        <option value="Other">سایر</option>
                    </select>
                </div>
            </div>
            <div class="row g-3 mb-3">
                <div class="col-md-2">
                    <label>نام کاربری:</label>
                    <input type="text" name="username" class="form-control" value="admin" required>
                </div>
                <div class="col-md-2">
                    <label>رمز عبور:</label>
                    <input type="password" name="password" class="form-control" required>
                </div>
                <div class="col-md-2">
                    <label>حد دما (°C):</label>
                    <input type="number" name="max_temp" class="form-control" value="80" required>
                </div>
                <div class="col-md-2">
                    <label>حداقل تراهش (TH):</label>
                    <input type="number" step="0.1" name="min_hashrate" class="form-control" value="0" required>
                </div>
                <div class="col-md-2">
                    <label>حداکثر فن:</label>
                    <input type="number" name="max_fan" class="form-control" value="7500" required>
                </div>
                <div class="col-md-2">
                    <label>حداقل فن:</label>
                    <input type="number" name="min_fan" class="form-control" value="1500" required>
                </div>
            </div>
            <button type="submit" class="btn btn-success w-100 fw-bold">افزودن</button>
        </form>

        <div class="settings-section">
        <h6 class="text-info settings-section-title fw-bold">📋 لیست دستگاه‌ها</h6>
        <div class="table-responsive">
            <table class="table table-dark table-bordered text-center align-middle">
                <thead>
                    <tr><th>نام</th><th>نوع</th><th>آدرس</th><th>حد دما</th><th>حداقل تراهش</th><th>فن</th><th>عملیات</th></tr>
                </thead>
                <tbody>
                    {% for miner in config.miners %}
                    <tr>
                        <td class="text-warning">{{ miner.name }}</td>
                        <td><span class="badge bg-secondary" style="font-size: 0.75rem;">{{ miner.get('type', 'Whatsminer') }}</span></td>
                        <td dir="ltr">{{ miner.url }}</td>
                        <td>{{ miner.max_temp }}°C</td>
                        <td>{{ miner.get('min_hashrate', 0) }} TH/s</td>
                        <td>{{ miner.min_fan }}-{{ miner.max_fan }}</td>
                        <td>
                            <button class="btn btn-primary btn-sm py-0 px-2" style="font-size: 0.75rem;" data-bs-toggle="modal" data-bs-target="#editModal-{{ loop.index0 }}">ویرایش</button>
                            <form action="/delete/{{ loop.index0 }}" method="post" style="display:inline;" onsubmit="return confirm('آیا از حذف این دستگاه مطمئن هستید؟');">
                                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                <button type="submit" class="btn btn-danger btn-sm py-0 px-2" style="font-size: 0.75rem;">حذف</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        </div>

      </div>
    </div>
  </div>
</div>

{% for miner in config.miners %}
<div class="modal fade edit-modal" id="editModal-{{ loop.index0 }}" tabindex="-1">
  <div class="modal-dialog modal-lg">
    <div class="modal-content">
      <div class="modal-header border-secondary py-2">
        <h6 class="modal-title text-warning">✏️ ویرایش دستگاه: {{ miner.name }}</h6>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body p-3">
        <form action="/edit/{{ loop.index0 }}" method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

            <div class="settings-section">
                <h6 class="text-info settings-section-title fw-bold">🔌 اتصال دستگاه</h6>
                <div class="row g-3">
                    <div class="col-md-4">
                        <label>نام دستگاه:</label>
                        <input type="text" name="name" class="form-control" value="{{ miner.name }}" required>
                    </div>
                    <div class="col-md-5">
                        <label>آدرس (IP:Port):</label>
                        <input type="text" name="url" class="form-control" value="{{ miner.url }}" required dir="ltr">
                    </div>
                    <div class="col-md-3">
                        <label>نوع ماینر:</label>
                        <select name="type" class="form-control">
                            <option value="Whatsminer" {% if miner.get('type', 'Whatsminer') == 'Whatsminer' %}selected{% endif %}>Whatsminer</option>
                            <option value="Antminer" {% if miner.get('type') == 'Antminer' %}selected{% endif %}>Antminer</option>
                            <option value="Avalon" {% if miner.get('type') == 'Avalon' %}selected{% endif %}>Avalon</option>
                            <option value="Innosilicon" {% if miner.get('type') == 'Innosilicon' %}selected{% endif %}>Innosilicon</option>
                            <option value="Other" {% if miner.get('type') == 'Other' %}selected{% endif %}>سایر</option>
                        </select>
                    </div>
                </div>
            </div>

            <div class="settings-section">
                <h6 class="text-info settings-section-title fw-bold">🔑 اطلاعات ورود</h6>
                <div class="row g-3">
                    <div class="col-md-6">
                        <label>نام کاربری:</label>
                        <input type="text" name="username" class="form-control" value="{{ miner.username }}" required>
                    </div>
                    <div class="col-md-6">
                        <label>رمز عبور:</label>
                        <input type="password" name="password" class="form-control" value="{{ miner.password }}" required autocomplete="new-password">
                    </div>
                </div>
            </div>

            <div class="settings-section mb-2">
                <h6 class="text-info settings-section-title fw-bold">⚠️ آستانه‌های هشدار</h6>
                <div class="row g-3">
                    <div class="col-6 col-md-3">
                        <label>حد دما (°C):</label>
                        <input type="number" name="max_temp" class="form-control" value="{{ miner.max_temp }}" required>
                    </div>
                    <div class="col-6 col-md-3">
                        <label>حداقل تراهش (TH):</label>
                        <input type="number" step="0.1" name="min_hashrate" class="form-control" value="{{ miner.get('min_hashrate', 0) }}" required>
                    </div>
                    <div class="col-6 col-md-3">
                        <label>حداکثر فن:</label>
                        <input type="number" name="max_fan" class="form-control" value="{{ miner.max_fan }}" required>
                    </div>
                    <div class="col-6 col-md-3">
                        <label>حداقل فن:</label>
                        <input type="number" name="min_fan" class="form-control" value="{{ miner.min_fan }}" required>
                    </div>
                </div>
            </div>

            <button type="submit" class="btn btn-warning w-100 fw-bold">ذخیره تغییرات</button>
        </form>
      </div>
    </div>
  </div>
</div>
{% endfor %}

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
const minersConfig = {{ config.miners | tojson }};
let audioEnabled = true;
let audioCtx = null;

document.addEventListener("DOMContentLoaded", () => {
    const savedSetting = localStorage.getItem("miner_audio_alarm");
    audioEnabled = savedSetting !== null ? savedSetting === "true" : true;
    const settingCheckbox = document.getElementById("settingAudioAlarm");
    if (settingCheckbox) settingCheckbox.checked = audioEnabled;
    updateAudioButtonUI();
});

function saveAudioSettingToStorage(checkbox) {
    audioEnabled = checkbox.checked;
    localStorage.setItem("miner_audio_alarm", audioEnabled);
    updateAudioButtonUI();
}

function toggleAudio() {
    audioEnabled = !audioEnabled;
    localStorage.setItem("miner_audio_alarm", audioEnabled);
    const settingCheckbox = document.getElementById("settingAudioAlarm");
    if (settingCheckbox) settingCheckbox.checked = audioEnabled;
    updateAudioButtonUI();
}

function updateAudioButtonUI() {
    const btn = document.getElementById('soundToggleBtn');
    if (!btn) return;
    btn.className = audioEnabled ? "btn btn-outline-danger btn-sm px-2 fw-bold me-1" : "btn btn-outline-success btn-sm px-2 fw-bold me-1";
    btn.innerText = audioEnabled ? "🔇 قطع آلارم صوتی" : "🔊 وصل آلارم صوتی";
}

function playAlarmBeep() {
    if (!audioEnabled) return;
    try {
        if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        if (audioCtx.state === 'suspended') audioCtx.resume();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(880, audioCtx.currentTime);
        gain.gain.setValueAtTime(0.15, audioCtx.currentTime);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.3);
    } catch(e) {}
}

function escapeHtmlSafe(str) {
    return String(str === undefined || str === null ? "--" : str).replace(/[&<>"']/g, function (c) {
        return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c];
    });
}

function setAntCircle(elemId, isOk, okText, badText) {
    const el = document.getElementById(elemId);
    if (!el) return;
    const span = el.querySelector('span');
    el.classList.toggle('alert', !isOk);
    if (span) span.innerText = isOk ? okText : badText;
}

// چیدمان قبلی/اصلی برای دستگاه‌های Whatsminer -- بدون هیچ تغییری نسبت به قبل
function updateWhatsminerCard(item, minerConf, index) {
    const maxTemp = parseFloat(minerConf.max_temp || 80);
    const maxFan = parseFloat(minerConf.max_fan || 7500);
    const minFan = parseFloat(minerConf.min_fan || 1500);
    const minHash = parseFloat(minerConf.min_hashrate || 0);

    const badge = document.getElementById(`status-badge-${index}`);
    const card = document.getElementById(`card-${index}`);
    if (!badge || !card) return false;

    let hasError = false;

    if (item.status === "Online") {
        badge.className = "badge badge-online";
        badge.innerText = "آنلاین";
    } else {
        badge.className = "badge badge-offline";
        badge.innerText = "آفلاین";
        hasError = true;
    }

    document.getElementById(`elapsed-${index}`).innerText = item.elapsed;
    document.getElementById(`power-${index}`).innerText = item.power || "--";

    const hrElem = document.getElementById(`hr-${index}`);
    if (hrElem) {
        hrElem.innerText = item.hashrate;
        let currentTH = parseFloat((item.hashrate || "").replace("TH/s", "").trim());
        if (!isNaN(currentTH) && minHash > 0 && currentTH < minHash) {
            hrElem.className = "metric-value text-danger-alert";
            hasError = true;
        } else {
            hrElem.className = "metric-value text-info";
        }
    }

    const errorsElem = document.getElementById(`errors-${index}`);
    if (errorsElem) {
        const errVal = item.errors || "0";
        errorsElem.innerText = errVal;
        if (errVal !== "0" && errVal !== "--" && errVal !== "-") {
            errorsElem.className = "metric-value text-danger-alert fw-bold";
            hasError = true;
        } else {
            errorsElem.className = "metric-value text-success fw-bold";
        }
    }

    const fanInElem = document.getElementById(`fan-in-${index}`);
    const fanInVal = parseFloat(item.fan_in);
    if (!isNaN(fanInVal) && (fanInVal > maxFan || fanInVal < minFan)) {
        fanInElem.className = "metric-value text-danger-alert";
        hasError = true;
    } else {
        fanInElem.className = "metric-value";
        fanInElem.style.color = "#58a6ff";
    }
    fanInElem.innerText = item.fan_in !== "--" ? item.fan_in : "--";

    const fanOutElem = document.getElementById(`fan-out-${index}`);
    const fanOutVal = parseFloat(item.fan_out);
    if (!isNaN(fanOutVal) && (fanOutVal > maxFan || fanOutVal < minFan)) {
        fanOutElem.className = "metric-value text-danger-alert";
        hasError = true;
    } else {
        fanOutElem.className = "metric-value";
        fanOutElem.style.color = "#58a6ff";
    }
    fanOutElem.innerText = item.fan_out !== "--" ? item.fan_out : "--";

    if (item.temps && item.temps.length >= 3) {
        item.temps.forEach((tVal, tIdx) => {
            const tempElem = document.getElementById(`temp${tIdx}-${index}`);
            const numericT = parseFloat(tVal);
            if (!isNaN(numericT) && numericT > maxTemp) {
                tempElem.className = "text-danger-alert";
                hasError = true;
            } else {
                tempElem.className = "text-warning";
            }
            tempElem.innerText = tVal;
        });
    }

    if (hasError) card.classList.add("card-error"); else card.classList.remove("card-error");
    return hasError;
}

// چیدمان جدید برای Antminer/Avalon/Innosilicon، شبیه پنل وب آنتماینر در عکس نمونه
function updateAntminerCard(item, minerConf, index) {
    const badge = document.getElementById(`status-badge-${index}`);
    const card = document.getElementById(`card-${index}`);
    if (!badge || !card) return false;

    const maxTemp = parseFloat(minerConf.max_temp || 80);
    const maxFan = parseFloat(minerConf.max_fan || 7500);
    const minFan = parseFloat(minerConf.min_fan || 1500);
    const minHash = parseFloat(minerConf.min_hashrate || 0);

    const isOnline = item.status === "Online";
    badge.className = isOnline ? "badge badge-online" : "badge badge-offline";
    badge.innerText = isOnline ? "آنلاین" : "آفلاین";
    setAntCircle(`ant-net-circle-${index}`, isOnline, "Normal", "Offline");

    let hasError = !isOnline;

    const currentTH = parseFloat((item.hashrate || "").replace("TH/s", "").trim());
    const hashKnown = !isNaN(currentTH);
    const hashOk = !hashKnown || minHash <= 0 || currentTH >= minHash;
    setAntCircle(`ant-hash-circle-${index}`, hashOk, "Normal", "Low");
    if (hashKnown && !hashOk) hasError = true;

    const rtEl = document.getElementById(`ant-realtime-hash-${index}`);
    if (rtEl) rtEl.innerText = item.hashrate || "--";
    const avgEl = document.getElementById(`ant-avg-hash-${index}`);
    if (avgEl) avgEl.innerText = item.avg_hashrate || "--";

    const fIn = parseFloat(item.fan_in);
    const fOut = parseFloat(item.fan_out);
    let fanOk = true;
    [fIn, fOut].forEach(v => { if (!isNaN(v) && (v > maxFan || v < minFan)) fanOk = false; });
    setAntCircle(`ant-fan-circle-${index}`, fanOk, "Normal", "Warning");
    if (!fanOk) hasError = true;

    let tempOk = true;
    (item.temps || []).forEach(t => {
        const nt = parseFloat(t);
        if (!isNaN(nt) && nt > maxTemp) tempOk = false;
    });
    setAntCircle(`ant-temp-circle-${index}`, tempOk, "Normal", "High");
    if (!tempOk) hasError = true;

    const errVal = item.errors || "0";
    if (errVal !== "0" && errVal !== "--" && errVal !== "-") hasError = true;

    const rejEl = document.getElementById(`ant-rejection-${index}`);
    if (rejEl) {
        const rej = item.pool_rejection_rate;
        const rejNum = parseFloat(rej);
        rejEl.innerText = (rej === undefined || rej === null || rej === "--" || isNaN(rejNum)) ? "--" : `${rejNum}%`;
        rejEl.className = "metric-value " + (!isNaN(rejNum) && rejNum > 5 ? "text-danger-alert" : "text-success");
    }

    const rtimeEl = document.getElementById(`ant-runtime-${index}`);
    if (rtimeEl) rtimeEl.innerText = item.running_time_fmt || "--";

    const tbody = document.getElementById(`ant-pool-body-${index}`);
    if (tbody) {
        const pools = item.pools || [];
        if (pools.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-secondary">--</td></tr>';
        } else {
            tbody.innerHTML = pools.map(p => `
                <tr>
                    <td>${escapeHtmlSafe(p.index)}</td>
                    <td dir="ltr">${escapeHtmlSafe(p.url)}</td>
                    <td>${escapeHtmlSafe(p.user)}</td>
                    <td><span class="badge ${p.status === 'Normal' ? 'badge-online' : 'badge-offline'}" style="font-size:0.6rem;">${escapeHtmlSafe(p.status)}</span></td>
                    <td>${escapeHtmlSafe(p.diff)}</td>
                    <td>${escapeHtmlSafe(p.accepted)}</td>
                    <td>${escapeHtmlSafe(p.rejected)}</td>
                    <td>${escapeHtmlSafe(p.stale)}</td>
                </tr>`).join('');
        }
    }

    if (hasError) card.classList.add("card-error"); else card.classList.remove("card-error");
    return hasError;
}

function updateMetrics() {
    fetch('/api/status')
        .then(res => res.json())
        .then(data => {
            let hasAnyErrorOverall = false;
            data.forEach((item, index) => {
                const minerConf = minersConfig[index] || {};
                const mType = minerConf.type || "Whatsminer";
                const isAntStyle = ["Antminer", "Avalon", "Innosilicon"].includes(mType);
                const hasError = isAntStyle
                    ? updateAntminerCard(item, minerConf, index)
                    : updateWhatsminerCard(item, minerConf, index);
                if (hasError) hasAnyErrorOverall = true;
            });

            if (hasAnyErrorOverall) playAlarmBeep();
        });
}

function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : "";
}

function createBackup() {
    const resDiv = document.getElementById('backup-result');
    resDiv.className = "mt-1 small text-warning";
    resDiv.innerText = "در حال ایجاد بکاپ...";
    fetch('/backup', { method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() } })
        .then(res => res.json())
        .then(data => {
            resDiv.className = data.success ? "mt-1 small text-success" : "mt-1 small text-danger";
            resDiv.innerText = (data.success ? "✅ " : "❌ ") + data.message;
        });
}

function testTelegram() {
    const resDiv = document.getElementById('test-result');
    resDiv.className = "mt-1 small text-warning";
    resDiv.innerText = "در حال ارسال...";
    fetch('/test_telegram', { method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() } })
        .then(res => res.json())
        .then(data => {
            resDiv.className = data.success ? "mt-1 small text-success" : "mt-1 small text-danger";
            resDiv.innerText = (data.success ? "✅ " : "❌ ") + data.message;
        });
}

setInterval(updateMetrics, 8443);
updateMetrics();
</script>
<div class="text-center mt-3 mb-2 pt-2 border-top border-secondary credit-footer">
    <div class="credit-name">Developed by Ali Fathinejad | v{{ app_version }}</div>
    <div class="mt-1">
        <a href="tel:+989163725383" class="credit-phone">09163725383</a>
        <a href="tel:+989163725383" class="credit-icon fa-solid fa-phone" title="تماس"></a>
        <a href="https://wa.me/989163725383" target="_blank" rel="noopener" class="credit-icon fa-brands fa-whatsapp" title="واتساپ"></a>
        <a href="https://t.me/+989163725383" target="_blank" rel="noopener" class="credit-icon fa-brands fa-telegram" title="تلگرام"></a>
    </div>
    <div class="mt-1">
        <a href="mailto:alifathinejad1980@gmail.com" class="credit-email">
            <i class="fa-solid fa-envelope me-1"></i>alifathinejad1980@gmail.com
        </a>
    </div>
</div>
</body>
</html>
"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    cfg = load_config()
    client_ip = request.remote_addr or "unknown"

    with LOGIN_ATTEMPTS_LOCK:
        entry = LOGIN_ATTEMPTS.get(client_ip)
        locked_remaining = int(entry["locked_until"] - time.time()) if entry and entry.get("locked_until", 0) > time.time() else 0

    if locked_remaining > 0:
        error = f"تعداد تلاش‌های ناموفق ورود زیاد بوده است. لطفاً {locked_remaining} ثانیه‌ی دیگر دوباره تلاش کنید."
        return render_template_string(LOGIN_TEMPLATE, error=error)

    if request.method == 'POST':
        user = request.form.get('username', '')
        pwd = request.form.get('password', '')
        stored_hash = cfg.get("admin_pass_hash", "")
        pwd_ok = False
        if stored_hash:
            try:
                pwd_ok = check_password_hash(stored_hash, pwd)
            except Exception:
                pwd_ok = False

        if user == cfg.get("admin_user", "admin") and pwd_ok:
            with LOGIN_ATTEMPTS_LOCK:
                LOGIN_ATTEMPTS.pop(client_ip, None)
            session.pop('csrf_token', None)  # جلوگیری از session fixation؛ توکن جدید بعد از لاگین ساخته می‌شود
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            with LOGIN_ATTEMPTS_LOCK:
                entry = LOGIN_ATTEMPTS.get(client_ip, {"count": 0, "locked_until": 0})
                entry["count"] = entry.get("count", 0) + 1
                if entry["count"] >= MAX_LOGIN_ATTEMPTS:
                    entry["locked_until"] = time.time() + LOGIN_LOCKOUT_SECONDS
                    entry["count"] = 0
                LOGIN_ATTEMPTS[client_ip] = entry
            error = "نام کاربری یا رمز عبور اشتباه است."
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template_string(
        HTML_TEMPLATE,
        config=load_config(),
        port_changed=request.args.get('port_changed'),
        port_error=request.args.get('port_error'),
        connection_mode=CONNECTION_MODE
    )

@app.route('/backup', methods=['POST'])
def backup():
    if not session.get('logged_in'):
        return jsonify({"success": False, "message": "دسترسی غیرمجاز"})
    
    backup_dir = os.path.join(BASE_DIR, "backup")
    try:
        os.makedirs(backup_dir, exist_ok=True)
        now_str = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        zip_path = os.path.join(backup_dir, f"backup_{now_str}.zip")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if os.path.exists(DATA_FILE): zipf.write(DATA_FILE, arcname="miners_config.json")
            script_path = sys.executable if getattr(sys, 'frozen', False) else __file__
            if os.path.exists(script_path) and not getattr(sys, 'frozen', False):
                zipf.write(script_path, arcname="app.py")
        return jsonify({"success": True, "message": f"بکاپ در پوشه backup ذخیره شد."})
    except Exception as e:
        return jsonify({"success": False, "message": f"خطا در ساخت بکاپ: {str(e)}"})

@app.route('/api/status')
def api_status():
    if not session.get('logged_in'):
        return jsonify([]), 401
    miners = load_config().get("miners", [])
    if not miners:
        return jsonify([])
    
    response_list = []
    with state_lock:
        for m in miners:
            m_id = m.get("url", "")
            if m_id in miner_states:
                st = miner_states[m_id]
                data_to_send = dict(st.get("last_data", {}))
                data_to_send["status"] = st.get("confirmed_status", "Offline")
                data_to_send["enabled"] = True
                response_list.append(data_to_send)
            else:
                response_list.append({"status": "Offline", "elapsed": "--", "hashrate": "--", "power": "--", "fan_in": "--", "fan_out": "--", "temps": ["--", "--", "--"], "errors": "--"})
    return jsonify(response_list)

@app.route('/update_credentials', methods=['POST'])
def update_credentials():
    if not session.get('logged_in'): return redirect(url_for('login'))
    cfg = load_config()
    new_user = (request.form.get("admin_user") or "").strip()
    new_pass = (request.form.get("admin_pass") or "").strip()
    if new_user:
        cfg["admin_user"] = new_user
    if new_pass:
        cfg["admin_pass_hash"] = generate_password_hash(new_pass)
    save_config(cfg)
    return redirect(url_for('index'))

@app.route('/update_port', methods=['POST'])
def update_port():
    if not session.get('logged_in'): return redirect(url_for('login'))
    cfg = load_config()
    try:
        new_port = int(request.form.get("panel_port"))
        if new_port < 1 or new_port > 65535:
            raise ValueError("out of range")
        cfg["panel_port"] = new_port
        save_config(cfg)
        return redirect(url_for('index', port_changed=1))
    except Exception:
        return redirect(url_for('index', port_error=1))

@app.route('/add', methods=['POST'])
def add():
    if not session.get('logged_in'): return redirect(url_for('login'))
    cfg = load_config()
    cfg["miners"].append({
        "name": request.form.get("name"),
        "url": request.form.get("url").strip(),
        "type": request.form.get("type", "Whatsminer"),
        "username": request.form.get("username"),
        "password": request.form.get("password"),
        "max_temp": float(request.form.get("max_temp")),
        "min_hashrate": float(request.form.get("min_hashrate", 0)),
        "max_fan": float(request.form.get("max_fan")),
        "min_fan": float(request.form.get("min_fan")),
        "enabled": True
    })
    save_config(cfg)
    return redirect(url_for('index'))

@app.route('/edit/<int:miner_id>', methods=['POST'])
def edit(miner_id):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cfg = load_config()
    if 0 <= miner_id < len(cfg["miners"]):
        cfg["miners"][miner_id] = {
            "name": request.form.get("name"),
            "url": request.form.get("url").strip(),
            "type": request.form.get("type", "Whatsminer"),
            "username": request.form.get("username"),
            "password": request.form.get("password"),
            "max_temp": float(request.form.get("max_temp")),
            "min_hashrate": float(request.form.get("min_hashrate", 0)),
            "max_fan": float(request.form.get("max_fan")),
            "min_fan": float(request.form.get("min_fan")),
            "enabled": True
        }
        save_config(cfg)
    return redirect(url_for('index'))

@app.route('/telegram', methods=['POST'])
def telegram_set():
    if not session.get('logged_in'): return redirect(url_for('login'))
    cfg = load_config()
    cfg["bot_token"] = (request.form.get("bot_token") or "").strip()
    cfg["chat_id"] = (request.form.get("chat_id") or "").strip()
    cfg["telegram_proxy"] = (request.form.get("telegram_proxy") or "").strip()
    save_config(cfg)
    return redirect(url_for('index'))

@app.route('/test_telegram', methods=['POST'])
def test_telegram_route():
    if not session.get('logged_in'): return jsonify({"success": False, "message": "دسترسی غیرمجاز"})
    success, msg = send_telegram("🤖 پیام تست موفقیت‌آمیز از پنل مانیتورینگ!")
    return jsonify({"success": success, "message": msg})

@app.route('/delete/<int:miner_id>', methods=['POST'])
def delete(miner_id):
    if not session.get('logged_in'): return redirect(url_for('login'))
    cfg = load_config()
    if 0 <= miner_id < len(cfg["miners"]):
        removed = cfg["miners"].pop(miner_id)
        with state_lock:
            if removed.get("url") in miner_states:
                del miner_states[removed.get("url")]
        save_config(cfg)
    return redirect(url_for('index'))

def build_ssl_context(cert_path, key_path, ca_path=None):
    """
    یک SSLContext می‌سازد. اگر مسیر گواهی CA داده شده و موجود باشد،
    حالت mTLS (احراز هویت گواهی کلاینت) فعال می‌شود؛ یعنی فقط دستگاهی که
    گواهی کلاینتِ امضاشده توسط همین CA را نصب کرده باشد می‌تواند اتصال
    TLS را کامل کند و پنل را ببیند. در صورت هر خطایی در بارگذاری CA،
    به‌جای از کار افتادن کل برنامه، فقط با HTTPS معمولی (بدون گواهی کلاینت) بالا می‌آید.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    if ca_path and os.path.exists(ca_path):
        try:
            context.load_verify_locations(cafile=ca_path)
            context.verify_mode = ssl.CERT_REQUIRED
            print(f"🛡️ mTLS enabled: only devices with a client certificate signed by {os.path.basename(ca_path)} can open the panel.")
        except Exception as e:
            print(f"⚠️ Failed to load CA certificate ({e}). Starting without client-certificate authentication (plain HTTPS only).")
    return context


import socketserver
from werkzeug.serving import BaseWSGIServer

class NonBlockingHandshakeWSGIServer(socketserver.ThreadingMixIn, BaseWSGIServer):
    """
    علت اصلی هنگ‌کردن پنل در حالت HTTPS/mTLS (و نه در حالت HTTP):

    رفتار پیش‌فرض Werkzeug این است که وقتی ssl_context به app.run() داده
    می‌شود، خودِ سوکت "شنودگر" (listening socket) با SSL رپ می‌شود. نتیجه
    این می‌شود که هندشیک TLS هر اتصال (و برای mTLS، بررسی گواهی کلاینت هم)
    داخل تک‌تردِ اصلی حلقه‌ی accept انجام می‌شود -- نه داخل ترد جداگانه‌ی
    هر درخواست -- و هیچ timeout ای هم روی این هندشیک نیست.

    پس اگر فقط یک اتصال (یک پروب شبکه، آنتی‌ویروس، یک تب مرورگر که وسط راه
    قطع شده، یا دستگاهی بدون گواهی معتبر) هندشیک را کامل نکند یا کند باشد،
    کل حلقه‌ی accept قفل می‌شود و دیگر هیچ‌کس -- حتی با گواهی معتبر -- نمی‌تواند
    وصل شود؛ یعنی از دید کاربر کل پنل "هنگ" می‌کند. در حالت HTTP این مشکل
    پیش نمی‌آید چون اصلاً هندشیکی وجود ندارد.

    راه‌حل این کلاس: سوکت شنودگر اصلاً SSL نمی‌شود. هر اتصال، داخل ترد
    مخصوص به خودش (که ThreadingMixIn برایش می‌سازد) رپ SSL و هندشیک می‌شود،
    با یک timeout مشخص (پیش‌فرض 15 ثانیه). اگر یک اتصال گیر کند، گواهی
    نداشته باشد یا نامعتبر باشد، فقط همان یک اتصال بسته می‌شود و بقیه‌ی
    سرور کاملاً سالم و پاسخگو باقی می‌ماند.
    """
    multithread = True
    daemon_threads = True
    handshake_timeout = 15  # ثانیه

    def __init__(self, host, port, app, handler=None, passthrough_errors=False, ssl_context=None, fd=None):
        self._ssl_ctx = ssl_context
        # عمداً ssl_context=None به کلاس پایه پاس داده می‌شود تا سوکت
        # شنودگر رپ نشود؛ رپ کردن را خودمان دستی روی هر اتصال انجام می‌دهیم.
        super().__init__(host, port, app, handler=handler, passthrough_errors=passthrough_errors, ssl_context=None, fd=fd)
        self.ssl_context = ssl_context

    def finish_request(self, request, client_address):
        if self._ssl_ctx is not None:
            try:
                request.settimeout(self.handshake_timeout)
                request = self._ssl_ctx.wrap_socket(request, server_side=True)
                request.settimeout(None)
            except Exception:
                # هندشیک ناقص/کند، گواهی نامعتبر یا نبود گواهی کلاینت.
                # فقط همین یک اتصال رد می‌شود؛ بقیه‌ی سرور دست‌نخورده می‌ماند.
                try:
                    request.close()
                except Exception:
                    pass
                return
        super().finish_request(request, client_address)

def print_credit_banner():
    print("-" * 60)
    print(f"👨‍💻 Developed by Ali Fathinejad | v{APP_VERSION}")
    print("📱 Phone/WhatsApp/Telegram: 09163725383")
    print("📧 Email: alifathinejad1980@gmail.com")
    print("-" * 60)

def print_mode_banner(mode, port):
    """
    mode: 'https_mtls' | 'https' | 'http'
    یک بنر واضح در ترمینال چاپ می‌کند تا معلوم شود سرور الان
    با HTTPS بالا آمده یا HTTP ساده، تا اشتباه گرفته نشود.
    """
    line = "=" * 60
    print(line)
    if mode == "https_mtls":
        print("  🛡️  MODE: HTTPS (SSL) + CLIENT CERTIFICATE (mTLS)")
        print(f"  🔒 Secure & Locked - only devices with the client cert can connect - port {port}")
    elif mode == "https":
        print("  🔒  MODE: HTTPS (SSL) - ENCRYPTED")
        print(f"  🔐 Secure connection - port {port}")
    else:
        print("  ⚠️  MODE: HTTP - NOT ENCRYPTED")
        print(f"  🌐 No SSL certificate found - plain HTTP - port {port}")
    print(line)

if __name__ == '__main__':
    # Detect SSL certificate files next to the script or the EXE
    cert_path = os.path.join(BASE_DIR, "fullchain.pem")
    key_path = os.path.join(BASE_DIR, "privkey.pem")

    # CA certificate file used for client-certificate authentication (mTLS).
    # Place it next to fullchain.pem/privkey.pem, named either ca.pem or ca.crt
    ca_path_pem = os.path.join(BASE_DIR, "ca.pem")
    ca_path_crt = os.path.join(BASE_DIR, "ca.crt")
    ca_path = ca_path_pem if os.path.exists(ca_path_pem) else (ca_path_crt if os.path.exists(ca_path_crt) else None)

    cfg = load_config()
    panel_port = int(cfg.get("panel_port", 2096))

    # threaded=True (HTTP) / custom threaded server (HTTPS): needed so the
    # server can handle multiple simultaneous connections without locking up.
    if os.path.exists(cert_path) and os.path.exists(key_path):
        ssl_ctx = build_ssl_context(cert_path, key_path, ca_path)
        mode = "https_mtls" if ssl_ctx.verify_mode == ssl.CERT_REQUIRED else "https"
        CONNECTION_MODE = mode
        app.config["SESSION_COOKIE_SECURE"] = True  # کوکی سشن فقط روی HTTPS ارسال شود
        if mode == "https_mtls":
            print(f"🛡️ Client certificate authentication ENABLED (CA: {ca_path})")
        print(f"🚀 Starting server with HTTPS (SSL) on port {panel_port} using certificates in: {BASE_DIR}")
        print_mode_banner(mode, panel_port)
        print_credit_banner()
        # از app.run(ssl_context=...) عمداً استفاده نمی‌کنیم، چون آن حالت
        # باعث هنگ‌کردن کل پنل می‌شد (توضیح کامل در docstring کلاس بالا).
        server = NonBlockingHandshakeWSGIServer("0.0.0.0", panel_port, app, ssl_context=ssl_ctx)
        server.serve_forever()
    else:
        CONNECTION_MODE = "http"
        app.config["SESSION_COOKIE_SECURE"] = False
        print("⚠️ SSL certificates (fullchain.pem, privkey.pem) not found. Starting with standard HTTP...")
        print(f"🌐 Starting server with HTTP on port {panel_port}...")
        print_mode_banner("http", panel_port)
        print_credit_banner()
        app.run(host="0.0.0.0", port=panel_port, threaded=True)
