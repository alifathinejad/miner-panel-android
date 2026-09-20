[app]

title = Miner Panel
package.name = minerpanel
package.domain = com.alifathinejad

source.dir = .
source.include_exts = py,png,jpg,json

version = 2.1

# پکیج‌های پایتونی مورد نیاز پنل. همه‌شان یا Pure-Python هستند یا recipe
# آماده در python-for-android دارند (نیازی به کامپایل lxml نداریم چون
# BeautifulSoup با html.parser استفاده شده است).
requirements = python3,flask,werkzeug,jinja2,markupsafe,itsdangerous,click,requests,urllib3,certifi,charset-normalizer,idna,beautifulsoup4,soupsieve

orientation = portrait
fullscreen = 0

# --- بوت‌استرپ webview: به‌جای رابط کاربری Kivy، یک WebView ساده‌ی اندروید
# باز می‌شود که به سرور محلی پایتون (همان Flask) وصل می‌شود -- دقیقاً همان
# داشبورد وبی که روی دسکتاپ می‌بینید.
p4a.bootstrap = webview
p4a.port = 2096

android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,WAKE_LOCK,FOREGROUND_SERVICE
android.api = 33
android.minapi = 24
android.archs = arm64-v8a,armeabi-v7a
android.allow_backup = True

# نکته‌ی مهم (نیاز به تست/بررسی بعد از اولین ساخت):
# از اندروید 9 به بعد، ترافیک HTTP ساده (cleartext) به‌صورت پیش‌فرض مسدود است.
# چون این پنل باید با HTTP ساده به دستگاه‌های ماینر توی شبکه‌ی محلی وصل شود،
# اگر بعد از نصب دیدید اتصال به ماینرها کار نمی‌کند ولی خود اپ باز می‌شود،
# احتمالاً باید مانیفست را برای اجازه‌ی cleartext traffic دستی ویرایش کنید
# (این مورد بین نسخه‌های مختلف Buildozer/python-for-android فرق دارد و باید
# روی گوشی واقعی تست شود).

[buildozer]
log_level = 2
warn_on_root = 1
