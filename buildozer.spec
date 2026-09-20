[app]

title = Miner Panel
package.name = minerpanel
package.domain = com.alifathinejad

source.dir = .
source.include_exts = py,png,jpg,json

version = 2.1

requirements = python3,flask,werkzeug,jinja2,markupsafe,itsdangerous,click,requests,urllib3,certifi,charset-normalizer,idna,beautifulsoup4,soupsieve

orientation = portrait
fullscreen = 0

p4a.bootstrap = webview
p4a.port = 2096

# نسخه‌ی پایدار و امتحان‌شده‌ی python-for-android که پیش‌فرضش پایتون 3.11
# است (نسخه‌های جدیدتر به‌صورت پیش‌فرض می‌روند سراغ پایتون 3.14 که با ابزار
# pip فعلی مشکل سازگاری دارد و باعث fail شدن Build می‌شود).
p4a.branch = v2024.01.21

android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,WAKE_LOCK,FOREGROUND_SERVICE
android.api = 33
android.minapi = 24
android.archs = arm64-v8a,armeabi-v7a
android.allow_backup = True

[buildozer]
log_level = 2
warn_on_root = 1
