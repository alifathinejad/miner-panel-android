[app]

title = Miner Panel
package.name = minerpanel
package.domain = com.alifathinejad

source.dir = .
source.include_exts = py,png,jpg,json

version = 2.1

requirements = python3,flask==1.1.4,werkzeug==1.0.1,jinja2==2.11.3,markupsafe==1.1.1,itsdangerous==1.1.0,click==7.1.2,requests,urllib3,certifi,charset-normalizer,idna,beautifulsoup4,soupsieve

orientation = portrait
fullscreen = 0

p4a.bootstrap = webview
p4a.port = 2096
p4a.branch = v2024.01.21

android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,WAKE_LOCK,FOREGROUND_SERVICE
android.api = 33
android.minapi = 24
android.archs = arm64-v8a,armeabi-v7a
android.allow_backup = True

[buildozer]
log_level = 2
warn_on_root = 1
