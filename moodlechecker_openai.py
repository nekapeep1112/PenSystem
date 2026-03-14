"""
Moodle Custom Build Fingerprinting Agent (OpenAI Version)
Определяет реальную версию и состав кастомной сборки Moodle удалённо.

Что делает:
  - Определяет реальную версию ядра через множество источников
  - Обнаруживает кастомные плагины и темы
  - Анализирует HTTP-заголовки и метаданные
  - Проверяет наличие нестандартных endpoint'ов
  - GPT-4o анализирует всё и делает вывод о составе сборки

Установка:
  pip install requests beautifulsoup4 openai python-dotenv --break-system-packages

Запуск:
  1. Создайте .env файл: OPENAI_API_KEY=sk-...
  2. python moodlechecker_openai.py https://your-moodle.com
"""

import sys
import os
import json
import time
import random
import re
import requests
from bs4 import BeautifulSoup
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin

from dotenv import load_dotenv
from openai import OpenAI

# Загружаем переменные окружения из .env
load_dotenv()

# Инициализация клиента OpenAI
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
MODEL = "gpt-4o"

requests.packages.urllib3.disable_warnings()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


# ══════════════════════════════════════════════
# Структуры данных
# ══════════════════════════════════════════════

@dataclass
class FingerprintResult:
    base_url: str
    # Версия
    version_display: str        = "unknown"   # то что показывает платформа
    version_real: str           = "unknown"   # реальная версия ядра
    build_date: str             = "unknown"
    branch: str                 = "unknown"
    is_custom_build: bool       = False
    custom_indicators: list     = field(default_factory=list)
    # Состав
    custom_plugins: list        = field(default_factory=list)
    custom_themes: list         = field(default_factory=list)
    removed_components: list    = field(default_factory=list)
    # Сервер
    server_software: str        = "unknown"
    php_version: str            = "unknown"
    headers: dict               = field(default_factory=dict)
    # Сырые данные для GPT
    raw_data: dict              = field(default_factory=dict)


# ══════════════════════════════════════════════
# HTTP клиент
# ══════════════════════════════════════════════

class StealthHttp:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False

    def get(self, url: str, **kwargs) -> requests.Response:
        time.sleep(random.uniform(0.8, 2.5))
        kwargs.setdefault("timeout", 15)
        kwargs.setdefault("headers", {})
        kwargs["headers"]["User-Agent"] = random.choice(USER_AGENTS)
        try:
            return self.session.get(url, **kwargs)
        except Exception as e:
            r = requests.Response()
            r.status_code = 0
            r._content = f"[ERROR] {e}".encode()
            return r

http = StealthHttp()

def u(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


# ══════════════════════════════════════════════
# Агент 1: HTTP заголовки и метаданные
# ══════════════════════════════════════════════

def fingerprint_headers(ctx: FingerprintResult):
    print("\n[Headers] Анализирую HTTP-заголовки...")

    r = http.get(ctx.base_url)
    if r.status_code == 0:
        print(f"  ✗ Недоступен: {r.text}")
        return

    # Сохраняем все заголовки
    ctx.headers = dict(r.headers)
    ctx.raw_data["headers"] = dict(r.headers)
    ctx.raw_data["home_html"] = r.text[:5000]

    # Сервер
    ctx.server_software = r.headers.get("Server", "unknown")
    print(f"  Server: {ctx.server_software}")

    # X-Powered-By может раскрыть PHP версию
    powered = r.headers.get("X-Powered-By", "")
    if "PHP" in powered:
        ctx.php_version = powered
        print(f"  PHP: {powered}")

    # Moodle иногда ставит свои заголовки
    for h, v in r.headers.items():
        if "moodle" in h.lower() or "moodle" in v.lower():
            ctx.custom_indicators.append(f"Header: {h}: {v}")

    # Анализ HTML главной страницы
    soup = BeautifulSoup(r.text, "html.parser")

    # meta generator
    meta_gen = soup.find("meta", {"name": "generator"})
    if meta_gen:
        content = meta_gen.get("content", "")
        ctx.version_display = content
        print(f"  Meta generator: {content}")

        # Парсим версию из meta
        match = re.search(r"(\d+\.\d+[\w\.\+]*)", content)
        if match:
            ctx.version_display = match.group(1)

    # Ищем версию в HTML (footer, скрипты)
    version_patterns = [
        r'version["\s:=]+["\']?([\d]+\.[\d]+\.[\d]+[\w\.]*)',
        r'release["\s:=]+["\']?([\d]+\.[\d]+[\w\.]*)',
        r'Moodle\s+([\d]+\.[\d]+\.[\d]+[\w\.]*)',
        r'"version":"([\d]+\.[\d]+\.[\d]+[\w\.]*)"',
        r'MoodleVersion\s*=\s*["\']?([\d\.]+)',
    ]
    for pattern in version_patterns:
        match = re.search(pattern, r.text, re.IGNORECASE)
        if match:
            found = match.group(1)
            if found not in ctx.version_display:
                ctx.custom_indicators.append(f"Version в HTML: {found}")
                if ctx.version_real == "unknown":
                    ctx.version_real = found
            break

    # CSS/JS файлы с версией в URL (cache-busting)
    scripts = soup.find_all("script", src=True)
    for s in scripts[:5]:
        src = s.get("src", "")
        # Moodle добавляет ?ver= или rev= к файлам
        ver_match = re.search(r"[?&](?:ver|rev|v)=([\d]+)", src)
        if ver_match:
            ctx.raw_data["js_cache_ver"] = ver_match.group(1)
            break


# ══════════════════════════════════════════════
# Агент 2: Версия через служебные файлы
# ══════════════════════════════════════════════

def fingerprint_version_files(ctx: FingerprintResult):
    print("\n[Version] Проверяю служебные файлы версии...")

    # Файлы которые могут раскрыть реальную версию
    version_files = [
        ("/lib/upgrade.txt",         "upgrade_txt"),
        ("/version.php",             "version_php"),
        ("/admin/environment.xml",   "environment_xml"),
        ("/lib/moodlelib.php",       "moodlelib"),        # содержит MOODLE_RELEASE
        ("/composer.json",           "composer"),
        ("/package.json",            "package_json"),
        ("/CHANGES.txt",             "changes"),
        ("/README.txt",              "readme"),
        ("/install.php",             "install"),          # раскрывает версию при доступе
    ]

    for path, key in version_files:
        r = http.get(u(ctx.base_url, path))

        if r.status_code == 200 and len(r.text) > 50:
            content = r.text[:2000]
            ctx.raw_data[key] = content
            print(f"  ✓ Доступен: {path} ({len(r.text)} байт)")

            # Ищем версию в файле
            patterns = [
                r'\$release\s*=\s*["\']([^"\']+)',      # version.php
                r'\$version\s*=\s*([\d\.]+)',            # version.php
                r'\$branch\s*=\s*["\']?(\d+)',          # version.php
                r"Moodle\s+([\d]+\.[\d]+\.[\d]+[\w\.]*)",
                r"version\s+([\d]+\.[\d]+\.[\d]+[\w\.]*)",
                r'"version"\s*:\s*"([^"]+)"',            # composer.json
            ]
            for pattern in patterns:
                m = re.search(pattern, content, re.IGNORECASE)
                if m:
                    found = m.group(1).strip()
                    print(f"    → Версия: {found}")
                    if ctx.version_real == "unknown" and re.search(r'\d+\.\d+', found):
                        ctx.version_real = found
                    elif "branch" in pattern.lower():
                        ctx.branch = found
                    break

            # Признаки кастомизации в файлах
            if key == "upgrade_txt":
                # Стандартный upgrade.txt начинается с "=== Moodle X.X ==="
                if "===" not in content and "Moodle" not in content:
                    ctx.is_custom_build = True
                    ctx.custom_indicators.append("upgrade.txt изменён — нестандартное содержимое")

        elif r.status_code == 403:
            print(f"  ⚠ Закрыт (403): {path}")
        else:
            pass  # 404 — нормально


# ══════════════════════════════════════════════
# Агент 3: Кастомные плагины и темы
# ══════════════════════════════════════════════

def fingerprint_plugins(ctx: FingerprintResult):
    print("\n[Plugins] Сканирую кастомные плагины и темы...")

    # Стандартные плагины Moodle — их наличие нормально
    standard_themes = {"boost", "classic", "clean", "more", "bootstrapbase"}

    # Директории кастомизации
    plugin_dirs = [
        "/local/",       # local plugins — самые частые для кастомизации
        "/theme/",       # темы
        "/blocks/",      # блоки
        "/mod/",         # модули активностей
        "/auth/",        # authentication plugins
        "/enrol/",       # enrollment plugins
        "/admin/tool/",  # admin tools
    ]

    for directory in plugin_dirs:
        r = http.get(u(ctx.base_url, directory))

        if r.status_code == 200:
            # Парсим листинг директории или HTML
            soup = BeautifulSoup(r.text, "html.parser")
            links = [a.get("href", "") for a in soup.find_all("a", href=True)]

            # Фильтруем реальные папки плагинов
            plugins = [
                l.strip("/") for l in links
                if l and not l.startswith("?") and not l.startswith("http")
                and not l.startswith("..") and "/" not in l.strip("/")
                and len(l.strip("/")) > 1
            ]

            if plugins:
                if "theme" in directory:
                    custom = [p for p in plugins if p.lower() not in standard_themes]
                    if custom:
                        ctx.custom_themes.extend(custom)
                        print(f"  Кастомные темы: {custom}")
                elif "local" in directory:
                    ctx.custom_plugins.extend(plugins)
                    print(f"  Local plugins: {plugins}")
                    if plugins:
                        ctx.is_custom_build = True
                        ctx.custom_indicators.append(f"Local plugins: {plugins}")

        # Проверяем конкретные кастомные local плагины
        common_custom = [
            "local/w3af", "local/w3", "local/custom",
            "local/api", "local/mobile", "local/sso",
            "local/ldap", "local/saml", "local/oauth",
        ]
        for plugin_path in common_custom:
            r2 = http.get(u(ctx.base_url, plugin_path + "/version.php"))
            if r2.status_code == 200:
                ctx.custom_plugins.append(plugin_path)
                ctx.is_custom_build = True
                # Извлекаем версию плагина
                m = re.search(r'\$plugin->version\s*=\s*([\d]+)', r2.text)
                ver = m.group(1) if m else "unknown"
                ctx.custom_indicators.append(f"Plugin {plugin_path} v{ver}")
                print(f"  ✓ Найден плагин: {plugin_path} (v{ver})")


# ══════════════════════════════════════════════
# Агент 4: JavaScript / RequireJS fingerprint
# ══════════════════════════════════════════════

def fingerprint_javascript(ctx: FingerprintResult):
    print("\n[JS] Анализирую JavaScript для определения версии...")

    # requirejs конфиг содержит версию Moodle
    js_endpoints = [
        "/lib/javascript.php",
        "/lib/requirejs.php/1/lib/requirejs.php",
        "/theme/boost/javascript/loader.js",
    ]

    for path in js_endpoints:
        r = http.get(u(ctx.base_url, path))
        if r.status_code == 200 and len(r.text) > 100:
            ctx.raw_data["js_" + path.split("/")[-1]] = r.text[:1000]

            # Ищем версию в JS
            patterns = [
                r'version["\s:=]+["\']?([\d]+\.[\d]+\.[\d]+[\w\.]*)',
                r'moodleVersion\s*[:=]\s*["\']([^"\']+)',
                r'"release":"([^"]+)"',
            ]
            for pattern in patterns:
                m = re.search(pattern, r.text, re.IGNORECASE)
                if m:
                    found = m.group(1)
                    print(f"  Версия в JS: {found}")
                    if ctx.version_real == "unknown":
                        ctx.version_real = found
                    break
            break

    # config.js иногда содержит данные сборки
    r = http.get(u(ctx.base_url, "/config.js"))
    if r.status_code == 200:
        ctx.raw_data["config_js"] = r.text[:500]
        # Ищем признаки кастомизации
        if "w3" in r.text.lower() or "custom" in r.text.lower():
            ctx.is_custom_build = True
            ctx.custom_indicators.append("config.js содержит признаки кастомизации")


# ══════════════════════════════════════════════
# Агент 5: API и web services fingerprint
# ══════════════════════════════════════════════

def fingerprint_api(ctx: FingerprintResult):
    print("\n[API] Проверяю API endpoints...")

    # Moodle REST API — возвращает версию в ошибке
    r = http.get(
        u(ctx.base_url, "/webservice/rest/server.php"),
        params={"wsfunction": "core_webservice_get_site_info",
                "wstoken": "invalid_token_for_fingerprint",
                "moodlewsrestformat": "json"}
    )

    if r.status_code == 200:
        try:
            data = r.json()
            ctx.raw_data["api_siteinfo"] = data

            # Иногда в ошибке есть версия
            if "debuginfo" in str(data):
                m = re.search(r"(\d+\.\d+\.[\d\.]+)", str(data))
                if m:
                    ctx.version_real = m.group(1)
                    print(f"  Версия из API error: {ctx.version_real}")

            print(f"  Web services: доступны (HTTP 200)")
        except Exception:
            pass

    # Mobile app service — раскрывает больше информации
    r2 = http.get(
        u(ctx.base_url, "/webservice/rest/server.php"),
        params={"wsfunction": "core_webservice_get_site_info",
                "wstoken": "invalid",
                "moodlewsrestformat": "json",
                "service": "moodle_mobile_app"}
    )
    if r2.status_code == 200:
        ctx.raw_data["api_mobile"] = r2.text[:500]

    # Проверяем нестандартные API endpoints (признак кастомной сборки)
    custom_apis = [
        "/webservice/rest/server.php?wsfunction=local_",
        "/api/v1/",
        "/api/v2/",
        "/local/api/",
    ]
    for api_path in custom_apis:
        r3 = http.get(u(ctx.base_url, api_path))
        if r3.status_code not in [404, 0]:
            ctx.is_custom_build = True
            ctx.custom_indicators.append(f"Нестандартный API endpoint: {api_path} (HTTP {r3.status_code})")
            print(f"  ✓ Кастомный API: {api_path}")


# ══════════════════════════════════════════════
# GPT-4o: финальный анализ
# ══════════════════════════════════════════════

def analyze_with_gpt(ctx: FingerprintResult) -> str:
    print("\n[GPT-4o] Анализирую собранные данные...")

    summary = {
        "base_url":           ctx.base_url,
        "version_display":    ctx.version_display,
        "version_real":       ctx.version_real,
        "branch":             ctx.branch,
        "build_date":         ctx.build_date,
        "server":             ctx.server_software,
        "php":                ctx.php_version,
        "is_custom_build":    ctx.is_custom_build,
        "custom_indicators":  ctx.custom_indicators,
        "custom_plugins":     ctx.custom_plugins,
        "custom_themes":      ctx.custom_themes,
        "headers":            ctx.headers,
        "raw_samples": {
            k: v[:500] for k, v in ctx.raw_data.items() if v
        }
    }

    response = client.chat.completions.create(
        model=MODEL,
        max_tokens=2000,
        messages=[
            {
                "role": "system",
                "content": (
                    "Ты эксперт по безопасности и reverse engineering Moodle. "
                    "Проанализируй данные fingerprinting кастомной сборки Moodle.\n\n"
                    "Ответь на вопросы:\n"
                    "1. РЕАЛЬНАЯ ВЕРСИЯ ЯДРА — что за Moodle на самом деле (branch, release)\n"
                    "2. ЧТО ЗНАЧИТ СУФФИКС W3 — твоя лучшая гипотеза основанная на данных\n"
                    "3. СОСТАВ СБОРКИ — какие компоненты кастомизированы, добавлены или удалены\n"
                    "4. АКТУАЛЬНЫЕ CVE — какие из известных уязвимостей Moodle 3.9 реально применимы\n"
                    "   к этой конкретной сборке с учётом её состава\n"
                    "5. УНИКАЛЬНЫЕ РИСКИ — уязвимости специфичные для кастомного кода\n"
                    "6. РЕКОМЕНДАЦИИ — что проверить вручную чтобы уточнить картину\n\n"
                    "Будь конкретным. Если данных недостаточно — скажи что именно нужно собрать."
                )
            },
            {
                "role": "user",
                "content": json.dumps(summary, ensure_ascii=False, indent=2)
            }
        ]
    )

    return response.choices[0].message.content


# ══════════════════════════════════════════════
# Главный запуск
# ══════════════════════════════════════════════

def main():
    # Проверка API ключа
    if not os.getenv("OPENAI_API_KEY"):
        print("ОШИБКА: OPENAI_API_KEY не найден!")
        print("Создайте файл .env с содержимым:")
        print("  OPENAI_API_KEY=sk-...")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Использование: python moodlechecker_openai.py https://your-moodle.com")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")
    ctx = FingerprintResult(base_url=base_url)

    print("=" * 60)
    print("  Moodle Custom Build Fingerprinting Agent (OpenAI)")
    print(f"  Цель: {base_url}")
    print(f"  Время: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 60)

    # Запускаем все агенты
    steps = [
        fingerprint_headers,
        fingerprint_version_files,
        fingerprint_plugins,
        fingerprint_javascript,
        fingerprint_api,
    ]

    for step in steps:
        try:
            step(ctx)
        except Exception as e:
            print(f"  [ERROR] {step.__name__}: {e}")

    # Итог
    print("\n" + "=" * 60)
    print("СОБРАННЫЕ ДАННЫЕ:")
    print("=" * 60)
    print(f"  Версия (показывает):  {ctx.version_display}")
    print(f"  Версия (реальная):    {ctx.version_real}")
    print(f"  Branch:               {ctx.branch}")
    print(f"  Сервер:               {ctx.server_software}")
    print(f"  Кастомная сборка:     {'ДА' if ctx.is_custom_build else 'вероятно нет'}")
    if ctx.custom_indicators:
        print("  Индикаторы кастомизации:")
        for i in ctx.custom_indicators:
            print(f"    → {i}")
    if ctx.custom_plugins:
        print(f"  Кастомные плагины: {ctx.custom_plugins}")
    if ctx.custom_themes:
        print(f"  Кастомные темы:    {ctx.custom_themes}")

    # Анализ GPT-4o
    print("\n" + "=" * 60)
    print("АНАЛИЗ GPT-4o:")
    print("=" * 60)
    analysis = analyze_with_gpt(ctx)
    print(analysis)

    # Сохраняем отчёт
    report_file = f"moodle_fingerprint_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"Moodle Fingerprint Report (OpenAI GPT-4o)\n")
        f.write(f"Цель: {base_url}\n")
        f.write(f"Дата: {datetime.now().isoformat()}\n\n")
        f.write(f"Версия (показывает): {ctx.version_display}\n")
        f.write(f"Версия (реальная):   {ctx.version_real}\n")
        f.write(f"Branch:              {ctx.branch}\n")
        f.write(f"Кастомная сборка:    {ctx.is_custom_build}\n\n")
        f.write("Индикаторы:\n")
        for i in ctx.custom_indicators:
            f.write(f"  - {i}\n")
        f.write("\n" + "=" * 60 + "\nАНАЛИЗ\n" + "=" * 60 + "\n")
        f.write(analysis)
        f.write("\n\n" + "=" * 60 + "\nСЫРЫЕ ДАННЫЕ\n" + "=" * 60 + "\n")
        f.write(json.dumps(ctx.raw_data, ensure_ascii=False, indent=2)[:10000])

    print(f"\nОтчёт сохранён: {report_file}")


if __name__ == "__main__":
    main()
