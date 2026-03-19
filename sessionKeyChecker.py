"""
Session Fixation Checker — CVE-2025-53021
Проверяет: обновляет ли сервер sesskey после входа.

Если sesskey до входа == sesskey после входа — уязвимость подтверждена.
Используйте только со своим аккаунтом.

Установка:
  pip install requests beautifulsoup4 --break-system-packages

Запуск:
  python sesskey_check.py
"""

import requests
import sys
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

TARGET = "https://e.sfu-kras.ru"

def extract_sesskey(html: str) -> str:
    """Извлекает sesskey из HTML страницы."""
    # Вариант 1: в M.cfg JSON
    import re
    m = re.search(r'"sesskey"\s*:\s*"([^"]+)"', html)
    if m:
        return m.group(1)
    # Вариант 2: в hidden input
    soup = BeautifulSoup(html, "html.parser")
    inp = soup.find("input", {"name": "sesskey"})
    if inp:
        return inp.get("value", "")
    return ""

def extract_logintoken(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    inp = soup.find("input", {"name": "logintoken"})
    return inp.get("value", "") if inp else ""

def main():
    print("=" * 55)
    print("  Session Fixation Checker")
    print(f"  Цель: {TARGET}")
    print("=" * 55)

    username = input("Логин (ваш тестовый аккаунт): ").strip()
    password = input("Пароль: ").strip()

    s = requests.Session()
    s.verify = False
    s.headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
    )

    # ── Шаг 1: открываем страницу входа БЕЗ авторизации ──
    print("\n[1] Открываю страницу входа...")
    r1 = s.get(f"{TARGET}/login/index.php")
    if r1.status_code != 200:
        print(f"  ✗ Ошибка: HTTP {r1.status_code}")
        sys.exit(1)

    sesskey_before = extract_sesskey(r1.text)
    logintoken     = extract_logintoken(r1.text)
    cookie_before  = s.cookies.get("MoodleSession", "")

    print(f"  MoodleSession (до входа): {cookie_before}")
    print(f"  sesskey       (до входа): {sesskey_before}")

    if not sesskey_before:
        print("  ! sesskey не найден на странице входа — возможно сайт требует JS")

    # ── Шаг 2: входим ──
    print("\n[2] Выполняю вход...")
    r2 = s.post(
        f"{TARGET}/login/index.php",
        data={
            "username":   username,
            "password":   password,
            "logintoken": logintoken,
            "anchor":     "",
        },
        allow_redirects=True,
    )

    cookie_after = s.cookies.get("MoodleSession", "")
    print(f"  HTTP статус: {r2.status_code}")
    print(f"  URL после входа: {r2.url}")

    # Проверяем успешность входа
    if "login" in r2.url and "username" not in r2.url:
        # Редиректнуло обратно на логин — неверный пароль
        print("  ✗ Вход не выполнен — проверьте логин/пароль")
        sys.exit(1)

    if "Invalid login" in r2.text or "Неверный" in r2.text:
        print("  ✗ Неверные учётные данные")
        sys.exit(1)

    # ── Шаг 3: получаем sesskey после входа ──
    print("\n[3] Получаю sesskey после входа...")
    r3 = s.get(f"{TARGET}/my/")
    sesskey_after = extract_sesskey(r3.text)
    print(f"  MoodleSession (после входа): {cookie_after}")
    print(f"  sesskey       (после входа): {sesskey_after}")

    # ── Вердикт ──
    print("\n" + "=" * 55)
    print("РЕЗУЛЬТАТ:")
    print("=" * 55)

    # Проверка 1: обновился ли MoodleSession cookie
    if cookie_before and cookie_after and cookie_before == cookie_after:
        print("  ✗ MoodleSession НЕ обновился после входа")
        print("    → Session Fixation возможна через cookie")
    elif cookie_before != cookie_after:
        print("  ✓ MoodleSession обновился после входа (хорошо)")

    # Проверка 2: обновился ли sesskey
    if sesskey_before and sesskey_after:
        if sesskey_before == sesskey_after:
            print("  ✗ sesskey НЕ изменился после входа")
            print("    → Уязвимость CVE-2025-53021 ПОДТВЕРЖДЕНА")
            print(f"    → sesskey: {sesskey_before}")
            verdict = "VULNERABLE"
        else:
            print("  ✓ sesskey изменился после входа")
            print("    → Session Fixation через sesskey НЕ работает")
            verdict = "NOT_VULNERABLE"
    else:
        print("  ? sesskey не удалось извлечь автоматически")
        print("    → Требуется ручная проверка в браузере (см. ниже)")
        verdict = "MANUAL_CHECK"

    # ── Инструкция для ручной проверки ──
    print("\n" + "=" * 55)
    print("РУЧНАЯ ПРОВЕРКА В БРАУЗЕРЕ:")
    print("=" * 55)
    print("1. Откройте e.sfu-kras.ru в режиме инкогнито")
    print("2. Откройте DevTools → Console")
    print("3. Введите: M.cfg.sesskey")
    print("   Запишите значение — это sesskey ДО входа")
    print("4. Войдите в аккаунт")
    print("5. Снова введите в Console: M.cfg.sesskey")
    print("   Если значение то же — уязвимость подтверждена")

    return verdict

if __name__ == "__main__":
    main()