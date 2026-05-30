
"""
╔══════════════════════════════════════════════════════════════╗
║           SKANER BEZPIECZEŃSTWA                              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝


"""

import sys
import time
import json
import argparse
import urllib.parse
import re
import requests
from colorama import Fore, Style, init
init(autoreset=True)

SQLI_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "1 AND 1=1--",
    "' UNION SELECT NULL,NULL--",
    "1; WAITFOR DELAY '0:0:5'--",
    "1 AND SLEEP(0)--",
]

SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"supplied argument is not a valid mysql",

    r"microsoft ole db provider",
    r"odbc sql server driver",
    r"mssql_",
    r"unclosed quotation mark",
    r"syntax error.*?sql",

    r"ora-\d{4,5}",
    r"oracle.*?driver",

    r"pg_query\(\)",
    r"postgresql.*?error",

    r"sqlite_",
    r"sqlite3\.",

    r"sql syntax",
    r"sql error",
    r"database error",
    r"invalid query",
]


XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",

    '"><script>alert(1)</script>',

    "'><script>alert(1)</script>",

    "<img src=x onerror=alert(1)>",

    '"><img src=x onerror=alert(1)>',

    "<svg onload=alert(1)>",

    "javascript:alert(1)",

    "%3Cscript%3Ealert(1)%3C/script%3E",
]



class Znalezisko:

    def __init__(self, typ, parametr, payload, dowod, url_testu, ryzyko):
        self.typ       = typ
        self.parametr  = parametr
        self.payload   = payload
        self.dowod     = dowod
        self.url_testu = url_testu
        self.ryzyko    = ryzyko



def wyslij(sesja, url, timeout=10):
    try:
        return sesja.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.SSLError:
        try:
            import urllib3; urllib3.disable_warnings()
            return sesja.get(url, timeout=timeout, allow_redirects=True, verify=False)
        except Exception:
            return None
    except Exception:
        return None


def testuj_sqli(sesja, url_bazowy, parametry):
    znaleziska = []
    parsed = urllib.parse.urlparse(url_bazowy)

    for param in parametry:
        for payload in SQLI_PAYLOADS:
            nowe_params = dict(parametry)
            nowe_params[param] = payload
            url_testu = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(nowe_params))
            )

            czas_start = time.time()
            resp = wyslij(sesja, url_testu)
            czas_trwania = time.time() - czas_start

            if not resp:
                continue

            tekst = resp.text.lower()

            for wzorzec in SQLI_ERROR_PATTERNS:
                dopasowanie = re.search(wzorzec, tekst, re.IGNORECASE)
                if dopasowanie:
                    znaleziska.append(Znalezisko(
                        typ       = "SQL Injection",
                        parametr  = param,
                        payload   = payload,
                        dowod     = f"Błąd bazy danych: '{dopasowanie.group()[:80]}'",
                        url_testu = url_testu,
                        ryzyko    = "CRITICAL",
                    ))
                    break

            if "sleep" in payload.lower() or "waitfor" in payload.lower():
                if czas_trwania >= 4.5:
                    znaleziska.append(Znalezisko(
                        typ       = "SQL Injection (time-based)",
                        parametr  = param,
                        payload   = payload,
                        dowod     = f"Serwer odpowiedział po {czas_trwania:.1f}s – wygląda na SLEEP()",
                        url_testu = url_testu,
                        ryzyko    = "CRITICAL",
                    ))

    return znaleziska


def testuj_xss(sesja, url_bazowy, parametry):
    znaleziska = []
    parsed = urllib.parse.urlparse(url_bazowy)

    for param in parametry:
        for payload in XSS_PAYLOADS:
            nowe_params = dict(parametry)
            nowe_params[param] = payload
            url_testu = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(nowe_params))
            )

            resp = wyslij(sesja, url_testu)
            if not resp:
                continue

            tekst_odpowiedzi = resp.text

            if payload in tekst_odpowiedzi:
                znaleziska.append(Znalezisko(
                    typ       = "XSS (Reflected)",
                    parametr  = param,
                    payload   = payload,
                    dowod     = "Payload znaleziony dosłownie w odpowiedzi HTML",
                    url_testu = url_testu,
                    ryzyko    = "HIGH",
                ))
                continue

            payload_decoded = urllib.parse.unquote(payload)
            if payload_decoded in tekst_odpowiedzi and payload_decoded != payload:
                znaleziska.append(Znalezisko(
                    typ       = "XSS (Reflected, URL-decoded)",
                    parametr  = param,
                    payload   = payload,
                    dowod     = "Zdekodowany payload znaleziony w odpowiedzi",
                    url_testu = url_testu,
                    ryzyko    = "HIGH",
                ))
                continue

            niebezpieczne_fragmenty = [
                ("<script>",       "Tag <script> nieescapowany"),
                ("onerror=",       "Handler onerror= nieescapowany"),
                ("onload=",        "Handler onload= nieescapowany"),
                ("javascript:",    "URI javascript: nieescapowany"),
                ("alert(",         "Wywołanie alert() nieescapowane"),
            ]
            for fragment, opis in niebezpieczne_fragmenty:
                if fragment in tekst_odpowiedzi.lower():
                    znaleziska.append(Znalezisko(
                        typ       = "XSS (Partial Reflection)",
                        parametr  = param,
                        payload   = payload,
                        dowod     = f"{opis} w odpowiedzi",
                        url_testu = url_testu,
                        ryzyko    = "MEDIUM",
                    ))
                    break

    return znaleziska



def wyciagnij_parametry(url, resp_tekst):

    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))


    if resp_tekst:
        html_names = re.findall(
            r'<(?:input|select|textarea)[^>]+name=["\']([^"\']+)["\']',
            resp_tekst, re.IGNORECASE
        )
        for name in html_names[:8]:
            if name not in params:
                params[name] = "test"

    if not params:
        params = {
            "id":     "1",
            "q":      "test",
            "search": "test",
            "page":   "1",
            "cat":    "1",
            "item":   "1",
        }

    return params



RYZYKO_KOLOR = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH":     Fore.YELLOW + Style.BRIGHT,
    "MEDIUM":   Fore.YELLOW,
}

RYZYKO_OPIS = {
    "CRITICAL": "Natychmiastowa naprawa – możliwe przejęcie bazy danych",
    "HIGH":     "Naprawa w ciągu 7 dni – możliwe wykonanie kodu w przeglądarce ofiary",
    "MEDIUM":   "Naprawa w ciągu 30 dni – częściowa podatność wymaga uwagi",
}

REKOMENDACJE = {
    "SQL Injection": [
        "Używaj zapytań parametrycznych, np.:",
        "  cursor.execute('SELECT * FROM users WHERE id = %s', (id,))",
        "Nigdy nie wstawiaj danych użytkownika bezpośrednio do stringa SQL.",
        "Używaj ORM (SQLAlchemy, Django ORM) z automatycznym escapowaniem.",
        "Nie wyświetlaj użytkownikom surowych błędów bazy danych.",
        "Zasada minimalnych uprawnień: konto DB powinno mieć tylko SELECT/INSERT.",
    ],
    "SQL Injection (time-based)": [
        "Jak wyżej – używaj prepared statements.",
        "Dodatkowo: ogranicz timeout zapytań SQL po stronie bazy.",
    ],
    "XSS (Reflected)": [
        "Escapuj wszystkie dane wyjściowe przed wstawieniem do HTML:",
        "  Python: html.escape(user_input)",
        "  PHP:    htmlspecialchars($input, ENT_QUOTES, 'UTF-8')",
        "  Node:   use DOMPurify or he library",
        "Wdróż Content-Security-Policy: default-src 'self'",
        "Używaj frameworków z automatycznym escapowaniem (React, Jinja2).",
    ],
    "XSS (Reflected, URL-decoded)": [
        "Jak dla XSS Reflected – escapuj dane wyjściowe.",
        "Waliduj dane wejściowe po stronie serwera przed przetworzeniem.",
    ],
    "XSS (Partial Reflection)": [
        "Aplikacja częściowo filtruje dane – filtr jest niekompletny.",
        "Zastąp własny filtr sprawdzoną biblioteką escapowania.",
        "Nie polegaj na blacklistach tagów – używaj whitelisty.",
    ],
}


def generuj_raport_txt(znaleziska, cel, czas_trwania):
    linie = []
    W = 72

    def linia(tekst="", prefix="  "):
        linie.append(prefix + tekst)

    def separator(znak="─"):
        linie.append(znak * W)

    def sekcja(tytul):
        linie.append(f"\n{'─'*3} {tytul} {'─'*(W - len(tytul) - 5)}")

    separator("═")
    linia("RAPORT AUDYTU BEZPIECZEŃSTWA  –  SQLi + XSS", "  ")
    linia(f"OWASP A03:2021  –  Injection", "  ")
    separator("═")
    linia()
    linia(f"Cel          : {cel}")
    linia(f"Data         : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    linia(f"Czas skanu   : {czas_trwania:.1f}s")
    linia(f"Podatności   : {len(znaleziska)}")
    linia()

    if not znaleziska:
        linia("✓ Nie znaleziono podatności SQLi ani XSS.")
        linia("  Pamiętaj: skaner automatyczny nie zastąpi ręcznego pentestingu.")
        linie.append("")
        return "\n".join(linie)

    for ryzyko in ["CRITICAL", "HIGH", "MEDIUM"]:
        grupa = [z for z in znaleziska if z.ryzyko == ryzyko]
        for z in grupa:
            separator("═")
            linia(f"[{z.ryzyko}]  {z.typ}")
            separator("─")
            linia()
            linia(f"Podatny parametr : {z.parametr}")
            linia(f"Użyty payload    : {z.payload[:60]}")
            linia(f"Dowód            : {z.dowod}")
            linia(f"URL testu        : {z.url_testu[:68]}")
            linia()
            linia(f"Priorytet : {RYZYKO_OPIS[z.ryzyko]}")
            linia()

            sekcja("Rekomendacje naprawcze")
            for i, rec in enumerate(REKOMENDACJE.get(z.typ, []), 1):
                linia(f"{i}. {rec}")
            linia()

    sekcja("Plan naprawczy")
    linia()
    krytyczne = [z for z in znaleziska if z.ryzyko == "CRITICAL"]
    wysokie   = [z for z in znaleziska if z.ryzyko == "HIGH"]
    srednie   = [z for z in znaleziska if z.ryzyko == "MEDIUM"]

    if krytyczne:
        linia("▶ NATYCHMIAST (≤ 48h)")
        for z in krytyczne:
            linia(f"  • [{z.parametr}] {z.typ}")
    if wysokie:
        linia("▶ KRÓTKOTERMINOWO (≤ 7 dni)")
        for z in wysokie:
            linia(f"  • [{z.parametr}] {z.typ}")
    if srednie:
        linia("▶ ŚREDNIOTERMINOWO (≤ 30 dni)")
        for z in srednie:
            linia(f"  • [{z.parametr}] {z.typ}")

    linia()
    separator("─")
    linia("Wyniki orientacyjne – zalecany manualny pentest")
    separator("─")
    linie.append("")
    return "\n".join(linie)


def drukuj_baner():
    print(Fore.RED + Style.BRIGHT + """
  ███████╗ ██████╗  █████╗ ███╗  ██╗███████╗██████╗
  ██╔════╝██╔════╝ ██╔══██╗████╗ ██║██╔════╝██╔══██╗
  ███████╗██║      ███████║██╔██╗██║█████╗  ██████╔╝
  ╚════██║██║      ██╔══██║██║╚████║██╔══╝  ██╔══██╗
  ███████║╚██████╗ ██║  ██║██║ ╚███║███████╗██║  ██║
  ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝╚═╝  ╚═╝
""" + Style.RESET_ALL)
    print(Style.DIM + "  SQLi + XSS Scanner  |  OWASP A03:2021\n" + Style.RESET_ALL)


def drukuj_znalezisko_live(z):
    kol = RYZYKO_KOLOR.get(z.ryzyko, "")
    print(f"\n  {kol}[{z.ryzyko}]{Style.RESET_ALL}  {Style.BRIGHT}{z.typ}{Style.RESET_ALL}")
    print(f"  {Style.DIM}Parametr :{Style.RESET_ALL} {z.parametr}")
    print(f"  {Style.DIM}Payload  :{Style.RESET_ALL} {z.payload[:55]}")
    print(f"  {Style.DIM}Dowód    :{Style.RESET_ALL} {z.dowod}")




def skanuj(cel, verbose=False):

    sesja = requests.Session()
    sesja.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
        ),
        "Accept-Language": "pl-PL,pl;q=0.9,en;q=0.8",
    })

    print(f"\n  {Fore.CYAN}→{Style.RESET_ALL} Cel: {Style.BRIGHT}{cel}{Style.RESET_ALL}")

    print(f"  {Fore.CYAN}→{Style.RESET_ALL} Pobieranie strony...", end="", flush=True)
    resp = wyslij(sesja, cel)
    if resp is None:
        print(f"\n  {Fore.RED}✗ Nie można połączyć się z celem{Style.RESET_ALL}")
        sys.exit(1)
    print(f" {Fore.GREEN}HTTP {resp.status_code}{Style.RESET_ALL}")

    parametry = wyciagnij_parametry(cel, resp.text)
    print(f"  {Fore.CYAN}→{Style.RESET_ALL} Parametry do testu: {', '.join(parametry.keys())}")

    wszystkie_znaleziska = []

    print(f"\n  {Style.BRIGHT}[1/2] Testuję SQL Injection...{Style.RESET_ALL}")
    print(f"  {Style.DIM}Payloady: {len(SQLI_PAYLOADS)} | Parametry: {len(parametry)}{Style.RESET_ALL}")

    sqli_wyniki = testuj_sqli(sesja, cel, parametry)
    wszystkie_znaleziska.extend(sqli_wyniki)

    if sqli_wyniki:
        for z in sqli_wyniki:
            drukuj_znalezisko_live(z)
    else:
        print(f"  {Fore.GREEN}✓ Brak oznak SQLi{Style.RESET_ALL}")

    print(f"\n  {Style.BRIGHT}[2/2] Testuję XSS...{Style.RESET_ALL}")
    print(f"  {Style.DIM}Payloady: {len(XSS_PAYLOADS)} | Parametry: {len(parametry)}{Style.RESET_ALL}")

    xss_wyniki = testuj_xss(sesja, cel, parametry)
    wszystkie_znaleziska.extend(xss_wyniki)

    if xss_wyniki:
        for z in xss_wyniki:
            drukuj_znalezisko_live(z)
    else:
        print(f"  {Fore.GREEN}✓ Brak oznak XSS{Style.RESET_ALL}")

    return wszystkie_znaleziska



def main():
    parser = argparse.ArgumentParser(
        prog="skaner",
        description="Skaner SQLi + XSS – OWASP A03:2021",
        epilog="""
Przykłady:
  python skaner.py https://cel.pl
  python skaner.py https://cel.pl?id=1&q=test
  python skaner.py https://cel.pl --output raport.txt
  python skaner.py https://cel.pl --json raport.json
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("cel",    help="URL docelowy (np. https://example.com)")
    parser.add_argument("-o", "--output", metavar="PLIK",
                        help="Zapis raportu TXT do pliku")
    parser.add_argument("-j", "--json",   metavar="PLIK",
                        help="Zapis raportu JSON do pliku")
    parser.add_argument("--no-color", action="store_true",
                        help="Wyłącz kolory w terminalu")
    args = parser.parse_args()

    if args.no_color:
        import colorama; colorama.deinit()

    drukuj_baner()

    cel = args.cel.strip()
    if not cel.startswith(("http://", "https://")):
        cel = "https://" + cel

    start = time.time()
    znaleziska = skanuj(cel)
    czas = time.time() - start

    print(f"\n  {'═'*50}")
    print(f"  {Style.BRIGHT}PODSUMOWANIE{Style.RESET_ALL}")
    print(f"  {'─'*50}")
    print(f"  Czas skanowania : {czas:.1f}s")
    print(f"  Podatności      : {len(znaleziska)}")

    for ryzyko in ["CRITICAL", "HIGH", "MEDIUM"]:
        ile = sum(1 for z in znaleziska if z.ryzyko == ryzyko)
        if ile:
            kol = RYZYKO_KOLOR[ryzyko]
            print(f"    {kol}{ryzyko:<10}{Style.RESET_ALL}  {'█'*ile}  {ile}")
    print()

    raport_txt = generuj_raport_txt(znaleziska, cel, czas)

    sciezka = args.output
    if not sciezka:
        host = urllib.parse.urlparse(cel).netloc.replace(":", "_")
        ts   = time.strftime("%Y%m%d_%H%M%S")
        sciezka = f"raport_{host}_{ts}.txt"

    with open(sciezka, "w", encoding="utf-8") as f:
        f.write(raport_txt)
    print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Raport TXT: {Style.BRIGHT}{sciezka}{Style.RESET_ALL}")

    if args.json:
        dane = {
            "cel": cel,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "czas_s": round(czas, 2),
            "podatnosci": [
                {
                    "typ":       z.typ,
                    "parametr":  z.parametr,
                    "payload":   z.payload,
                    "dowod":     z.dowod,
                    "url_testu": z.url_testu,
                    "ryzyko":    z.ryzyko,
                }
                for z in znaleziska
            ],
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(dane, f, ensure_ascii=False, indent=2)
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Raport JSON: {Style.BRIGHT}{args.json}{Style.RESET_ALL}")

    print()
    if any(z.ryzyko == "CRITICAL" for z in znaleziska):
        sys.exit(2)
    elif znaleziska:
        sys.exit(1)


if __name__ == "__main__":
    main()