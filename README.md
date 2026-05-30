# 🔍 skaner.py – SQLi + XSS Scanner

Jednoplikowy skaner podatności webaplikacji skupiony na dwóch najgroźniejszych kategoriach wstrzykiwań z listy **OWASP Top 10:2021 (A03 – Injection)**.

---

## ⚡ Szybki start

```bash
pip install requests colorama
python skaner.py https://twoja-strona.pl
```

---

## 📋 Wymagania

| Wymaganie | Wersja |
|-----------|--------|
| Python    | 3.9+   |
| requests  | 2.x    |
| colorama  | 0.4+   |

```bash
pip install requests colorama
```

---

## 🚀 Użycie

### Podstawowy skan
```bash
python skaner.py https://example.com
```

### URL z parametrami (skaner przetestuje je wszystkie)
```bash
python skaner.py "https://example.com/users?id=1&cat=news"
```

### Zapis raportu do pliku tekstowego
```bash
python skaner.py https://example.com --output raport.txt
```

### Zapis raportu JSON (do CI/CD, dalszej analizy)
```bash
python skaner.py https://example.com --json wyniki.json
```

### Wyłączenie kolorów (np. logi serwera, pipe)
```bash
python skaner.py https://example.com --no-color
```

### Pełny przykład
```bash
python skaner.py "https://example.com?id=1" --output raport.txt --json wyniki.json
```

---

## 🧠 Co i jak wykrywa

### SQL Injection (SQLi)

Skaner podmienia każdy parametr URL kolejno na 7 payloadów i analizuje odpowiedź serwera.

**Metoda 1 – Error-based**
Szuka w odpowiedzi wzorców błędów bazy danych. Obsługuje MySQL, MSSQL, Oracle, PostgreSQL, SQLite.

```
Payload:  '
URL:      https://cel.pl/users?id='
Odpowiedź zawiera: "You have an error in your SQL syntax..."
→ CRITICAL: SQL Injection wykryty!
```

**Metoda 2 – Time-based**
Dla payloadów `SLEEP()` / `WAITFOR DELAY` mierzy czas odpowiedzi. Jeśli serwer odpowiada po 4.5s+ – baza wykonała polecenie.

```
Payload:  1; WAITFOR DELAY '0:0:5'--
Czas odpowiedzi: 5.2s  →  CRITICAL: SQL Injection (time-based)!
```

**Używane payloady:**
```
'                           ← łamie składnię SQL
"                           ← wariant z cudzysłowem
' OR '1'='1                 ← bypass logiki logowania
1 AND 1=1--                 ← komentarz SQL
' UNION SELECT NULL,NULL--  ← próba wyciągania danych
1; WAITFOR DELAY '0:0:5'--  ← time-based MSSQL
1 AND SLEEP(0)--            ← time-based MySQL
```

---

### Cross-Site Scripting (XSS)

Skaner wstrzykuje payloady JS do parametrów i sprawdza czy wróciły **nieescapowane** w odpowiedzi.

**Sprawdzenie 1 – Dosłowna refleksja** (najgroźniejsze, HIGH)
```
Payload:  <script>alert('XSS')</script>
Odpowiedź zawiera go dosłownie → przeglądarka wykona skrypt!
```

**Sprawdzenie 2 – Refleksja po URL-dekodowaniu** (HIGH)
```
Payload:  %3Cscript%3Ealert(1)%3C/script%3E
Serwer dekoduje i zwraca: <script>alert(1)</script>
```

**Sprawdzenie 3 – Częściowa refleksja** (MEDIUM)
```
Payload zawiera onerror= lub javascript: nieescapowane w atrybucie HTML
→ filtr aplikacji jest niekompletny
```

**Używane payloady:**
```
<script>alert('XSS')</script>           ← klasyczny
"><script>alert(1)</script>             ← wyjście z atrybutu "
'><script>alert(1)</script>             ← wyjście z atrybutu '
<img src=x onerror=alert(1)>            ← przez zdarzenie HTML
"><img src=x onerror=alert(1)>          ← wariant atrybutu
<svg onload=alert(1)>                   ← SVG (omija wiele filtrów)
javascript:alert(1)                     ← dla kontekstu href=""
%3Cscript%3Ealert(1)%3C/script%3E      ← podwójne kodowanie URL
```

---

## 📊 Format raportu tekstowego

```
════════════════════════════════════════════════════════════════════════
RAPORT AUDYTU BEZPIECZEŃSTWA  –  SQLi + XSS
OWASP A03:2021  –  Injection
════════════════════════════════════════════════════════════════════════
  Cel          : https://example.com?id=1
  Data         : 2026-05-30 18:30:00
  Czas skanu   : 12.4s
  Podatności   : 2
════════════════════════════════════════════════════════════════════════
  [CRITICAL]  SQL Injection
────────────────────────────────────────────────────────────────────────
  Podatny parametr : id
  Użyty payload    : '
  Dowód            : Błąd bazy danych: 'you have an error in your sql...'
  URL testu        : https://example.com?id='
  Priorytet        : Natychmiastowa naprawa – możliwe przejęcie bazy danych

--- Rekomendacje naprawcze ---
  1. Używaj zapytań parametrycznych (prepared statements)
  2. Nigdy nie wstawiaj danych użytkownika bezpośrednio do stringa SQL
  ...

--- Plan naprawczy ---
  ▶ NATYCHMIAST (≤ 48h)
    • [id] SQL Injection
  ▶ KRÓTKOTERMINOWO (≤ 7 dni)
    • [q] XSS (Reflected)
```

---

## 🔢 Kody wyjścia

| Kod | Znaczenie |
|-----|-----------|
| `0` | Brak podatności |
| `1` | Znaleziono MEDIUM |
| `2` | Znaleziono HIGH lub CRITICAL |

Przydatne w CI/CD:
```bash
python skaner.py https://app.example.com || echo "UWAGA: wykryto podatności!"
```

---

## 🧩 Struktura kodu

```
skaner.py
├── Sekcja 1 – Payloady          (SQLi: 7, XSS: 8)
├── Sekcja 2 – Model danych      (klasa Znalezisko)
├── Sekcja 3 – Wykrywanie        (testuj_sqli, testuj_xss)
├── Sekcja 4 – Ekstrakcja params (z URL + z HTML formularzy)
├── Sekcja 5 – Generator raportów (TXT + JSON)
├── Sekcja 6 – Terminal UI       (kolory, live feedback)
├── Sekcja 7 – Logika skanowania (orchestrator)
└── Sekcja 8 – Argument parser   (CLI)
```

Każda sekcja jest obszernie skomentowana po polsku bezpośrednio w kodzie.

---

## 🛡️ Jak naprawić wykryte podatności

### SQL Injection → Prepared Statements

**❌ Podatny kod:**
```python
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
```

**✅ Bezpieczny kod:**
```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### XSS → Escapowanie wyjścia

**❌ Podatny kod (PHP):**
```php
echo "Szukasz: " . $_GET['q'];
```

**✅ Bezpieczny kod:**
```php
echo "Szukasz: " . htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
```

**✅ Bezpieczny kod (Python):**
```python
import html
print("Szukasz: " + html.escape(user_input))
```

---

## ⚠️ Ważna informacja prawna

Narzędzie służy wyłącznie do **autoryzowanego testowania własnych aplikacji** lub systemów, do których masz pisemną zgodę właściciela.

Testowanie bez zgody jest **nielegalne** i może podlegać odpowiedzialności karnej.

Wyniki są **orientacyjne** – automatyczny skaner nie zastąpi ręcznego pentestingu przez certyfikowanego specjalistę.
