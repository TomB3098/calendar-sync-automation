# Calendar Sync Webapp

Die Anwendung wird von einem reinen Sync-Skript zu einer Webanwendung mit internem Hauptkalender umgebaut.

## Aktueller Stand

Es gibt derzeit zwei Einstiegspunkte:

- `webapp/`: neue FastAPI-Webanwendung mit Login, internem Hauptkalender, Provider-Verwaltung und Sync-Logs
- `sync_exchange_icloud_calendar.py`: bestehende Script-Engine, die weiterhin die Provider- und Sync-Logik liefert

## Bereits umgesetzt

- login-geschuetzte Webanwendung mit lokalem Benutzerkonto
- interner Hauptkalender in SQLite
- Events im Web anlegen, bearbeiten und loeschen
- Google-, Exchange- und iCloud-Verbindungen speichern, aktivieren und deaktivieren
- manueller Sync-Lauf als Hintergrundjob
- Job- und Aktions-Logs
- Locking gegen parallele Sync-Laeufe pro Benutzer
- stale running jobs werden automatisch als `abandoned` markiert
- CSRF-Schutz fuer alle POST-Formulare
- Security-Header und Host-Header-Validierung
- Login-Throttling gegen brute-force Versuche
- Provider-Secrets werden in der Datenbank verschluesselt gespeichert
- Passwort-Hashing mit Argon2, falls die Abhaengigkeit installiert ist

## Sicherheitsmodell

Die Webapp ist jetzt auf einen realistischen Testbetrieb gehaertet:

- Session-Cookies sind `HttpOnly` und konfigurierbar als `Secure`
- CSP, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `nosniff`, COOP und CORP werden gesetzt
- optionaler HTTPS-Redirect und HSTS fuer internet-facing Deployments
- keine offenen API-Dokumentationsendpunkte
- Provider-Zugangsdaten werden nicht mehr im Klartext in `calendar_connections` abgelegt

Wichtig: Das ist ein deutlich besseres Baseline-Hardening, aber keine formale Zertifizierung oder Garantie fuer "alle Sicherheitsstandards".

## Live-Test lokal

1. Virtuelle Umgebung und Abhaengigkeiten installieren:

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

2. Secrets erzeugen:

```bash
python3 scripts/generate_webapp_secrets.py
```

3. `.env.example` als Vorlage verwenden und mindestens diese Werte setzen:

```bash
export CAL_WEBAPP_SECRET='...'
export CAL_WEBAPP_DATA_KEY='...'
```

4. Fuer einen lokalen HTTP-Test:

```bash
export CAL_WEBAPP_ALLOWED_HOSTS='127.0.0.1,localhost'
export CAL_WEBAPP_FORCE_HTTPS='false'
export CAL_WEBAPP_SECURE_COOKIES='false'
export CAL_WEBAPP_SESSION_COOKIE='aether_session'
```

5. Webapp starten:

```bash
.venv/bin/uvicorn run_webapp:app --reload
```

6. Browser:

```text
http://127.0.0.1:8000
```

Beim ersten Start wird unter `/setup` der erste Benutzer angelegt.

## Internet-Facing Test

Wenn du die App hinter einer Domain testen willst:

```bash
export CAL_WEBAPP_ALLOWED_HOSTS='calendar.example.com'
export CAL_WEBAPP_FORCE_HTTPS='true'
export CAL_WEBAPP_SECURE_COOKIES='true'
export CAL_WEBAPP_HSTS_SECONDS='31536000'
export CAL_WEBAPP_SESSION_COOKIE='__Host-aether_session'
```

Empfohlen:

- TLS an Reverse Proxy oder Load Balancer terminieren
- `uvicorn` mit Proxy-Headers korrekt betreiben
- nur die benoetigten Hosts in `CAL_WEBAPP_ALLOWED_HOSTS` eintragen

## Wichtige ENV-Variablen

```bash
CAL_WEBAPP_NAME='Aether Calendar Console'
CAL_WEBAPP_DB_PATH='data/calendar_webapp.sqlite3'
CAL_WEBAPP_SECRET='replace-with-random-secret'
CAL_WEBAPP_DATA_KEY='replace-with-fernet-key'
CAL_WEBAPP_SESSION_COOKIE='aether_session'
CAL_WEBAPP_SESSION_COOKIE_DOMAIN=''
CAL_WEBAPP_SESSION_COOKIE_SAMESITE='lax'
CAL_WEBAPP_CSRF_COOKIE='aether_csrf'
CAL_WEBAPP_SESSION_TTL_HOURS='12'
CAL_WEBAPP_SYNC_WINDOW_DAYS='90'
CAL_WEBAPP_PROVIDER_TIMEOUT_SEC='30'
CAL_WEBAPP_SYNC_JOB_STALE_MINUTES='120'
CAL_WEBAPP_ALLOWED_HOSTS='127.0.0.1,localhost'
CAL_WEBAPP_LOGIN_RATE_LIMIT_ATTEMPTS='5'
CAL_WEBAPP_LOGIN_RATE_LIMIT_WINDOW_MINUTES='15'
CAL_WEBAPP_FORCE_HTTPS='false'
CAL_WEBAPP_SECURE_COOKIES='false'
CAL_WEBAPP_HSTS_SECONDS='0'
```

Eine vollere Vorlage steht in [`.env.example`](/Users/tombecker/Documents/WORKSPACE/calendar-sync-automation/.env.example).

## Architektur

- `webapp/main.py`: FastAPI-App, Security-Middleware, Login, CSRF, HTML-Routen
- `webapp/security.py`: Passwort-Hashing, Session-Signaturen, CSRF- und Secret-Handling
- `webapp/database.py`: SQLite-Schema
- `webapp/repository.py`: Persistenz fuer Benutzer, Verbindungen, Events, Jobs, Logs und Login-Attempts
- `webapp/sync_service.py`: Webapp-Sync-Service mit Background-Job-Start und Running-Job-Locking
- `webapp/templates/`: serverseitig gerenderte Seiten
- `webapp/static/`: Stylesheet

Wichtige Tabellen:

- `users`
- `calendar_connections`
- `internal_events`
- `event_links`
- `sync_jobs`
- `sync_log_entries`
- `auth_login_attempts`

## Tests

Kompletter Lauf in der Projekt-Umgebung:

```bash
.venv/bin/python -m unittest -v
```

Syntax-Check:

```bash
python3 -m py_compile $(rg --files -g '*.py')
```

Hinweis: Wenn `fastapi` oder `cryptography` im System-Python nicht installiert sind, werden die entsprechenden Webapp-Tests unter `python3 -m unittest -v` uebersprungen. In der `.venv` laeuft der volle Satz.

## Legacy-Skript

Das bisherige Script bleibt weiter nutzbar:

```bash
python3 sync_exchange_icloud_calendar.py
python3 sync_exchange_icloud_calendar.py --dry-run
```

Die neue Webapp verwendet dessen Provider-Logik intern weiter.

Wichtige Legacy-Skript-Variablen:

```bash
SYNC_DRY_RUN=false
SYNC_WINDOW_DAYS=365
CAL_SYNC_TIMEOUT_SEC=30
CAL_SYNC_STATE_PATH=/root/.openclaw/workspace/memory/calendar-sync-state.json
SYNC_WRITE_DELAY_MS=500
MAX_WRITES_PER_RUN=500
SYNC_ENABLE_BACKOFF=true
SYNC_BACKOFF_BASE_MS=1000
SYNC_BACKOFF_MAX_MS=15000
```

Schreibmodus/Resilienz im Legacy-Skript:

- Writes laufen strikt sequenziell mit Delay zwischen Operationen (`SYNC_WRITE_DELAY_MS`)
- optionaler Exponential Backoff bei `429/503/507` (`SYNC_ENABLE_BACKOFF`)
- iCloud-`507 Insufficient Storage` wird in eine Retry-Queue im State geschrieben; spaetere Laeufe setzen diese Eintraege fort
- Checkpointing speichert den State nach jedem erfolgreichen Write und bei Retry-Queue-Aenderungen
- Safety-Cap pro Lauf via `MAX_WRITES_PER_RUN`

## Bekannte Grenzen

- noch kein periodischer Scheduler; Sync wird manuell ueber die UI gestartet
- keine OAuth-UI-Flows; Provider-Zugangsdaten werden manuell eingetragen
- Wiederholungen werden derzeit nur basisnah gespeichert und noch nicht vollstaendig provideruebergreifend modelliert
- SQLite reicht fuer den Live-Test, fuer echten Mehrbenutzerbetrieb waere Postgres die bessere Basis
