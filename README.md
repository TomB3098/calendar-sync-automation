# Kalender-Sync: Exchange ↔ iCloud (+ Google)

Script: `sync_exchange_icloud_calendar.py`

## Verhalten

- **Exchange ↔ iCloud**: bidirektional, normale Detail-Synchronisierung.
- **Exchange/iCloud → Google**: Datenschutz-Regel aktiv:
  - gleicher Zeitraum
  - neutraler Titel (Default: `Blocked`)
  - keine sensiblen Detailfelder
- **Google → Exchange/iCloud**: normal mit Details.

Konfliktauflösung (Last-Write-Wins):
- Bei gleicher `sync_id` und kollidierenden Zeitständen gewinnt die **neueste Änderung**.
- Vergleichbare Änderungszeit je Provider:
  - Exchange: `lastModifiedDateTime`
  - Google: `updated`
  - iCloud: `LAST-MODIFIED` oder `DTSTAMP` (Fallback defensiv)
- Gewinner wird in die anderen Provider gespiegelt.

Löschlogik:
- Löschen auf **Exchange** oder **iCloud** wird bidirektional auf die verknüpften Kopien propagiert.
- Löschen eines **nativen Google-Termins** wird auf Exchange/iCloud propagiert.
- Löschen eines reinen **Google-Blocked-Mirror-Termins** löscht die Quelltermine nicht; der Mirror wird bei Bedarf neu aufgebaut.
- Verschwundene Provider-Kopien werden nur dann als echtes Delete interpretiert, wenn die verbleibenden Kopien seit dem letzten erfolgreichen Sync inhaltlich unverändert sind.

Duplikat-/Loop-Schutz:
- stabile Sync-ID pro Event
- Provider-Metadaten:
  - Exchange `singleValueExtendedProperties`
  - iCloud `X-AETHER-SYNC-*` in ICS
  - Google `extendedProperties.private`
- zusätzlicher lokaler State (`CAL_SYNC_STATE_PATH`)
- inhaltsbasiertes Relinking von verwaisten Kopien ohne Metadaten
- automatische Bereinigung mehrfach vorhandener Events mit gleicher `sync_id` pro Provider

## ENV-Konfiguration

### Pflicht (Exchange + iCloud)

```bash
EXCHANGE_TENANT_ID=...
EXCHANGE_CLIENT_ID=...
EXCHANGE_CLIENT_SECRET=...
EXCHANGE_USER=...

ICLOUD_USER=...
ICLOUD_APP_PW=...
ICLOUD_PRINCIPAL_PATH=/.../principal/
ICLOUD_TARGET_CAL_DISPLAY=Kalender
```

### Optional Google (3-Wege aktivieren)

```bash
GOOGLE_SYNC_ENABLED=true
GOOGLE_CALENDAR_ID=primary
GOOGLE_BLOCKED_TITLE=Blocked
```

Google Auth – **eine** Variante reicht:

#### Variante A: OAuth Refresh Token

```bash
GOOGLE_OAUTH_CLIENT_ID=...
GOOGLE_OAUTH_CLIENT_SECRET=...
GOOGLE_OAUTH_REFRESH_TOKEN=...
```

#### Variante B: Service Account

```bash
# Pfad zu JSON oder JSON-String direkt
GOOGLE_SERVICE_ACCOUNT_JSON=/secure/path/google-service-account.json

# optional für Domain-Wide Delegation
GOOGLE_IMPERSONATE_USER=user@deine-domain.tld
```

### Laufzeit

```bash
SYNC_DRY_RUN=false
SYNC_WINDOW_DAYS=365
CAL_SYNC_TIMEOUT_SEC=30
CAL_SYNC_STATE_PATH=/root/.openclaw/workspace/memory/calendar-sync-state.json
```

## Ausführen

```bash
python3 sync_exchange_icloud_calendar.py
```

Dry-Run:

```bash
python3 sync_exchange_icloud_calendar.py --dry-run
```

## Google Setup (Kurz)

### OAuth (User-basiert)
1. Google Cloud Projekt + Calendar API aktivieren.
2. OAuth Client (Desktop/Web) erstellen.
3. Einmal Consent durchführen und Refresh Token generieren.
4. `GOOGLE_OAUTH_*` setzen.

### Service Account
1. Service Account + JSON Key erstellen.
2. Zielkalender mit Service Account teilen **oder** Domain-Wide Delegation nutzen.
3. `GOOGLE_SERVICE_ACCOUNT_JSON` setzen.
4. Bei Delegation optional `GOOGLE_IMPERSONATE_USER` setzen.

## Kurztest Konflikt-Simulation

```bash
python3 -m unittest -v test_sync_exchange_icloud_calendar.py
```

## Logs

Das Script loggt kompakt je Provider:
- `created`
- `updated`
- `deleted`
- `skipped`

und am Ende eine Summary.

Secrets werden nicht in Klartext geloggt.
