# Avon connected operations platform

Plain HTML/CSS/JavaScript front end, Python FastAPI API, SQLite persistence, signed device ingestion, and an ESP32/serial gateway. This implements the EOG → NorthMark → Winstead workflow from the HackUTD notes. The original plain white UI, square borders, compact cards, and tables are preserved.

## Start on your laptop

Python 3.12 or newer is recommended. On macOS/Linux, unzip the project, open a terminal in its folder, then:

```bash
bash start.sh
```

Open **http://127.0.0.1:8000**. First startup prints separate usernames and randomly generated passwords for `eog.demo`, `northmark.demo`, and `winstead.demo`. Save these passwords. They are not embedded in the source. Subsequent starts keep existing accounts and database records.

Manual / Windows setup:

```bash
python -m venv .venv
# macOS/Linux: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m backend.manage init
python -m backend.run
```

The backend serves the front end and API from the same origin. No Node build, cloud subscription, LLM key, or paid model call is required. Package downloads are needed on first install. Do not open `frontend/index.html` directly as a file; it requires the server.

## Demo flow

1. Open EOG from the main portal and sign in to EOG. Send a **Pump failure** sample. It travels through the authenticated ingestion path and creates linked cases in all three portals. At the initial sample, the 800 bbl tank is 48% full, the shutdown limit is 90%, and net inflow is 75 bbl/hr: the correct countdown is **268.8 minutes**.
2. Inspect telemetry, history, response costs, assignment, and decision notes. A truck allocation records a decision in the database; contact field dispatch separately.
3. Sign in to NorthMark in another tab. The same case appears with the same case ID. Send a cooling sample to populate temperature, power, PUE, WUE, and cooling incidents. Create a work order.
4. Sign in to Winstead. Inspect linked cases, scope states, device registration, response steps, and the audit chain. The initial Winstead account is an administrator and can add a person to one portal or revoke access.
5. Open the incident room in two portals, select the same case, generate a room key in one tab, and copy it directly to the other tab. Unlock both rooms. Messages are encrypted before sending and can be decrypted with the matching key. The backend never receives the key.
6. Save a handoff, reload, and confirm it remains. Export reports from each portal within that account's scope.

## Stack and responsibilities

| Layer | Implementation | Purpose |
|---|---|---|
| Browser | Existing plain CSS + vanilla JavaScript | Separate logins, dashboards, 4-second refresh, browser message encryption |
| API | FastAPI + Pydantic + Uvicorn | Session and role checks, schema validation, incident workflows |
| Database | SQLite transactions | Accounts, incidents, encrypted telemetry/details, ciphertext rooms, handoffs, audit |
| Edge gateway | Python `gateway.py` | USB/JSONL/simulator input, local rules, HMAC signing, encrypted offline queue |
| Bench device | ESP32 Arduino sketch | Photoresistor, water/IR raw ADC, DHT11 ambient readings, GY-521 acceleration |
| Cryptography | Python cryptography + browser Web Crypto | AES-GCM storage/messages, Ed25519 receipts, HMAC device auth/audit |
| HTTPS | Your reverse proxy, example Caddy config | Transport confidentiality for non-loopback connections |

## Run a continuous sensor simulator

With the server running and your virtual environment active:

```bash
python gateway.py --config data/eog-sim-01.json --mode simulate --scenario pump_failure --count 0 --interval 3
# In a second terminal:
python gateway.py --config data/dc-sim-01.json --mode simulate --scenario cooling --count 0 --interval 4
```

`--count 0` runs until Ctrl+C. Available EOG scenarios: `normal`, `pump_failure`, `flow_mismatch`, `sensor_anomaly`, `sensor_conflict`. NorthMark: `normal`, `cooling`.

For the outage flow, select **Simulate core outage** in NorthMark while the gateway is running. The API returns 503 to ingestion, the gateway continues evaluating locally, and encrypted packets remain queued on disk. Restore ingestion to flush the queue. You can also run:

```bash
python gateway.py --config data/eog-sim-01.json --mode flush
```

A successfully signed receipt must match the packet hash, device, and nonce before the gateway marks delivery complete. Receipt verification failure leaves the packet pending. Authentication failures, expired packets, and invalid data are quarantined for manual review. No queued data is silently deleted. Replay protection is idempotent: an identical signed retry returns its original receipt; a nonce reused with different data is rejected.

## Connect the hardware

See `hardware/README.md` for wiring, calibration boundaries, and serial commands. Provision a distinct device with `source=hardware`; do not reuse simulator credentials. The hardware JSONL adapter accepts measured fields only and never invents tank capacity, flow rate, or CSI observations.

## What is implemented and what is still external

Implemented: authenticated portals, role restrictions, persistent workflow, encrypted record fields, cryptographic packet validation, signed receipts, offline gateway queue, deterministic local/core comparison, client-encrypted room messages, account and device disable, provisioning/key rotation, and audit-chain verification.

External work: physically assembling/calibrating the board; a real CSI capture/model; replacing illustrative detection thresholds; an independent safety/control system; live EOG challenge-file import mapping; Tiger, HR, S3 and IP repository adapters; independent security network/host; production TLS, key management, backups, and deployment monitoring. The generic typed JSONL gateway is the integration boundary for existing data sources. No claim of regulatory certification, air-gap isolation, trained leak classification, or autonomous physical control is made.

ChatGPT/Grok/Gemini were possibilities in the notes, not a configured model. This build deliberately uses deterministic rules to keep costs at zero and offline behavior reproducible. A future model belongs behind `analyze()` with strict structured output; it should not grant permissions or issue equipment commands.

## Deployment and security boundaries

The default server binds to loopback. For remote use, configure HTTPS, set `AVON_SECURE_COOKIE=1`, and set `AVON_ALLOWED_ORIGINS` to the exact HTTPS origin. See `.env.example` and `Caddyfile.example`. The gateway refuses plain HTTP to non-loopback hosts. Environment variables are read from the process, not automatically from `.env` files.

Run a single backend instance for this SQLite prototype. The browser source is public static code; sensitive API data requires a scoped session. Each module has an independent HttpOnly, SameSite=Strict session cookie. Mutations require a CSRF token. Passwords use salted scrypt; session tokens are hashed before storage; login attempts are limited per account and source address. Sessions expire after eight hours and can be revoked by disabling the account. This is not enterprise SSO/MFA.

`data/keys.json` is the local root of trust. The service needs its contents to decrypt records; protect it separately from database backups. Telemetry bodies, incident details/notes, and handoffs are encrypted with AES-256-GCM and random 96-bit nonces. Account names, incident titles, device identities, timestamps, audit metadata, and signed processing receipts are metadata stored without field encryption. This is not full-disk/database encryption. SQLite WAL and filesystem access also need host protection.

Browser room encryption uses a randomly generated 256-bit key shared directly by users. The key is not persisted by the app. Losing it makes old messages unreadable. A disabled user cannot fetch new ciphertext, but cannot be made to forget a key or messages already received; use a new room key after membership changes. Server compromise that changes the delivered browser JavaScript can undermine browser encryption; a separately trusted client/origin is needed for that threat model.

The HMAC audit chain detects changes to retained records. An attacker with the audit key can forge it; a removed tail requires an independently stored chain-head anchor to detect. Winstead is a logically separate portal within this service, not a separate physical air-gapped system. The three portals share case summaries intentionally; EOG cannot query NorthMark's detailed readings or Winstead account administration.

## API and maintenance

The machine-readable API schema is available at `/openapi.json`.

| Endpoint | Access |
|---|---|
| `POST /api/{portal}/login` | Scoped credentials |
| `GET /api/{portal}/me`, `/state` | That portal session |
| `POST /api/telemetry` | Device signature, active key, timestamp, unique nonce |
| `POST /api/{portal}/simulate` | EOG/NorthMark operator; signed simulator path |
| `POST /api/{portal}/incidents/{id}/action` | Incident belongs to portal; operator/admin |
| `GET/POST /api/{portal}/rooms/{case}` | Portal has a linked incident; write requires operator/admin |
| `POST /api/{portal}/handoff` | Operator/admin |
| `POST /api/northmark/core` | NorthMark operator/admin |
| `POST /api/winstead/users`, `/users/{name}/active` | Winstead admin |
| `POST /api/winstead/devices/{id}/active` | Winstead admin |

Device registration and rotation run locally on the server:

```bash
python -m backend.manage device rig-hardware-01 --module eog --asset 'S1 / Bench sensor' --source hardware
python -m backend.manage device rig-hardware-01 --rotate
```

Rotation invalidates the old key immediately. Copy the new restricted device configuration to its authorized gateway. Pending packets signed with a revoked key are quarantined, not silently re-signed. Keep backups of the database and encryption keys, and establish production key rotation separately; only device signing-key rotation is implemented here.

## Checks

```bash
python -m unittest discover -s tests -v
```

The integration suite exercises scoped logins, CSRF, role restrictions, device authentication, duplicate/nonce handling, signed receipts, linked cases, correct tank units, stale data, ciphertext room access, revocation, key rotation, durable handoffs, audit tampering, and gateway spool encryption. Physical hardware is not available in this environment; the Arduino sketch requires a compile and bench test on your board.

References used for the implementation: [FastAPI cookies](https://fastapi.tiangolo.com/advanced/response-cookies/), [cryptography AEAD](https://cryptography.io/en/latest/hazmat/primitives/aead/), [Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/), [ESP32 ADC](https://docs.espressif.com/projects/arduino-esp32/en/latest/api/adc.html), [Adafruit DHT](https://github.com/adafruit/DHT-sensor-library).

## Verification for this build

Nine backend/gateway integration tests pass, including simulated outage queue recovery, shared-case recurrence, view-only logout, key rotation, encrypted rooms, and audit tamper detection. JavaScript syntax and Python compilation checks pass. The shared portal and EOG login layout were visually reviewed in the browser. Authenticated dashboard interactions were covered through API tests, not a complete browser walkthrough. Gateway HTTP delivery was tested against an in-process API transport; remote TLS and physical serial hardware require your bench test.

A browser cannot reach the central dashboard during a real network outage. The gateway continues local rules and queued capture; a separately hosted local operator UI and physically separate Winstead service remain deployment work.
