# ESP32 / gateway hookup

The supplied sketch targets a classic ESP32 DevKit, not every ESP32 family variant. Select the matching board in Arduino IDE and install the Adafruit DHT sensor library and its dependencies. The sketch uses `Wire` for the MPU-6050 at address 0x68. It has not been compiled or tested against your physical board.

| Component | Sample pin | Data sent |
|---|---|---|
| Laser photoresistor divider output | GPIO34 / ADC | `laser_raw`, 12-bit ADC |
| Water-level module analog output | GPIO35 / ADC | `water_raw`, uncalibrated |
| IR module analog output | GPIO32 / ADC | `ir_raw`, uncalibrated |
| DHT11 data | GPIO4 | `ambient_c`, `humidity_pct` |
| GY-521 SDA / SCL | GPIO21 / GPIO22 | `vibration_g`, acceleration-magnitude deviation from 1 g |
| USB serial | 115200 baud | One JSON object per line every 2.5 seconds |

Keep ADC and logic signals within the ESP32's specified input range; do not wire 5 V sensor outputs directly to its GPIOs. Use appropriate sensor supply, dividers/level shifting, common ground, and pull-ups. Power a laser module through its appropriate driver; the sketch does not power or switch it through GPIO. Enclose the optical path for the bench demonstration.

The DHT11 measures ambient air, not water temperature. Raw water/optical/IR readings require calibration; they cannot establish hydrocarbon contamination. The MPU output here is a simple acceleration feature, not a calibrated vibration diagnosis. CSI capture is not implemented by this sketch. An independent CSI pipeline may supply `csi_score` through JSONL after its score meaning has been defined.

## Provision and start

On the backend host:

```bash
python -m backend.manage device bench-01 --module eog --asset 'S1 / Bench sensor' --source hardware --url http://127.0.0.1:8000
```

Securely copy `data/bench-01.json` to the gateway machine. It contains a device HMAC secret and a pinned server receipt verification key. For a remote backend, use its HTTPS URL and a certificate trusted by the gateway.

On the gateway, activate the project environment and install serial support:

```bash
python -m pip install -r requirements-hardware.txt
python gateway.py --config data/bench-01.json --mode serial --serial-port /dev/ttyUSB0 --count 0
```

Use your actual serial port, e.g. `/dev/cu.usbserial-…` on macOS or `COM3` on Windows. The USB connection ends at the gateway; HMAC authenticates the gateway-to-backend data path. A compromised gateway or untrusted serial device can still feed false readings, so this is not hardware attestation.

A pre-existing sensor or data converter can use JSONL instead:

```bash
python gateway.py --config data/bench-01.json --mode jsonl --input readings.jsonl
```

Each line contains readings only:

```json
{"laser_raw":3100,"water_raw":1400,"ir_raw":650,"ambient_c":24.5,"humidity_pct":46,"vibration_g":0.03}
```

For calibrated field telemetry, permitted fields include `tank_pct`, `capacity_bbl`, `inflow_bph`, `pump_bph`, `received_bph`, `pressure_psi`, `oil_bph`, and `gas_mcfph`. Do not convert an uncalibrated water probe to tank percent or invent flow values. Readings are validated for finite values and ranges in `backend/core.py`.

The gateway creates a nonce and collection timestamp, encrypts the packet into a local SQLite spool, signs the exact serialized bytes with HMAC-SHA256, and sends it over HTTPS (or loopback HTTP in development). The backend validates registration, key version, signature, timestamp, schema and nonce before processing. It returns an Ed25519-signed receipt pinned to the packet hash. The gateway verifies that receipt before marking delivery complete.

Offline packets retain their collection timestamp. Packets more than 120 seconds old, or older than the latest reading, are stored as historical and do not create current incidents. Packets older than 24 hours are rejected and quarantined. Keep gateway clocks synchronized. The gateway continues its local heuristic computation when ingestion fails; it does not operate any pump, valve, relay, or safety system.
