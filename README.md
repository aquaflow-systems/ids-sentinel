# ids-sentinel

Intrusion detection for the dosing stage's Modbus/TCP traffic.

## Detection

**Rule-based IDS** (`src/rule_ids.py`) -- passively sniffs traffic to `plc-dosing`
and flags writes from an unauthorized source address or using an unexpected
function code.

Alerts are collected in `src/alert_store.py` and served over HTTP/WebSocket by
`src/api.py`, so `ops-dashboard` can display them live the same way it displays
`plant-sim` and `scada-hmi` state.

Anomaly detection (an Isolation Forest trained on normal-operation data, targeting
pattern-level attacks rather than protocol-level ones) is planned as a second pass,
once real attack traffic exists to validate it against.

## Running standalone

```bash
pip install -r requirements.txt
python -m src.main
```

Serves alerts at http://localhost:8082. Needs `NET_RAW`/`NET_ADMIN` capability to
sniff `control-net` traffic -- see `plant-orchestrator/docker-compose.yml`.

## Tests

```bash
pytest
```

Cover: does the rule flag a write from an unauthorized source, does it flag an
unexpected function code, does it correctly ignore legitimate traffic.