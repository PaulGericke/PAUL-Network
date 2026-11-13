# PAUL Network – Public Autonomous Uplink Layer

Offenes Community-Funknetz auf LoRa-Basis. Vorhandene LoRa-Gateways senden signierte Beacons, andere Nodes bestätigen den Empfang signiert. Daraus entsteht eine nachprüfbare Netzkarte, auf der Tracker, Sensoren, ein verschlüsselter Gateway-Messenger und ein Mesh laufen.

*An open, community-run LoRa radio network. Gateways broadcast signed beacons, other nodes sign witness reports, and the result is a verifiable live map carrying trackers, sensors, an encrypted gateway-to-gateway messenger and a mesh relay.*

- Website & Live-Karte: https://paulnetwork.io
- Punkte: https://paulnetwork.io/punkte
- Community & Installation: https://discord.gg/r9ZJt3bEc

## Inhalt

| Ordner | Was |
| --- | --- |
| `node/` | PAUL-Node (läuft als Docker-Container auf dem Gateway): Beacons/Witnesses (`protocol.py`, `node.py`), Messenger (`messenger*.py`), Mesh-Weiterleitung (`mesh.py`), GNSS/RTK (`rtk.py`) |
| `host/` | Host-Agent auf dem Gateway: zentrale Updates mit Rollback, WLAN-Hotspot, Hardware-Erkennung |
| `tests/` | Tests für das Mesh |

## Tests

```bash
cd tests && python3 -m unittest test_mesh
```

## Konfiguration

Der Node wird über Umgebungsvariablen konfiguriert, u. a. `COLLECTOR_URL`, `GATEWAY_EUI`, `REGION` (`EU868`, `US915`, `AUTO`) und `DATA_DIR` (Standard `/data`). Optional: `PAUL_LEGACY_COLLECTORS` (kommagetrennte alte Collector-Adressen, die auf den öffentlichen Collector umgeschrieben werden).

## Mitmachen

Gateway einrichten: Gerätemodell im Discord nennen, Invite holen, der Anleitung auf https://paulnetwork.io folgen.

## Lizenz

GNU Affero General Public License v3.0 (AGPL-3.0), siehe [LICENSE](LICENSE). Wer den Code verändert und damit einen Dienst betreibt, muss die Änderungen ebenfalls offenlegen.
