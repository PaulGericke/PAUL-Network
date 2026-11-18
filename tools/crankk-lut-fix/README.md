# Crankk LUT-Fix – Sendeleistung korrigieren

*English version below.*

Viele Packet-Forwarder-Vorlagen von Crankk (`crankkster/pktfwd`) haben für SX1302/SX1250-Gateways eine falsche Leistungstabelle (TX gain LUT). Der eingestellte Wert in dBm passt nicht zu dem, was der Funkchip tatsächlich sendet: Das Gateway ist rund **9 dB lauter** als eingestellt und liegt damit über dem EU868-Limit.

Dieses Skript ersetzt **nur** diese Tabelle durch korrekte Werte. Crankk, ChirpStack, Weiterleitungen und PAUL bleiben unverändert. PAUL muss nicht installiert sein.

Anleitung mit Kopier-Buttons: **https://paulnetwork.io/lut**

## Betroffene Geräte

| Crankk-Vorlage | Tabelle |
| --- | --- |
| `rak`, `panther_x2/sx1302`, `bobcat/sx1302`, `nebra/sx1302`, `pisces`, `cotx`, `helium_og`, `tapdo`, `controllino`, `browan_merryiot/sx1302` | **verschoben – zu laut** |
| `panther` (v1), `heltec/sx1302`, `wisgate`, Semtech-Standard | korrekt |
| `sensecap`, `linxdot`, `finestra`, `dusun`, `midas`, `syncrobit` | korrekt (Niedrigleistungs-Tabelle ab 1 dBm) |
| SX1301-Geräte (z. B. ältere Bobcat 300) | anderes Tabellenformat, nicht unterstützt |

## Die Werte in dBm

Format `pa_gain/pwr_idx`. „Real“ = Leistung laut Semtech-Referenztabelle für SX1250 (`sx1302_hal`, `global_conf.json.sx1250.EU868`). Das ist abgeleitet, nicht mit einem Messgerät gemessen.

| eingestellt | Crankk RAK-Vorlage | ≈ real | PAUL-Tabelle | ≈ real |
| ---: | :---: | ---: | :---: | ---: |
| 2 dBm | – | – | `0/5` | 2 dBm |
| 4 dBm | – | – | `0/7` | 4 dBm |
| 6 dBm | – | – | `0/9` | 6 dBm |
| 8 dBm | – | – | `0/11` | 8 dBm |
| 10 dBm | – | – | `0/13` | 10 dBm |
| 11 dBm | – (→ erster Eintrag) | **21 dBm** | `0/14` | 11 dBm |
| 12 dBm | `1/4` | **21 dBm** | `0/15` | 12 dBm |
| 13 dBm | `1/5` | **22 dBm** | `0/16` | 13 dBm |
| 14 dBm | `1/6` | **23 dBm** | `0/17` | 14 dBm |
| 15 dBm | `1/7` | **24 dBm** | `0/19` | 15 dBm |
| 16 dBm | `1/9` | **25 dBm** | `0/20` | 16 dBm |
| 17 dBm | `1/10` | **≈ 25,5 dBm** | `0/22` | 17 dBm |
| 18–27 dBm | `1/11` … `1/20` | **26 … > 27 dBm** | → 17 dBm (Maximum) | 17 dBm |

Wichtig: Fordert ein Server **weniger als 12 dBm** an, nimmt der Forwarder den ersten Tabelleneintrag. Bei der Crankk-Vorlage sind das etwa **21 dBm**. Alle PAUL-Sendungen in EU868 (10–13 dBm angefordert) liefen deshalb mit etwa 21 dBm.

Die Vorlagen `panther_x2` und `bobcat` sind ab 16 dBm um einen Index anders (`1/8` statt `1/9` usw.), die Aussage ist dieselbe.

### Gemessen

RAK-Gateway → Panther-X2-Gateway im Testnetz, gleiche Strecke, PAUL-Beacons und Mesh-Pakete (SF11/SF12), 18.11.2026:

| | RSSI | SNR |
| --- | ---: | ---: |
| vorher (134 Beacons, 7 Tage) | ≈ −100 dBm | ≈ +5 dB |
| nachher (6 Pakete, alle empfangen) | −113 … −116 dBm | −1,8 … −8,5 dB (Median ≈ −6) |

Ergebnis: etwa **11 dB leiser**, erwartet waren etwa 10 dB. Die Verbindung bleibt stabil.

### Rechnung EU868 (Beispiel 3-dBi-Antenne)

Limit 868,0–868,6 MHz: 25 mW ERP = 14 dBm ERP = **16,15 dBm EIRP**.

| | angefordert | Crankk zieht 2 dBi ab | real vorher | real nachher | EIRP nachher |
| --- | ---: | ---: | ---: | ---: | ---: |
| PAUL-Beacon | 13 dBm | 11 dBm | ≈ 21 dBm | 11 dBm | **14 dBm ✓** |
| ChirpStack-Downlink RX1 | 16 dBm | 14 dBm | ≈ 23 dBm | 14 dBm | 17 dBm (Limit 16,15) |

Für ChirpStack-Downlinks zusätzlich `downlink_tx_power` in ChirpStack senken oder in Crankk den echten Antennengewinn eintragen.

## Benutzung

Per SSH auf dem Gateway, als root, Mitglied der docker-Gruppe oder mit sudo:

```sh
curl -fsSL https://node.paulnetwork.io/lut-check | sh    # prüfen, ändert nichts
curl -fsSL https://node.paulnetwork.io/lut-apply | sh    # Fix anwenden
curl -fsSL https://node.paulnetwork.io/lut-status | sh   # Status
curl -fsSL https://node.paulnetwork.io/lut-undo | sh     # rückgängig
```

Ohne curl: `curl -fsSL` durch `wget -qO-` ersetzen. Oder lokal aus diesem Ordner: `sh paul-crankk-safe-lut.sh --check|--apply|--status|--uninstall`.

## Wie es funktioniert

- Crankk lädt beim Start `/data/global_conf.json`, wenn die Datei existiert, und trägt danach selbst ID, Ports, Antennengewinn und Weiterleitungen ein (`PacketForwarder.checkConfig()`/`fixConfig()`).
- Das Skript nimmt die **laufende** Konfiguration, ersetzt nur `SX130x_conf.radio_0.tx_gain_lut` und speichert das Ergebnis als `/data/global_conf.json`. Damit bleibt der Fix auch nach Neustarts erhalten.
- Es fügt den SX1301-Block aus Crankks eigener Vorlage hinzu. Panther und Bobcat starten zuerst als SX1301 und wechseln erst nach „failed to start the concentrator“ auf SX1302.
- Nach dem Neustart wartet es auf „concentrator started“, sonst rollt es automatisch zurück. Es läuft per `nohup` im Hintergrund, damit eine abbrechende SSH-Verbindung den Rollback nicht stoppt.
- Detached-Forwarder (z. B. Meshpoint) und SX1301-Konfigurationen werden übersprungen.
- Zustand: `/data/paul-safe-lut.json`. Rückgängig mit `--uninstall`.

---

# Crankk LUT fix – correct the transmit power

Many Crankk packet forwarder templates (`crankkster/pktfwd`) ship a wrong TX gain LUT for SX1302/SX1250 gateways. The configured dBm value does not match what the radio actually transmits: the gateway is about **9 dB louder** than configured and above the EU868 limit.

This script replaces **only** that table with correct values. Crankk, ChirpStack, forwarding and PAUL stay unchanged. PAUL does not need to be installed.

How-to with copy buttons: **https://paulnetwork.io/lut?lang=en**

## Affected devices

| Crankk template | Table |
| --- | --- |
| `rak`, `panther_x2/sx1302`, `bobcat/sx1302`, `nebra/sx1302`, `pisces`, `cotx`, `helium_og`, `tapdo`, `controllino`, `browan_merryiot/sx1302` | **shifted – too loud** |
| `panther` (v1), `heltec/sx1302`, `wisgate`, Semtech default | correct |
| `sensecap`, `linxdot`, `finestra`, `dusun`, `midas`, `syncrobit` | correct (low-power table from 1 dBm) |
| SX1301 devices (e.g. older Bobcat 300) | different table format, not supported |

## The values in dBm

Format `pa_gain/pwr_idx`. “Real” = power according to the Semtech SX1250 reference table (`sx1302_hal`, `global_conf.json.sx1250.EU868`). This is derived, not measured with an instrument.

| configured | Crankk RAK template | ≈ real | PAUL table | ≈ real |
| ---: | :---: | ---: | :---: | ---: |
| 2 dBm | – | – | `0/5` | 2 dBm |
| 4 dBm | – | – | `0/7` | 4 dBm |
| 6 dBm | – | – | `0/9` | 6 dBm |
| 8 dBm | – | – | `0/11` | 8 dBm |
| 10 dBm | – | – | `0/13` | 10 dBm |
| 11 dBm | – (→ first entry) | **21 dBm** | `0/14` | 11 dBm |
| 12 dBm | `1/4` | **21 dBm** | `0/15` | 12 dBm |
| 13 dBm | `1/5` | **22 dBm** | `0/16` | 13 dBm |
| 14 dBm | `1/6` | **23 dBm** | `0/17` | 14 dBm |
| 15 dBm | `1/7` | **24 dBm** | `0/19` | 15 dBm |
| 16 dBm | `1/9` | **25 dBm** | `0/20` | 16 dBm |
| 17 dBm | `1/10` | **≈ 25.5 dBm** | `0/22` | 17 dBm |
| 18–27 dBm | `1/11` … `1/20` | **26 … > 27 dBm** | → 17 dBm (maximum) | 17 dBm |

Important: if a server requests **less than 12 dBm**, the forwarder uses the first table entry – about **21 dBm** with the Crankk template. All PAUL EU868 transmissions (10–13 dBm requested) therefore went out at about 21 dBm.

The `panther_x2` and `bobcat` templates differ by one index from 16 dBm up (`1/8` instead of `1/9` etc.); the conclusion is the same.

### Measured

RAK gateway → Panther X2 gateway in the test network, same path, PAUL beacons and mesh packets (SF11/SF12), 2026-11-18:

| | RSSI | SNR |
| --- | ---: | ---: |
| before (134 beacons, 7 days) | ≈ −100 dBm | ≈ +5 dB |
| after (6 packets, all received) | −113 … −116 dBm | −1.8 … −8.5 dB (median ≈ −6) |

Result: about **11 dB quieter**, about 10 dB were expected. The link stays stable.

### EU868 calculation (example 3 dBi antenna)

Limit 868.0–868.6 MHz: 25 mW ERP = 14 dBm ERP = **16.15 dBm EIRP**.

| | requested | Crankk subtracts 2 dBi | real before | real after | EIRP after |
| --- | ---: | ---: | ---: | ---: | ---: |
| PAUL beacon | 13 dBm | 11 dBm | ≈ 21 dBm | 11 dBm | **14 dBm ✓** |
| ChirpStack downlink RX1 | 16 dBm | 14 dBm | ≈ 23 dBm | 14 dBm | 17 dBm (limit 16.15) |

For ChirpStack downlinks, also lower `downlink_tx_power` in ChirpStack or enter the real antenna gain in Crankk.

## Usage

Via SSH on the gateway, as root, docker group member or with sudo:

```sh
curl -fsSL https://node.paulnetwork.io/lut-check | sh    # check, changes nothing
curl -fsSL https://node.paulnetwork.io/lut-apply | sh    # apply the fix
curl -fsSL https://node.paulnetwork.io/lut-status | sh   # status
curl -fsSL https://node.paulnetwork.io/lut-undo | sh     # undo
```

Without curl: replace `curl -fsSL` with `wget -qO-`. Or locally from this folder: `sh paul-crankk-safe-lut.sh --check|--apply|--status|--uninstall`.

## How it works

- On start, Crankk loads `/data/global_conf.json` if it exists, and then fills in ID, ports, antenna gain and forwarding itself (`PacketForwarder.checkConfig()`/`fixConfig()`).
- The script takes the **running** configuration, replaces only `SX130x_conf.radio_0.tx_gain_lut` and saves the result as `/data/global_conf.json`. The fix therefore survives restarts.
- It adds the SX1301 block from Crankk's own template. Panther and Bobcat first start as SX1301 and only switch to SX1302 after “failed to start the concentrator”.
- After the restart it waits for “concentrator started”, otherwise it rolls back automatically. It runs in the background via `nohup`, so a dropped SSH session cannot stop the rollback.
- Detached forwarders (e.g. Meshpoint) and SX1301 configurations are skipped.
- State: `/data/paul-safe-lut.json`. Undo with `--uninstall`.

License: AGPL-3.0, see [LICENSE](../../LICENSE).
