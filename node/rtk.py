import socket
import threading
import time


class RtkReader:
    def __init__(self, host="127.0.0.1", port=29996, max_age=30):
        self.host = host
        self.port = int(port)
        self.max_age = int(max_age)
        self._lock = threading.Lock()
        self._latest = None

        # NMEA 4.x GSA System-ID:
        # 1 GPS, 2 GLONASS, 3 Galileo, 4 BeiDou
        self._constellations = {
            "gps_satellites": 0,
            "glonass_satellites": 0,
            "galileo_satellites": 0,
            "beidou_satellites": 0,
        }

        # Satelliten für Live-Skyplot.
        # Key = (constellation, PRN)
        self._sky = {}

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def snapshot(self):
        with self._lock:
            value = dict(self._latest) if self._latest else None

        if not value or time.time() - value["observed_at"] > self.max_age:
            return {"valid": False}

        return value

    def _run(self):
        while True:
            try:
                with socket.create_connection((self.host, self.port), timeout=10) as stream:
                    stream.settimeout(30)
                    buffer = b""

                    while True:
                        chunk = stream.recv(4096)
                        if not chunk:
                            break

                        buffer += chunk

                        while b"\n" in buffer:
                            line, buffer = buffer.split(b"\n", 1)
                            self._consume(
                                line.decode("ascii", errors="ignore").strip()
                            )

            except OSError:
                time.sleep(5)

    def _consume(self, line):
        # UM980 stream may also contain binary RTCM data.
        # PAUL only parses valid NMEA sentences.
        if not line.startswith("$"):
            return

        if "*" not in line or not self._checksum_ok(line):
            return

        if line.startswith("$GNGSA") or line.startswith("$GPGSA"):
            self._consume_gsa(line)
            return

        if (
            line.startswith("$GPGSV")
            or line.startswith("$GLGSV")
            or line.startswith("$GAGSV")
            or line.startswith("$GBGSV")
            or line.startswith("$BDGSV")
        ):
            self._consume_gsv(line)
            return

        if line.startswith("$GNGGA") or line.startswith("$GPGGA"):
            self._consume_gga(line)

    def _consume_gsa(self, line):
        fields = line.split("*")[0].split(",")

        # NMEA 4.x:
        # 0 talker
        # 1 mode
        # 2 fix
        # 3..14 satellite PRNs
        # 15 PDOP
        # 16 HDOP
        # 17 VDOP
        # 18 System-ID
        if len(fields) < 18:
            return

        prns = [value for value in fields[3:15] if value]
        keys = {
            1: "gps_satellites",
            2: "glonass_satellites",
            3: "galileo_satellites",
            4: "beidou_satellites",
        }

        if len(fields) >= 19 and fields[18]:
            try:
                key = keys.get(int(fields[18]))
            except ValueError:
                return
            if not key:
                return
            counts = {key: len(prns)}
        else:
            # PAUL_GSA_NO_SYSTEM_ID_V1: NMEA <= 4.0 (simple USB receivers) has no
            # System-ID. $GPGSA = GPS only; $GNGSA: classify by PRN numbering
            # (1-32 GPS, 65-96 GLONASS, 201-237/401-437 BeiDou, 301-336 Galileo).
            counts = {}
            for value in prns:
                try:
                    prn = int(value)
                except ValueError:
                    continue
                if fields[0] == "$GPGSA" or 1 <= prn <= 32:
                    key = "gps_satellites"
                elif 65 <= prn <= 96:
                    key = "glonass_satellites"
                elif 301 <= prn <= 336:
                    key = "galileo_satellites"
                elif 201 <= prn <= 237 or 401 <= prn <= 437:
                    key = "beidou_satellites"
                else:
                    continue  # SBAS / QZSS / unknown
                counts[key] = counts.get(key, 0) + 1
            if not counts:
                return

        with self._lock:
            for key, count in counts.items():
                self._constellations[key] = count

                # Falls bereits ein GGA-Fix vorhanden ist, Counts sofort aktualisieren.
                if self._latest:
                    self._latest[key] = count

    def _consume_gsv(self, line):
        fields = line.split("*")[0].split(",")
        if len(fields) < 4:
            return

        talker = fields[0]

        constellation = {
            "$GPGSV": "GPS",
            "$GLGSV": "GLONASS",
            "$GAGSV": "Galileo",
            "$GBGSV": "BeiDou",
            "$BDGSV": "BeiDou",
        }.get(talker)

        if not constellation:
            return

        now = time.time()

        # Nach den ersten vier Feldern folgen Satellitenblöcke:
        # PRN, Elevation, Azimuth, SNR
        # Ganz am Ende kann zusätzlich eine Signal-ID stehen.
        values = fields[4:]

        satellites = []

        for i in range(0, len(values) - 3, 4):
            prn = values[i]
            elevation = values[i + 1]
            azimuth = values[i + 2]
            snr = values[i + 3]

            if not prn or not elevation or not azimuth:
                continue

            try:
                prn_i = int(prn)
                elevation_f = float(elevation)
                azimuth_f = float(azimuth)
                snr_f = float(snr) if snr else None
            except ValueError:
                continue

            if not 0 <= elevation_f <= 90:
                continue
            if not 0 <= azimuth_f <= 360:
                continue

            satellites.append(
                (constellation, prn_i, elevation_f, azimuth_f, snr_f)
            )

        with self._lock:
            for constellation, prn, elevation, azimuth, snr in satellites:
                key = (constellation, prn)
                old = self._sky.get(key)

                # Bei mehreren Frequenzen/Signal-IDs denselben Satelliten
                # nur einmal führen. Für die Anzeige stärkste aktuelle SNR.
                if old and now - old["seen_at"] < 5:
                    old_snr = old.get("snr")
                    if snr is not None and (old_snr is None or snr > old_snr):
                        old_snr = snr

                    self._sky[key] = {
                        "constellation": constellation,
                        "prn": prn,
                        "elevation": elevation,
                        "azimuth": azimuth,
                        "snr": old_snr,
                        "seen_at": now,
                    }
                else:
                    self._sky[key] = {
                        "constellation": constellation,
                        "prn": prn,
                        "elevation": elevation,
                        "azimuth": azimuth,
                        "snr": snr,
                        "seen_at": now,
                    }

            # Alte Satelliten entfernen
            cutoff = now - 15
            self._sky = {
                key: value
                for key, value in self._sky.items()
                if value["seen_at"] >= cutoff
            }

    def _consume_gga(self, line):
        fields = line.split("*")[0].split(",")

        if len(fields) < 15:
            return

        try:
            fix_quality = int(fields[6] or 0)
            satellites = int(fields[7] or 0)
            hdop = float(fields[8]) if fields[8] else None
            latitude = self._coordinate(fields[2], fields[3])
            longitude = self._coordinate(fields[4], fields[5])
            altitude = float(fields[9])

            rtk_age = float(fields[13]) if fields[13] else None
            reference_station = fields[14] or None

        except (ValueError, IndexError):
            return

        if fix_quality <= 0:
            return

        with self._lock:
            constellations = dict(self._constellations)

            now = time.time()
            sky_view = []

            for sat in self._sky.values():
                if now - sat["seen_at"] <= 15:
                    sky_view.append({
                        "constellation": sat["constellation"],
                        "prn": sat["prn"],
                        "elevation": sat["elevation"],
                        "azimuth": sat["azimuth"],
                        "snr": sat["snr"],
                    })

            sky_view.sort(
                key=lambda x: (x["constellation"], x["prn"])
            )

            self._latest = {
                "valid": True,
                "fix_quality": fix_quality,
                "satellites": satellites,
                "latitude": latitude,
                "longitude": longitude,
                "altitude_m": altitude,
                "hdop": hdop,
                "rtk_age": rtk_age,
                "reference_station": reference_station,
                "gps_satellites": constellations["gps_satellites"],
                "glonass_satellites": constellations["glonass_satellites"],
                "galileo_satellites": constellations["galileo_satellites"],
                "beidou_satellites": constellations["beidou_satellites"],
                "sky_view": sky_view,
                "observed_at": int(time.time()),
            }

    @staticmethod
    def _coordinate(value, hemisphere):
        raw = float(value)
        degrees = int(raw // 100)
        result = degrees + (raw - degrees * 100) / 60
        return -result if hemisphere in ("S", "W") else result

    @staticmethod
    def _checksum_ok(line):
        if not line.startswith("$") or "*" not in line[1:]:
            return False

        body, checksum = line[1:].split("*", 1)

        if len(checksum) < 2:
            return False

        value = 0

        for char in body.encode("ascii"):
            value ^= char

        try:
            return value == int(checksum[:2], 16)
        except ValueError:
            return False
