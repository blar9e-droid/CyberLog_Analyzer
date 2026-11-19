from collections import deque
from dataclasses import dataclass
from pathlib import Path
import pandas as pd

REQUIRED_COLUMNS = ("timestamp", "source_ip", "username", "status")
VALID_STATUSES = {"SUCCESS", "FAILED"}


@dataclass
class FGDetection:
    source_ip: str
    attempts: int
    window_start: str
    window_end: str


class FGLogAnalyzer:
    def __init__(self):
        self.data = pd.DataFrame(columns=list(REQUIRED_COLUMNS))
        self.detections = []

    def load_csv(self, path):
        source = Path(path)
        if not source.is_file():
            raise FileNotFoundError(f"Nem található a fájl: {source}")
        frame = pd.read_csv(source, dtype={"source_ip": str, "username": str, "status": str}, encoding="utf-8-sig")
        missing = [col for col in REQUIRED_COLUMNS if col not in frame.columns]
        if missing:
            raise ValueError("Hiányzó oszlop(ok): " + ", ".join(missing))
        frame = frame.loc[:, list(REQUIRED_COLUMNS)].copy()
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
        if frame["timestamp"].isna().any():
            raise ValueError("Hibás dátum az események között (ISO dátum/idő szükséges).")
        for col in ("source_ip", "username", "status"):
            if frame[col].isna().any() or frame[col].astype(str).str.strip().eq("").any():
                raise ValueError(f"Üres vagy hiányzó mező: {col}")
            frame[col] = frame[col].astype(str).str.strip()
        frame["status"] = frame["status"].str.upper()
        unknown = set(frame["status"]) - VALID_STATUSES
        if unknown:
            raise ValueError("Ismeretlen státusz: " + ", ".join(sorted(unknown)))
        self.data = frame.sort_values("timestamp").reset_index(drop=True)
        self.detections = []
        return len(self.data)

    def statistics(self):
        counts = self.data["status"].value_counts()
        failed = self.data.loc[self.data["status"].eq("FAILED")]
        top = failed["source_ip"].value_counts().head(10)
        return {
            "total": len(self.data),
            "success": int(counts.get("SUCCESS", 0)),
            "failed": int(counts.get("FAILED", 0)),
            "unique_ips": int(self.data["source_ip"].nunique()),
            "top_ips": [(str(ip), int(count)) for ip, count in top.items()],
        }

    def fg_detect_bruteforce(self, threshold=5, window_seconds=60):
        if threshold < 2 or window_seconds < 1:
            raise ValueError("A küszöb legalább 2, az időablak legalább 1 másodperc legyen.")
        failed = self.data[self.data["status"].eq("FAILED")].sort_values("timestamp")
        results = []
        for ip, group in failed.groupby("source_ip"):
            window = deque()
            first_detected = False
            for stamp in group["timestamp"]:
                window.append(stamp)
                while window and (stamp - window[0]).total_seconds() > window_seconds:
                    window.popleft()
                if len(window) >= threshold and not first_detected:
                    results.append(FGDetection(
                        str(ip), len(window), window[0].strftime("%Y-%m-%d %H:%M:%S"),
                        stamp.strftime("%Y-%m-%d %H:%M:%S")
                    ))
                    first_detected = True
        self.detections = sorted(results, key=lambda row: row.source_ip)
        return self.detections

    def filtered(self, ip_fragment="", status="Összes"):
        frame = self.data
        if ip_fragment.strip():
            frame = frame[frame["source_ip"].str.contains(ip_fragment.strip(), regex=False, case=False)]
        if status in VALID_STATUSES:
            frame = frame[frame["status"].eq(status)]
        return frame

    def export_csv(self, path, ip_fragment="", status="Összes"):
        result = self.filtered(ip_fragment, status)
        result.to_csv(path, index=False, encoding="utf-8-sig", date_format="%Y-%m-%d %H:%M:%S")
        return len(result)
