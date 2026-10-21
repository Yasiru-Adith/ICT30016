from collections import deque
import uuid

from edr.core import timestamp, utc


class AFW2:
    """AFW2: correlate Juice Shop file-upload requests with a target file change."""

    rule_id = "AFW2-001"

    def __init__(self, config):
        self.window = float(config.get("window_seconds", 10))
        self.target_path = str(config.get("target_path", "/ftp/legal.md"))
        self.severity = int(config.get("severity", 5))

        if self.window <= 0:
            raise ValueError("AFW2 window_seconds must be greater than 0")
        if not 1 <= self.severity <= 5:
            raise ValueError("AFW2 severity must be between 1 and 5")
        if not self.target_path:
            raise ValueError("AFW2 target_path must not be empty")

        # Keep recent upload and file-change events so the rule can correlate
        # evidence even when the two collectors deliver events a little apart.
        self.uploads = deque()
        self.file_changes = deque()
        self.alerted_pairs = set()

    @staticmethod
    def _path_matches(path, target_path):
        if not path:
            return False
        normalised = str(path).replace("\\", "/")
        target = target_path.replace("\\", "/").lstrip("/")
        return normalised.lstrip("/").endswith(target)

    def _age(self, now):
        cutoff = now - self.window
        while self.uploads and timestamp(self.uploads[0]["event_timestamp"]) < cutoff:
            self.uploads.popleft()
        while self.file_changes and timestamp(self.file_changes[0]["event_timestamp"]) < cutoff:
            self.file_changes.popleft()

        # Event IDs are unique and bounded by the same rolling window.
        active_pairs = set()
        for upload in self.uploads:
            for change in self.file_changes:
                active_pairs.add((upload["event_id"], change["event_id"]))
        self.alerted_pairs.intersection_update(active_pairs)

    def _matching_upload(self, file_event):
        file_time = timestamp(file_event["event_timestamp"])
        host = file_event["host"]

        candidates = []
        for upload in self.uploads:
            upload_time = timestamp(upload["event_timestamp"])
            if upload["host"] != host:
                continue
            if abs(file_time - upload_time) <= self.window:
                candidates.append(upload)

        if not candidates:
            return None

        # Prefer the most recent upload before the file modification. If the
        # collector order is reversed, the nearest upload in time is used.
        candidates.sort(
            key=lambda item: abs(file_time - timestamp(item["event_timestamp"]))
        )
        return candidates[0]

    def _matching_file(self, upload_event):
        upload_time = timestamp(upload_event["event_timestamp"])
        host = upload_event["host"]

        candidates = []
        for change in self.file_changes:
            change_time = timestamp(change["event_timestamp"])
            if change["host"] != host:
                continue
            if abs(change_time - upload_time) <= self.window:
                candidates.append(change)

        if not candidates:
            return None

        candidates.sort(
            key=lambda item: abs(upload_time - timestamp(item["event_timestamp"]))
        )
        return candidates[0]

    def _alert(self, upload, change):
        pair = (upload["event_id"], change["event_id"])
        if pair in self.alerted_pairs:
            return []

        self.alerted_pairs.add(pair)
        detected = utc()
        upload_time = timestamp(upload["event_timestamp"])
        change_time = timestamp(change["event_timestamp"])

        return [{
            "alert_id": str(uuid.uuid4()),
            "rule_id": self.rule_id,
            "attack": "Possible Arbitrary File Write 2 (AFW2)",
            "severity": self.severity,
            "severity_label": {
                1: "Informational",
                2: "Low",
                3: "Medium",
                4: "High",
                5: "Critical",
            }[self.severity],
            "host": upload["host"],
            "mitre_technique": "T1190",
            "source_ip": upload["data"].get("source_ip"),
            "target_ip": upload["data"].get("target_ip"),
            "target_port": upload["data"].get("target_port"),
            "request_method": upload["data"].get("request_method"),
            "request_path": upload["data"].get("request_path"),
            "target_file": change["data"].get("path"),
            "window_seconds": self.window,
            "upload_event_timestamp": upload["event_timestamp"],
            "file_change_event_timestamp": change["event_timestamp"],
            "detection_timestamp": detected,
            "attack_to_detection_seconds": timestamp(detected) - min(upload_time, change_time),
            "evidence_event_ids": [upload["event_id"], change["event_id"]],
            "recommended_action": (
                "Review the upload and file-change evidence, verify whether the "
                "target file was legitimately modified, preserve the affected "
                "file for evidence, and restore it from a known-good copy if the "
                "write is confirmed as unauthorised."
            ),
        }]

    def process(self, value):
        event_type = value.get("event_type")
        data = value.get("data", {})

        if value.get("host") is None:
            return []

        try:
            when = timestamp(value["event_timestamp"])
        except (KeyError, TypeError, ValueError):
            return []

        self._age(when)

        # Network evidence: the existing HTTP collector already exposes every
        # HTTP request sent to the configured Juice Shop target.
        if (
            event_type == "http_request"
            and data.get("service") == "juice_shop"
            and data.get("request_method") == "POST"
            and data.get("request_path") == "/file-upload"
        ):
            self.uploads.append(value)
            match = self._matching_file(value)
            if match is not None:
                return self._alert(value, match)
            return []

        # Filesystem evidence: watchdog emits file_modified events. The rule
        # only treats the configured target path as relevant.
        if event_type == "file_modified" and self._path_matches(
            data.get("path"), self.target_path
        ):
            self.file_changes.append(value)
            match = self._matching_upload(value)
            if match is not None:
                return self._alert(match, value)

        return []
