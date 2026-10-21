from pathlib import PurePath
import uuid

from edr.core import utc


class ImproperInputValidation:
    rule_id = "IIV-001"

    def __init__(self, config):
        self.severity = int(config.get("severity", 3))
        self.status_codes = {
            int(code) for code in config.get("status_codes", [500])
        }
        self.allowed_extensions = {
            str(ext).lower() if str(ext).startswith(".") else f".{str(ext).lower()}"
            for ext in config.get("allowed_extensions", [".pdf", ".zip"])
        }
        self.alerted_streams = set()

        if not 1 <= self.severity <= 5:
            raise ValueError("IIV severity must be between 1 and 5")

        if not self.status_codes:
            raise ValueError("IIV status_codes must not be empty")

        if not self.allowed_extensions:
            raise ValueError("IIV allowed_extensions must not be empty")

    def _alert(self, value, reason, filename=None, extension=None):
        data = value.get("data", {})
        detected = utc()

        return {
            "alert_id": str(uuid.uuid4()),
            "rule_id": self.rule_id,
            "attack": "Possible Improper Input Validation – File Upload",
            "severity": self.severity,
            "severity_label": {
                1: "Informational",
                2: "Low",
                3: "Medium",
                4: "High",
                5: "Critical",
            }[self.severity],
            "host": value["host"],
            "mitre_technique": "T1190",
            "source_ip": data.get("source_ip"),
            "target_ip": data.get("target_ip"),
            "target_port": data.get("target_port"),
            "request_path": data.get("request_path"),
            "http_status": data.get("http_status"),
            "upload_filename": filename or data.get("upload_filename"),
            "upload_mime_type": data.get("upload_mime_type"),
            "file_extension": extension,
            "detection_reason": reason,
            "detection_timestamp": detected,
            "evidence_event_ids": [value["event_id"]],
            "recommended_action": (
                "Review the file-upload request and related Juice Shop evidence. "
                "Confirm whether the uploaded file violates the expected file-type "
                "restrictions or whether the request was malformed before containment."
            ),
        }

    def process(self, value):
        data = value.get("data", {})

        if data.get("service") != "juice_shop":
            return []

        if data.get("request_method") != "POST":
            return []

        if data.get("request_path") != "/file-upload":
            return []

        event_type = value.get("event_type")
        stream = str(data.get("tcp_stream", ""))

        # Primary detection: an uploaded filename violates the expected
        # Juice Shop file extension restrictions (.pdf or .zip by default).
        if event_type in {"http_request", "file_upload_metadata"}:
            filename = str(data.get("upload_filename", "")).strip()
            if not filename:
                return []

            extension = PurePath(filename).suffix.lower()
            if extension in self.allowed_extensions:
                return []

            if stream:
                if stream in self.alerted_streams:
                    return []
                self.alerted_streams.add(stream)

            return [self._alert(
                value,
                reason="disallowed_file_extension",
                filename=filename,
                extension=extension or "(none)",
            )]

        # Secondary detection: preserve the already-tested malformed upload
        # behaviour where the /file-upload request results in HTTP 500.
        if event_type == "file_upload_response":
            status = data.get("http_status")
            if status not in self.status_codes:
                return []

            if stream and stream in self.alerted_streams:
                return []

            if stream:
                self.alerted_streams.add(stream)

            filename = data.get("upload_filename")
            extension = PurePath(filename).suffix.lower() if filename else None

            return [self._alert(
                value,
                reason="abnormal_upload_response",
                filename=filename,
                extension=extension,
            )]

        return []
