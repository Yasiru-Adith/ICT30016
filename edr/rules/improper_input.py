import uuid

from edr.core import utc


class ImproperInputValidation:
    rule_id = "IIV-001"

    def __init__(self, config):
        self.severity = int(config.get("severity", 3))
        self.status_codes = {
            int(code) for code in config.get("status_codes", [500])
        }

        if not 1 <= self.severity <= 5:
            raise ValueError("IIV severity must be between 1 and 5")

        if not self.status_codes:
            raise ValueError("IIV status_codes must not be empty")

    def process(self, value):
        if value.get("event_type") != "file_upload_response":
            return []

        data = value.get("data", {})

        if data.get("service") != "juice_shop":
            return []

        if data.get("request_method") != "POST":
            return []

        if data.get("request_path") != "/file-upload":
            return []

        status = data.get("http_status")

        if status not in self.status_codes:
            return []

        detected = utc()

        return [{
            "alert_id": str(uuid.uuid4()),
            "rule_id": self.rule_id,
            "attack": "Possible Improper Input Validation – Abnormal File Upload",
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
            "http_status": status,
            "detection_timestamp": detected,
            "evidence_event_ids": [value["event_id"]],
            "recommended_action": (
                "Review the file-upload request and related Juice Shop logs. "
                "Confirm whether the request was malformed or bypassed expected "
                "input restrictions before taking containment action."
            ),
        }]