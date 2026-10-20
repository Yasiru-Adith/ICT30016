
import uuid
from urllib.parse import unquote_plus

from edr.core import utc


class SQLiExfiltration:
    rule_id = "SQLI-001"

    def __init__(self, config):
        self.severity = int(config.get("severity", 4))

        if not 1 <= self.severity <= 5:
            raise ValueError("SQLi severity must be between 1 and 5")

    def process(self, value):
        # This rule only handles HTTP request events.
        if value.get("event_type") != "http_request":
            return []

        data = value.get("data", {})

        if data.get("service") != "juice_shop":
            return []

        if data.get("request_path") != "/rest/products/search":
            return []

        # Decode URL-encoded query parameters before checking indicators.
        request_uri = unquote_plus(str(data.get("request_uri", "")))
        query = request_uri.partition("?")[2].lower()

        indicators = (
            "union select",
            "information_schema",
            "sleep(",
            "benchmark(",
        )

        matched = [item for item in indicators if item in query]

        if not matched:
            return []

        detected = utc()

        return [{
            "alert_id": str(uuid.uuid4()),
            "rule_id": self.rule_id,
            "attack": "Possible SQL Injection – Data Exfiltration",
            "severity": self.severity,
            "severity_label": {
                1: "Informational",
                2: "Low",
                3: "Medium",
                4: "High",
                5: "Critical",
            }[self.severity],
            "host": value["host"],
            "source_ip": data.get("source_ip"),
            "target_ip": data.get("target_ip"),
            "target_port": data.get("target_port"),
            "request_path": data.get("request_path"),
            "indicators": matched,
            "detection_timestamp": detected,
            "evidence_event_ids": [value["event_id"]],
            "recommended_action": (
                "Review the HTTP request and associated application evidence "
                "to determine whether SQL injection succeeded."
            ),
        }]
