
import tempfile
import unittest
import time
from pathlib import Path

from edr.core import event, Store
from edr.rules.broken_auth import BrokenAuth
from edr.rules.registry import load_rules
from edr.response import respond
from edr.collectors.http_auth import AuthenticationCollector
from dashboard import status


class Tests(unittest.TestCase):
    def values(self, offsets, source="192.0.2.20"):
        base = time.time() - 20
        return [
            event(
                "test",
                "authentication_failure",
                {
                    "service": "juice_shop",
                    "source_ip": source,
                    "target_ip": "192.0.2.10",
                    "target_port": 3000,
                },
                base + n,
            )
            for n in offsets
        ]

    def test_threshold_persistence_dashboard(self):
        rule = BrokenAuth({})
        values = self.values([0, 2, 4, 6, 8, 9])

        for value in values[:4]:
            self.assertEqual(rule.process(value), [])

        alert = rule.process(values[4])[0]
        self.assertEqual(rule.process(values[5]), [])

        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / "db.sqlite")
            db = Store(path)

            for value in values[:5]:
                db.add("events", value)

            respond(alert, db)
            data = status(path)

            self.assertEqual(
                data["counts"],
                {"events": 5, "alerts": 1, "responses": 1},
            )
            self.assertEqual(data["alerts"][0]["severity"], 3)
            self.assertEqual(
                len(data["alerts"][0]["evidence_event_ids"]), 5
            )
            db.close()

    def test_window_and_isolation(self):
        rule = BrokenAuth({})

        for value in self.values([0, 3, 6, 9, 12]):
            self.assertEqual(rule.process(value), [])

        rule = BrokenAuth({})

        for index, value in enumerate(self.values([0, 1, 2, 3, 4])):
            value["data"]["source_ip"] = str(index)
            self.assertEqual(rule.process(value), [])

    def test_late_event_and_rearm(self):
        rule = BrokenAuth({})
        values = self.values([0, 1, 2, 3, 4, 20, 21, 22, 23, 24])

        alerts = [
            alert
            for value in values
            for alert in rule.process(value)
        ]

        self.assertEqual(len(alerts), 2)
        self.assertEqual(rule.process(values[0]), [])

    def test_collector(self):
        collector = AuthenticationCollector(
            "lab", "192.0.2.10", 3000
        )

        request = (
            "100\t1\t192.0.2.20\t192.0.2.10\t50000\t3000"
            "\tPOST\t/rest/user/login\t\t1\n"
        )
        response = (
            "101\t1\t192.0.2.10\t192.0.2.20\t3000\t50000"
            "\t\t\t401\t2\n"
        )

        request_event = collector.parse(request)
        self.assertIsNotNone(request_event)
        self.assertEqual(request_event["event_type"], "http_request")
        self.assertEqual(
            request_event["data"]["request_path"], "/rest/user/login"
        )

        failure_event = collector.parse(response)
        self.assertIsNotNone(failure_event)
        self.assertEqual(
            failure_event["event_type"], "authentication_failure"
        )
        self.assertEqual(
            failure_event["data"]["service"], "juice_shop"
        )
        self.assertEqual(
            failure_event["data"]["http_status"], 401
        )

        self.assertIsNone(collector.parse(response))

        other_request = collector.parse(
            request.replace("/rest/user/login", "/other")
        )
        self.assertIsNotNone(other_request)
        self.assertEqual(
            other_request["event_type"], "http_request"
        )

        self.assertIsNone(collector.parse(response))

    def test_rule_registration(self):
        rules = load_rules({"BA-001": {"enabled": True}})
        self.assertEqual(len(rules), 1)

        with self.assertRaises(ValueError):
            load_rules({"unknown": {"enabled": True}})


if __name__ == "__main__":
    unittest.main()
