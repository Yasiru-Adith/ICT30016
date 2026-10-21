import unittest

from edr.core import event
from edr.collectors.http_auth import AuthenticationCollector
from edr.rules.improper_input import ImproperInputValidation
from edr.rules.registry import load_rules


class TestImproperInputValidation(unittest.TestCase):

    def setUp(self):
        self.rule = ImproperInputValidation({
            "severity": 3,
            "status_codes": [500],
        })

    def make_event(
        self,
        status=500,
        path="/file-upload",
        event_type="file_upload_response"
    ):
        return event(
            "test_http",
            event_type,
            {
                "service": "juice_shop",
                "source_ip": "192.168.241.129",
                "target_ip": "192.168.241.128",
                "target_port": 3000,
                "request_method": "POST",
                "request_uri": path,
                "request_path": path,
                "http_status": status,
            },
        )

    def test_http_500_upload_creates_alert(self):
        value = self.make_event()

        alerts = self.rule.process(value)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "IIV-001")
        self.assertEqual(alerts[0]["severity"], 3)
        self.assertEqual(alerts[0]["http_status"], 500)
        self.assertEqual(
            alerts[0]["evidence_event_ids"],
            [value["event_id"]],
        )

    def test_normal_upload_does_not_alert(self):
        value = self.make_event(status=200)

        self.assertEqual(self.rule.process(value), [])

    def test_other_endpoint_does_not_alert(self):
        value = self.make_event(
            status=500,
            path="/rest/user/login",
        )

        self.assertEqual(self.rule.process(value), [])

    def test_other_event_type_is_ignored(self):
        value = self.make_event(
            event_type="http_request",
        )

        self.assertEqual(self.rule.process(value), [])

    def test_collector_creates_upload_response_event(self):
        collector = AuthenticationCollector(
            "lab",
            "192.168.241.128",
            3000,
        )

        request = (
            "100\t1\t192.168.241.129\t192.168.241.128"
            "\t50000\t3000\tPOST\t/file-upload\t\t1\n"
        )

        response = (
            "101\t1\t192.168.241.128\t192.168.241.129"
            "\t3000\t50000\t\t\t500\t2\n"
        )

        request_event = collector.parse(request)

        self.assertIsNotNone(request_event)
        self.assertEqual(
            request_event["event_type"],
            "http_request"
        )

        response_event = collector.parse(response)

        self.assertIsNotNone(response_event)
        self.assertEqual(
            response_event["event_type"],
            "file_upload_response"
        )
        self.assertEqual(
            response_event["data"]["request_path"],
            "/file-upload"
        )
        self.assertEqual(
            response_event["data"]["http_status"],
            500
        )

    def test_rule_is_registered(self):
        rules = load_rules({
            "IIV-001": {
                "enabled": True,
                "severity": 3,
                "status_codes": [500],
            }
        })

        self.assertEqual(len(rules), 1)
        self.assertEqual(
            rules[0].rule_id,
            "IIV-001"
        )


if __name__ == "__main__":
    unittest.main()