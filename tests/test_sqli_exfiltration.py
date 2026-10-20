
import unittest

from edr.core import event
from edr.rules.sqli_exfiltration import SQLiExfiltration


class TestSQLiExfiltration(unittest.TestCase):
    def setUp(self):
        self.rule = SQLiExfiltration({"severity": 4})

    def make_event(self, uri, event_type="http_request",
                   service="juice_shop",
                   path="/rest/products/search"):
        return event(
            "test_http",
            event_type,
            {
                "service": service,
                "source_ip": "192.168.241.129",
                "target_ip": "192.168.241.128",
                "target_port": 3000,
                "request_path": path,
                "request_uri": uri,
            },
        )

    def test_union_select_creates_alert(self):
        value = self.make_event(
            "/rest/products/search?q=test%27%29%29%20UNION%20SELECT"
        )

        alerts = self.rule.process(value)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "SQLI-001")
        self.assertEqual(alerts[0]["severity"], 4)
        self.assertEqual(alerts[0]["evidence_event_ids"], [value["event_id"]])

    def test_normal_search_does_not_alert(self):
        value = self.make_event("/rest/products/search?q=orange")
        self.assertEqual(self.rule.process(value), [])

    def test_other_event_type_is_ignored(self):
        value = self.make_event(
            "/rest/products/search?q=UNION%20SELECT",
            event_type="authentication_failure",
        )
        self.assertEqual(self.rule.process(value), [])

    def test_other_endpoint_is_ignored(self):
        value = self.make_event(
            "/rest/user/login?q=UNION%20SELECT",
            path="/rest/user/login",
        )
        self.assertEqual(self.rule.process(value), [])

    def test_other_service_is_ignored(self):
        value = self.make_event(
            "/rest/products/search?q=UNION%20SELECT",
            service="another_service",
        )
        self.assertEqual(self.rule.process(value), [])


if __name__ == "__main__":
    unittest.main()
