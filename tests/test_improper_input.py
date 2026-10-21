import unittest

from edr.core import event
from edr.collectors.http_auth import AuthenticationCollector, capture_command
from edr.rules.improper_input import ImproperInputValidation
from edr.rules.registry import load_rules


class TestImproperInputValidation(unittest.TestCase):

    def setUp(self):
        self.rule = ImproperInputValidation({
            "severity": 3,
            "status_codes": [500],
            "allowed_extensions": [".pdf", ".zip"],
        })

    def make_event(
        self,
        event_type="http_request",
        status=None,
        path="/file-upload",
        filename=None,
        stream="1",
    ):
        data = {
            "service": "juice_shop",
            "source_ip": "192.168.241.129",
            "target_ip": "192.168.241.128",
            "target_port": 3000,
            "request_method": "POST",
            "request_uri": path,
            "request_path": path,
            "tcp_stream": stream,
        }

        if status is not None:
            data["http_status"] = status
        if filename is not None:
            data["upload_filename"] = filename

        return event("test_http", event_type, data)

    def test_disallowed_txt_upload_creates_alert(self):
        value = self.make_event(filename="test.txt")

        alerts = self.rule.process(value)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "IIV-001")
        self.assertEqual(alerts[0]["detection_reason"], "disallowed_file_extension")
        self.assertEqual(alerts[0]["upload_filename"], "test.txt")
        self.assertEqual(alerts[0]["file_extension"], ".txt")

    def test_allowed_pdf_upload_does_not_alert(self):
        value = self.make_event(filename="report.pdf")
        self.assertEqual(self.rule.process(value), [])

    def test_allowed_zip_upload_does_not_alert(self):
        value = self.make_event(filename="evidence.zip")
        self.assertEqual(self.rule.process(value), [])

    def test_http_500_upload_still_creates_alert(self):
        value = self.make_event(
            event_type="file_upload_response",
            status=500,
            filename="report.pdf",
        )

        alerts = self.rule.process(value)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "IIV-001")
        self.assertEqual(alerts[0]["http_status"], 500)
        self.assertEqual(alerts[0]["detection_reason"], "abnormal_upload_response")

    def test_normal_response_does_not_alert(self):
        value = self.make_event(
            event_type="file_upload_response",
            status=200,
            filename="report.pdf",
        )
        self.assertEqual(self.rule.process(value), [])

    def test_other_endpoint_does_not_alert(self):
        value = self.make_event(
            path="/rest/user/login",
            filename="test.txt",
        )
        self.assertEqual(self.rule.process(value), [])

    def test_same_stream_is_not_alerted_twice(self):
        request = self.make_event(filename="test.txt", stream="22")
        response = self.make_event(
            event_type="file_upload_response",
            status=500,
            filename="test.txt",
            stream="22",
        )

        self.assertEqual(len(self.rule.process(request)), 1)
        self.assertEqual(self.rule.process(response), [])

    def test_collector_extracts_upload_filename(self):
        collector = AuthenticationCollector(
            "lab",
            "192.168.241.128",
            3000,
        )

        request = (
            "100\t1\t192.168.241.129\t192.168.241.128"
            "\t50000\t3000\tPOST\t/file-upload\t\t1"
            "\tform-data; name=\"file\"; filename=\"test.txt\""
            "\ttext/plain\n"
        )

        request_event = collector.parse(request)

        self.assertIsNotNone(request_event)
        self.assertEqual(request_event["event_type"], "http_request")
        self.assertEqual(
            request_event["data"]["upload_filename"],
            "test.txt",
        )
        self.assertEqual(
            request_event["data"]["upload_mime_type"],
            "text/plain",
        )

    def test_collector_handles_metadata_on_later_frame(self):
        collector = AuthenticationCollector(
            "lab",
            "192.168.241.128",
            3000,
        )

        request = (
            "100\t3\t192.168.241.129\t192.168.241.128"
            "\t50000\t3000\tPOST\t/file-upload\t\t1\n"
        )
        metadata = (
            "100.1\t3\t192.168.241.129\t192.168.241.128"
            "\t50000\t3000\t\t\t\t2"
            "\tform-data; name=\"file\"; filename=\"test.txt\""
            "\ttext/plain\n"
        )

        self.assertEqual(
            collector.parse(request)["event_type"],
            "http_request",
        )

        metadata_event = collector.parse(metadata)

        self.assertIsNotNone(metadata_event)
        self.assertEqual(metadata_event["event_type"], "file_upload_metadata")
        self.assertEqual(
            metadata_event["data"]["upload_filename"],
            "test.txt",
        )

    def test_old_ten_field_format_still_works(self):
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

        self.assertEqual(
            collector.parse(request)["event_type"],
            "http_request",
        )
        response_event = collector.parse(response)
        self.assertEqual(response_event["event_type"], "file_upload_response")
        self.assertEqual(response_event["data"]["http_status"], 500)

    def test_capture_command_requests_multipart_fields(self):
        command = capture_command("any", "192.168.241.128", 3000)
        joined = " ".join(command)
        self.assertIn("mime_multipart.header.content-disposition", joined)
        self.assertIn("mime_multipart.header.content-type", joined)
        self.assertIn("mime_multipart", joined)

    def test_rule_is_registered(self):
        rules = load_rules({
            "IIV-001": {
                "enabled": True,
                "severity": 3,
                "status_codes": [500],
                "allowed_extensions": [".pdf", ".zip"],
            }
        })

        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].rule_id, "IIV-001")


if __name__ == "__main__":
    unittest.main()
