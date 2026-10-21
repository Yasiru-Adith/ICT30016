from collections import defaultdict, deque
from urllib.parse import urlsplit
from uuid import uuid4
import re
import socket
import subprocess
import threading

from edr.core import utc as stamp


def identifier():
    return str(uuid4())


BASKET_PATH = re.compile(r'^/rest/basket/(\d+)(?:\?.*)?$')
FILENAME_PATTERN = re.compile(r'filename\*?=(?:UTF-8\'\')?["\']?([^"\';]+)', re.IGNORECASE)


def upload_filename(content_disposition):
    """Extract a multipart upload filename from Content-Disposition."""
    if not content_disposition:
        return None

    match = FILENAME_PATTERN.search(content_disposition)
    if not match:
        return None

    return match.group(1).strip()


class AuthenticationCollector:
    def __init__(self, host, target, port):
        self.host = host
        self.target = target
        self.port = int(port)
        self.pending = defaultdict(deque)

    def parse(self, line):
        values = line.rstrip("\r\n").split("\t")

        # The first 10 fields are the original shared collector format.
        # The final two fields are additive multipart metadata for IIV-001.
        if len(values) < 10:
            return None

        values += [""] * (12 - len(values))
        (
            timestamp,
            stream,
            src,
            dst,
            sport,
            dport,
            method,
            uri,
            status,
            frame,
            content_disposition,
            part_content_type,
        ) = values[:12]

        try:
            observed = float(timestamp)
        except (ValueError, TypeError):
            return None

        filename = upload_filename(content_disposition)

        # IDOR-001: detect access to a Juice Shop basket.
        if method == "GET" and dst == self.target and dport == str(self.port):
            match = BASKET_PATH.match(uri)
            if match:
                return {
                    "schema_version": 1,
                    "source": "http_auth",
                    "event_id": identifier(),
                    "event_type": "basket_access",
                    "event_timestamp": stamp(observed),
                    "collector_timestamp": stamp(),
                    "host": self.host,
                    "data": {
                        "service": "juice_shop",
                        "source_ip": src,
                        "target_ip": self.target,
                        "target_port": self.port,
                        "basket_id": int(match.group(1)),
                        "request_path": uri.split("?")[0],
                        "tcp_stream": stream,
                        "frame_number": frame,
                    },
                }

        # Remove requests that have been waiting too long for a response.
        for key in list(self.pending):
            requests = self.pending[key]
            while requests and observed - requests[0]["observed"] > 60:
                requests.popleft()
            if not requests:
                del self.pending[key]

        # Handle HTTP requests sent to the configured Juice Shop target.
        if method and dst == self.target and dport == str(self.port):
            parsed_path = urlsplit(uri).path

            data = {
                "service": "juice_shop",
                "source_ip": src,
                "target_ip": dst,
                "target_port": self.port,
                "request_method": method,
                "request_uri": uri,
                "request_path": parsed_path,
                "tcp_stream": stream,
                "frame_number": frame,
            }

            # Multipart metadata is included only when TShark exposes it.
            if parsed_path == "/file-upload":
                if filename:
                    data["upload_filename"] = filename
                if part_content_type:
                    data["upload_mime_type"] = part_content_type

            self.pending[stream].append({
                "observed": observed,
                "client": src,
                "target": dst,
                "method": method,
                "uri": uri,
                "frame": frame,
                "upload_filename": filename,
                "upload_mime_type": part_content_type or None,
            })

            return {
                "schema_version": 1,
                "source": "http_auth",
                "event_id": identifier(),
                "event_type": "http_request",
                "event_timestamp": stamp(observed),
                "collector_timestamp": stamp(),
                "host": self.host,
                "data": data,
            }

        # Multipart data can be dissected on a later TCP frame than the HTTP
        # request headers. Update the pending request and emit a dedicated
        # metadata event without changing the existing HTTP event types.
        if (
            filename
            and dst == self.target
            and dport == str(self.port)
            and self.pending.get(stream)
        ):
            request = self.pending[stream][-1]
            request_path = urlsplit(request["uri"]).path

            if request["method"] == "POST" and request_path == "/file-upload":
                request["upload_filename"] = filename
                request["upload_mime_type"] = part_content_type or None

                return {
                    "schema_version": 1,
                    "source": "http_auth",
                    "event_id": identifier(),
                    "event_type": "file_upload_metadata",
                    "event_timestamp": stamp(observed),
                    "collector_timestamp": stamp(),
                    "host": self.host,
                    "data": {
                        "service": "juice_shop",
                        "source_ip": request["client"],
                        "target_ip": request["target"],
                        "target_port": self.port,
                        "request_method": request["method"],
                        "request_uri": request["uri"],
                        "request_path": request_path,
                        "upload_filename": filename,
                        "upload_mime_type": part_content_type or None,
                        "tcp_stream": stream,
                        "frame_number": frame,
                    },
                }

        # Ignore rows that aren't HTTP responses from the target.
        if not status or src != self.target or sport != str(self.port):
            return None

        # Informational responses don't finish the request/response exchange.
        if status.startswith("1"):
            return None

        requests = self.pending.get(stream)
        if not requests:
            return None

        request = requests.popleft()
        if not requests:
            self.pending.pop(stream, None)

        client = request["client"]
        target = request["target"]
        request_method = request["method"]
        request_uri = request["uri"]
        request_frame = request["frame"]
        filename = request.get("upload_filename")
        upload_mime_type = request.get("upload_mime_type")

        # Preserve the existing failed-login event for BA-001.
        if (
            status == "401"
            and request_method == "POST"
            and urlsplit(request_uri).path == "/rest/user/login"
        ):
            return {
                "schema_version": 1,
                "source": "http_auth",
                "event_id": identifier(),
                "event_type": "authentication_failure",
                "event_timestamp": stamp(observed),
                "collector_timestamp": stamp(),
                "host": self.host,
                "data": {
                    "service": "juice_shop",
                    "source_ip": client,
                    "target_ip": target,
                    "target_port": self.port,
                    "http_status": 401,
                    "request_path": "/rest/user/login",
                    "tcp_stream": stream,
                    "frame_number": frame,
                },
            }

        # IIV-001: expose the response for POST /file-upload.
        # This remains additive and does not alter existing rule behaviour.
        if (
            request_method == "POST"
            and urlsplit(request_uri).path == "/file-upload"
        ):
            try:
                http_status = int(status)
            except ValueError:
                return None

            data = {
                "service": "juice_shop",
                "source_ip": client,
                "target_ip": target,
                "target_port": self.port,
                "request_method": request_method,
                "request_uri": request_uri,
                "request_path": "/file-upload",
                "http_status": http_status,
                "tcp_stream": stream,
                "request_frame_number": request_frame,
                "response_frame_number": frame,
            }

            if filename:
                data["upload_filename"] = filename
            if upload_mime_type:
                data["upload_mime_type"] = upload_mime_type

            return {
                "schema_version": 1,
                "source": "http_auth",
                "event_id": identifier(),
                "event_type": "file_upload_response",
                "event_timestamp": stamp(observed),
                "collector_timestamp": stamp(),
                "host": self.host,
                "data": data,
            }

        return None


def capture_command(interface, target, port):
    fields = [
        "frame.time_epoch",
        "tcp.stream",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "http.request.method",
        "http.request.uri",
        "http.response.code",
        "frame.number",
        "mime_multipart.header.content-disposition",
        "mime_multipart.header.content-type",
    ]

    command = [
        "tshark",
        "-l",
        "-n",
        "-i",
        interface,
        "-f",
        f"host {target} and tcp port {port}",
        "-d",
        f"tcp.port=={port},http",
        "-Y",
        "http.request or http.response or mime_multipart",
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "occurrence=f",
    ]

    for field in fields:
        command.extend(["-e", field])

    return command


def run(config, stop, emit, interval):
    collector = AuthenticationCollector(
        socket.gethostname(),
        config["target_ip"],
        config["port"],
    )

    process = subprocess.Popen(
        capture_command(
            config["interface"],
            config["target_ip"],
            config["port"],
        ),
        stdout=subprocess.PIPE,
        stderr=None,
        text=True,
        bufsize=1,
    )

    def terminate():
        stop.wait()
        if process.poll() is None:
            process.terminate()

    threading.Thread(target=terminate, daemon=True).start()

    try:
        for line in process.stdout:
            if stop.is_set():
                break

            value = collector.parse(line)
            if value is not None:
                emit(value)

        return_code = process.wait()
        if return_code != 0 and not stop.is_set():
            raise RuntimeError(
                "TShark failed; check the interface, target IP, "
                "port, and capture permissions."
            )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

        if process.stdout:
            process.stdout.close()
