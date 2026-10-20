
from collections import defaultdict, deque
from urllib.parse import urlsplit
from uuid import uuid4
import socket
import subprocess
import threading

from edr.core import utc as stamp


def identifier():
    return str(uuid4())


class AuthenticationCollector:
    def __init__(self, host, target, port):
        self.host = host
        self.target = target
        self.port = int(port)
        self.pending = defaultdict(deque)

    def parse(self, line):
        values = line.rstrip("\r\n").split("\t")

        if len(values) != 10:
            return None

        timestamp, stream, src, dst, sport, dport, method, uri, status, frame = values

        try:
            observed = float(timestamp)
        except (ValueError, TypeError):
            return None

        # Remove requests that have been waiting too long for a response.
        for key in list(self.pending):
            requests = self.pending[key]
            while requests and observed - requests[0][0] > 60:
                requests.popleft()
            if not requests:
                del self.pending[key]

        # Handle HTTP requests sent to the configured Juice Shop target.
        if method and dst == self.target and dport == str(self.port):
            parsed_path = urlsplit(uri).path

            request_event = {
                "schema_version": 1,
                "source": "http_auth",
                "event_id": identifier(),
                "event_type": "http_request",
                "event_timestamp": stamp(observed),
                "collector_timestamp": stamp(),
                "host": self.host,
                "data": {
                    "service": "juice_shop",
                    "source_ip": src,
                    "target_ip": dst,
                    "target_port": self.port,
                    "request_method": method,
                    "request_uri": uri,
                    "request_path": parsed_path,
                    "tcp_stream": stream,
                    "frame_number": frame,
                },
            }

            # Keep request information to pair it with a later response.
            self.pending[stream].append(
                (observed, src, dst, method, uri, frame)
            )

            return request_event

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

        _, client, target, request_method, request_uri, request_frame = request

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
        "http.request or http.response",
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
