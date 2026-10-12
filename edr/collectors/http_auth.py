from collections import defaultdict, deque
from edr.core import utc as stamp
from uuid import uuid4
def identifier():
    return str(uuid4())

class AuthenticationCollector:
    def __init__(self, host, target, port):
        self.host, self.target, self.port = host, target, port
        self.pending = defaultdict(deque)

    def parse(self, line):
        values = line.rstrip('\r\n').split('\t')
        if len(values) != 10:
            return None
        timestamp, stream, src, dst, sport, dport, method, uri, status, frame = values
        try:
            observed = float(timestamp)
        except ValueError:
            return None
        # Expire unpaired requests to bound memory in this lab prototype.
        for key in list(self.pending):
            queue = self.pending[key]
            while queue and observed - queue[0][0] > 60:
                queue.popleft()
            if not queue:
                del self.pending[key]
        if method and dst == self.target and dport == str(self.port):
            self.pending[stream].append((observed, src, method, uri))
        if not status or src != self.target or sport != str(self.port):
            return None
        if status.startswith('1'):
            return None
        queue = self.pending.get(stream)
        if not queue:
            return None
        _, client, request_method, request_uri = queue.popleft()
        if status != '401' or request_method != 'POST' or request_uri.split('?')[0] != '/rest/user/login':
            return None
        return {
            'schema_version': 1, 'source': 'http_auth', 'event_id': identifier(),
            'event_type': 'authentication_failure',
            'event_timestamp': stamp(observed), 'collector_timestamp': stamp(),
            'host': self.host, 'data': {
                'service': 'juice_shop', 'source_ip': client, 'target_ip': self.target,
                'target_port': self.port, 'http_status': 401,
                'request_path': '/rest/user/login', 'tcp_stream': stream,
                'frame_number': frame
            }
        }

def capture_command(interface, target, port):
    fields = ['frame.time_epoch', 'tcp.stream', 'ip.src', 'ip.dst',
              'tcp.srcport', 'tcp.dstport', 'http.request.method',
              'http.request.uri', 'http.response.code', 'frame.number']
    command = ['tshark', '-l', '-n', '-i', interface, '-f',
               f'host {target} and tcp port {port}', '-d', f'tcp.port=={port},http',
               '-Y', 'http.request or http.response', '-T', 'fields',
               '-E', 'separator=/t', '-E', 'occurrence=f']
    for field in fields:
        command += ['-e', field]
    return command


def run(config, stop, emit, interval):
    import socket
    import subprocess
    import threading
    collector = AuthenticationCollector(socket.gethostname(), config['target_ip'], config['port'])
    process = subprocess.Popen(capture_command(config['interface'], config['target_ip'], config['port']), stdout=subprocess.PIPE, text=True)
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
            if value:
                emit(value)
        if process.wait() and not stop.is_set():
            raise RuntimeError('TShark failed; check interface and capture permissions')
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        process.stdout.close()
