import subprocess
import threading
import json
import re
from edr.core import event


def stream(command, source, stop, emit):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True, stderr=None)
    def terminate():
        stop.wait()
        if process.poll() is None:
            process.terminate()
    threading.Thread(target=terminate, daemon=True).start()
    try:
        for line in process.stdout:
            if stop.is_set():
                break
            if source == 'system_auth':
                match = re.search(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+) port (\d+)', line)
                if match:
                    emit(event(source, 'system_authentication_failure',
                               {'username':match[1], 'source_ip':match[2], 'source_port':int(match[3]),
                                'service':'ssh', 'timestamp_basis':'collector_observation'}))
                else:
                    emit(event(source, 'system_auth_log_observed', {'line_length':len(line.rstrip()), 'parser_status':'unmatched'}))
            else:
                # No raw logs are persisted until their format and redaction are agreed.
                emit(event(source, source + '_log_observed', {'line_length': len(line.rstrip()),
                                                           'parser_status': 'unconfigured'}))
        if process.wait() and not stop.is_set():
            raise RuntimeError(f'{source} log command failed')
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        process.stdout.close()


def docker(config, stop, emit, interval):
    stream(['docker', 'logs', '--follow', '--since', '0s', '--timestamps', config['container']], 'docker', stop, emit)


def auth(config, stop, emit, interval):
    stream(['journalctl', '--follow', '--lines', '0', '--output', 'cat', '--unit', config['unit']], 'system_auth', stop, emit)
