import json
import socket
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def utc(t=None):
    return datetime.fromtimestamp(time.time() if t is None else t, timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def timestamp(text):
    return datetime.fromisoformat(text.replace('Z', '+00:00')).timestamp()


def event(source, kind, data, observed=None):
    return {'schema_version': 1, 'event_id': str(uuid.uuid4()), 'host': socket.gethostname(),
            'source': source, 'event_type': kind, 'event_timestamp': utc(observed),
            'collector_timestamp': utc(), 'data': data}


class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.connection:
            self.connection.execute('PRAGMA journal_mode=WAL')
            for table in ('events', 'alerts', 'responses', 'health', 'performance', 'trials'):
                self.connection.execute(f'CREATE TABLE IF NOT EXISTS {table} (id INTEGER PRIMARY KEY, recorded TEXT, payload TEXT)')

    def add(self, table, payload):
        if table not in ('events', 'alerts', 'responses', 'health', 'performance', 'trials'):
            raise ValueError('Unknown table')
        with self.lock, self.connection:
            self.connection.execute(f'INSERT INTO {table}(recorded,payload) VALUES (?,?)', (utc(), json.dumps(payload)))

    def close(self):
        self.connection.close()
