import psutil
from edr.core import event


def processes(config, stop, emit, interval):
    seen = None
    while not stop.is_set():
        current = {}
        for process in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'create_time']):
            try:
                info = process.info
                current[(info['pid'], info['create_time'])] = info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if seen is None:
            emit(event('process', 'process_baseline', {'process_count': len(current)}))
        else:
            for key in current.keys() - seen.keys():
                emit(event('process', 'process_started', current[key], current[key]['create_time']))
            for key in seen.keys() - current.keys():
                emit(event('process', 'process_disappeared', seen[key]))
        seen = current
        stop.wait(interval)


def connections(config, stop, emit, interval):
    seen = set()
    first = True
    while not stop.is_set():
        current = set()
        for item in psutil.net_connections(kind='inet'):
            local = tuple(item.laddr) if item.laddr else ()
            remote = tuple(item.raddr) if item.raddr else ()
            key = (item.pid, local, remote, item.status)
            current.add(key)
            if key not in seen:
                emit(event('network', 'network_connection_snapshot' if first else 'network_connection_observed',
                           {'pid': item.pid, 'local_address': local, 'remote_address': remote, 'status': item.status}))
        seen = current
        first = False
        stop.wait(interval)
