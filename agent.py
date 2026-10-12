import argparse
import json
import queue
import threading
import time
from edr.core import Store, event
from edr.rules.registry import load_rules
from edr.response import respond


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='config.json')
    parser.add_argument('--demo', action='store_true', help='Synthetic BA test; not live attack evidence')
    args = parser.parse_args()
    with open(args.config, encoding='utf-8') as handle:
        config = json.load(handle)
    if args.demo:
        config['database'] = 'runs/demo.db'
    if config['response']['mode'] != 'notify_only':
        parser.error('Only notify_only is implemented')
    interval = float(config.get('poll_seconds', 5))
    if interval <= 0:
        parser.error('poll_seconds must be positive')
    rules = load_rules(config['rules'])
    store = Store(config['database'])
    stop = threading.Event()
    inbox = queue.Queue(maxsize=int(config.get('queue_size', 2000)))
    workers = []
    counters = {'dropped_events': 0}
    counter_lock = threading.Lock()
    def emit(value):
        try:
            inbox.put_nowait(value)
        except queue.Full:
            with counter_lock:
                counters['dropped_events'] += 1
    def worker(name, function, settings):
        store.add('health', {'collector': name, 'status': 'started'})
        try:
            function(settings, stop, emit, interval)
            store.add('health', {'collector': name, 'status': 'stopped'})
        except Exception as exc:
            store.add('health', {'collector': name, 'status': 'failed', 'error': str(exc)})
            print(f'[COLLECTOR FAILED] {name}: {exc}', flush=True)
    store.add('health', {'component': 'agent', 'status': 'started', 'mode': 'synthetic_demo' if args.demo else 'live'})
    if args.demo:
        for index in range(5):
            value = event('synthetic_demo', 'authentication_failure', {'service':'juice_shop', 'source_ip':'192.0.2.20', 'target_ip':'192.0.2.10', 'target_port':3000, 'http_status':401}, time.time() - 4 + index)
            value['synthetic'] = True
            emit(value)
    else:
        from edr.collectors import host, files, logs, http_auth
        registry = {'process':host.processes, 'network':host.connections, 'files':files.run,
                    'docker':logs.docker, 'system_auth':logs.auth, 'http_auth':http_auth.run}
        for name, settings in config['collectors'].items():
            if settings.get('enabled'):
                if name not in registry:
                    raise ValueError(f'Unknown collector: {name}')
                thread = threading.Thread(target=worker, args=(name, registry[name], settings), daemon=True)
                thread.start()
                workers.append(thread)
    def performance():
        import psutil
        process = psutil.Process()
        process.cpu_percent(None)
        while not stop.wait(interval):
            children = process.children(recursive=True)
            store.add('performance', {'agent_cpu_percent':process.cpu_percent(None),
                'agent_rss_bytes':process.memory_info().rss,
                'child_rss_bytes':sum(p.memory_info().rss for p in children if p.is_running()),
                'system_cpu_percent':psutil.cpu_percent(None),
                'queue_depth':inbox.qsize(), **counters})
    if not args.demo:
        thread = threading.Thread(target=worker, args=('performance', lambda c,s,e,i:performance(), {}), daemon=True)
        thread.start()
        workers.append(thread)
    print(f"[AGENT STARTED] database={config['database']} rules={[r.rule_id for r in rules]}", flush=True)
    try:
        while not stop.is_set():
            try:
                value = inbox.get(timeout=0.5)
            except queue.Empty:
                if args.demo:
                    break
                continue
            value['ingest_timestamp'] = event('clock', 'clock', {})['collector_timestamp']
            store.add('events', value)
            for rule in rules:
                try:
                    for alert in rule.process(value):
                        alert['synthetic'] = bool(value.get('synthetic'))
                        respond(alert, store)
                except Exception as exc:
                    store.add('health', {'rule_id':rule.rule_id, 'status':'failed_event', 'event_id':value['event_id'], 'error':str(exc)})
    except KeyboardInterrupt:
        print('\n[STOPPING]', flush=True)
    finally:
        stop.set()
        for thread in workers:
            thread.join(timeout=4)
        store.add('health', {'component':'agent', 'status':'stopped', **counters, 'unprocessed_events':inbox.qsize()})
        store.close()

if __name__ == '__main__':
    main()
