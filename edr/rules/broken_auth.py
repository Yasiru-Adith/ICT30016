from collections import deque
import uuid
from edr.core import timestamp, utc


class BrokenAuth:
    rule_id = 'BA-001'

    def __init__(self, config):
        self.threshold = int(config.get('threshold', 5))
        self.window = float(config.get('window_seconds', 10))
        if self.threshold < 2 or self.window <= 0:
            raise ValueError('BA threshold must be >=2 and window >0')
        self.groups = {}
        self.active = set()
        self.watermark = None

    def process(self, value):
        if value['event_type'] != 'authentication_failure':
            return []
        data = value['data']
        if data.get('service') != 'juice_shop':
            return []
        when = timestamp(value['event_timestamp'])
        self.watermark = max(when, self.watermark or when)
        if when < self.watermark - self.window:
            return []
        for key in list(self.groups):
            recent = deque(e for e in self.groups[key] if timestamp(e['event_timestamp']) >= self.watermark - self.window)
            if len(recent) < self.threshold:
                self.active.discard(key)
            if recent:
                self.groups[key] = recent
            else:
                del self.groups[key]
        key = (value['host'], data['source_ip'], data['target_ip'], data['target_port'])
        queue = self.groups.setdefault(key, deque())
        queue.append(value)
        queue = deque(sorted(queue, key=lambda e: timestamp(e['event_timestamp'])))
        self.groups[key] = queue
        if len(queue) < self.threshold or key in self.active:
            return []
        self.active.add(key)
        detected = utc()
        first = queue[0]['event_timestamp']
        qualifying = queue[-1]['event_timestamp']
        return [{'alert_id': str(uuid.uuid4()), 'rule_id': self.rule_id,
                 'attack': 'Possible Brute-Force Authentication', 'severity': 3,
                 'severity_label': 'Medium', 'host': value['host'], 'mitre_technique': 'T1110',
                 'source_ip': data['source_ip'], 'target_ip': data['target_ip'], 'target_port': data['target_port'],
                 'failed_attempts': len(queue), 'window_seconds': self.window,
                 'first_event_timestamp': first, 'threshold_event_timestamp': qualifying,
                 'detection_timestamp': detected,
                 'attack_to_detection_seconds': timestamp(detected) - timestamp(first),
                 'threshold_to_detection_seconds': timestamp(detected) - timestamp(qualifying),
                 'evidence_event_ids': [e['event_id'] for e in queue],
                 'recommended_action': 'Review login evidence and source authorization before containment.'}]
