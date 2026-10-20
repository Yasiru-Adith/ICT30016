from collections import deque
import uuid
from edr.core import timestamp, utc


class IDOR:
    # IDOR-001: detects Juice Shop basket enumeration. Alerts when one source
    # hits >= distinct_threshold baskets within window_seconds. MITRE T1083.
    rule_id = 'IDOR-001'

    def __init__(self, config):
        self.threshold = int(config.get('distinct_threshold', 3))
        self.window = float(config.get('window_seconds', 10))
        if self.threshold < 2 or self.window <= 0:
            raise ValueError('IDOR distinct_threshold must be >=2 and window >0')
        self.groups = {}          
        self.active = set()        
        self.watermark = None    

    def process(self, value):
        # Only basket reads from Juice Shop are relevant.
        if value['event_type'] != 'basket_access':
            return []
        data = value['data']
        if data.get('service') != 'juice_shop':
            return []
        if data.get('basket_id') is None:
            return []

        # Advance watermark; ignore late events outside the window.
        when = timestamp(value['event_timestamp'])
        self.watermark = max(when, self.watermark or when)
        if when < self.watermark - self.window:
            return []

        # Age out expired events; re-arm sources that dropped below threshold.
        for key in list(self.groups):
            recent = deque(
                e for e in self.groups[key]
                if timestamp(e['event_timestamp']) >= self.watermark - self.window
            )
            if len({e['data']['basket_id'] for e in recent}) < self.threshold:
                self.active.discard(key)
            if recent:
                self.groups[key] = recent
            else:
                del self.groups[key]

        # Record this read under its source identity (host + source IP).
        key = (value['host'], data['source_ip'])
        queue = self.groups.setdefault(key, deque())
        queue.append(value)
        queue = deque(sorted(queue, key=lambda e: timestamp(e['event_timestamp'])))
        self.groups[key] = queue

        # Distinct-basket check: duplicates collapse, so repeated reads of one
        # basket never trigger. Only breadth across baskets does.
        distinct_ids = sorted({e['data']['basket_id'] for e in queue})
        if len(distinct_ids) < self.threshold or key in self.active:
            return []

        self.active.add(key)
        detected = utc()
        first = queue[0]['event_timestamp']
        qualifying = queue[-1]['event_timestamp']
        return [{
            'alert_id': str(uuid.uuid4()),
            'rule_id': self.rule_id,
            'attack': 'Possible IDOR Basket Enumeration (Broken Access Control)',
            'severity': 3,
            'severity_label': 'Medium',
            'host': value['host'],
            'mitre_technique': 'T1083',
            'source_ip': data['source_ip'],
            'target_ip': data.get('target_ip'),
            'target_port': data.get('target_port'),
            'distinct_baskets': len(distinct_ids),
            'basket_ids': distinct_ids,
            'window_seconds': self.window,
            'first_event_timestamp': first,
            'threshold_event_timestamp': qualifying,
            'detection_timestamp': detected,
            'attack_to_detection_seconds': timestamp(detected) - timestamp(first),
            'threshold_to_detection_seconds': timestamp(detected) - timestamp(qualifying),
            'evidence_event_ids': [e['event_id'] for e in queue],
            'recommended_action': "Review basket access authorization; confirm one token read multiple users' baskets before containment.",
        }]
