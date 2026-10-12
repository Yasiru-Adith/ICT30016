from edr.core import utc


def respond(alert, store):
    alert['alert_timestamp'] = utc()
    store.add('alerts', alert)
    print(f"[ALERT] {alert['rule_id']} severity={alert['severity']} source={alert.get('source_ip', '?')}", flush=True)
    store.add('responses', {'alert_id': alert['alert_id'], 'action': 'console_notification',
                            'status': 'completed', 'response_timestamp': utc(),
                            'recommended_action': alert['recommended_action']})
