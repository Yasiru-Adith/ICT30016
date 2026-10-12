# Shared interfaces (version 1)

Event: schema_version, event_id, host, source, event_type, event_timestamp, collector_timestamp, ingest_timestamp (added by pipeline), data. Use UTC ISO timestamps. event_timestamp is the source's occurrence time when available, otherwise observation time; document basis in data. event_id supports evidence links; host identifies endpoint; source/type route events; data contains only justified fields.

Collectors: function(config, stop_event, emit, poll_seconds). Stop cleanly, emit dictionaries, report failure through the worker wrapper. All persistence happens centrally except health/performance records. The queue is bounded.

Rules: registered class(config), process(event) -> list of alerts. Ignore unrelated types; maintain bounded/expiring correlation state; preserve evidence IDs; avoid collecting passwords/tokens. The engine isolates rule exceptions and records failures.

Alert: alert_id, rule_id, attack, severity, severity_label, host, detection_timestamp, evidence_event_ids, recommended_action. Suggested team severity mapping: 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical. This mapping is a project convention, not a research-derived severity score. attack_to_detection_seconds/threshold_to_detection_seconds apply to BA and are explicitly defined in README.

Response: alert_id, action, status, response_timestamp, recommended_action. Current action is console_notification, completed. Storing/printing is not containment.

SQLite tables: events, alerts, responses, health, performance, trials. Each stores id, recorded (storage timestamp) and payload JSON. Evidence event IDs refer to event payloads, not SQLite row IDs. Dashboard returns latest 30 rows per section and total counts. Export/analyse using sqlite3/Python when needed.

Scope: local Ubuntu host and Docker Juice Shop; no central management or ML. Shared codebase and per-VM config, not a central service managing multiple agents.
