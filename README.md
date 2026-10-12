# Team EDR — first shared build

Python agent on Ubuntu → collectors → normalized events → registered rules → alerts → response.
The local browser dashboard reads the same SQLite database. Kali only generates authorised test traffic. This is a new codebase; preserve your old working scripts and evidence.

## What is implemented

- Configurable process and network polling, filesystem notifications, live HTTP authentication collection, SSH failure parsing through journalctl, Docker log-stream integration.
- One shared schema, bounded queue, collector error records, SQLite event/alert/response persistence.
- Independently registered BA-001 rule: five failures within ten seconds, grouped by host/source/target/port; numeric severity 3/5 (Medium).
- Notification response with recorded outcome and recommendation. No containment actions yet.
- Local dashboard: counts, recent alerts, evidence/timing, event records and collector status history; refreshes every three seconds.
- Agent CPU/memory sampling and labelled trial evaluation: TP, FN, FP, TN, detection rate, false-positive rate and MTTD.

Important: Docker collection currently records that log lines were observed, not their content or attack indicators. Application log parsing needs actual team samples and agreed redaction. SSH parsing recognizes common failed-password/publickey messages, using collector-observation time; it does not feed the Juice Shop BA rule. These integrations are not complete attack detectors.

## 1. Transfer into VMware

Download team-edr.zip on Windows and drag it into Ubuntu Home. If unavailable, use VMware Shared Folders as discussed. Extract into your home directory:

```bash
cd ~
unzip team-edr.zip
cd team-edr
sudo apt update
sudo apt install python3-venv tshark
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

Dependencies require internet or locally available packages. If the lab is host-only, install dependencies before returning to the controlled lab network. Python code is not tied to VMware vs VirtualBox; Linux services and privileges still matter.

## 2. Preview the interface without a live attack

```bash
.venv/bin/python agent.py --demo
.venv/bin/python dashboard.py --database runs/demo.db
```

Open http://127.0.0.1:8080 INSIDE the Ubuntu VM. The demo creates five synthetic events and one synthetic alert per execution. It uses a separate demo database and the interface labels synthetic alerts. This is an interface/logic check, not live detection evidence. Ctrl+C stops the dashboard. The dashboard is read-only and bound to localhost; no login or containment controls are included.

## 3. Configure live collection

Find the interface and container:

```bash
ip -br address
sudo tshark -D
docker ps --format '{{.Names}}'
nano config.json
```

In config.json:
- Set database to runs/ba-test-1.db (fresh filename per test avoids mixed counts and trials).
- Enable http_auth, set actual interface, Juice Shop IP and exposed port.
- Keep process/network enabled for broader host visibility.
- For file collection, first create /tmp/edr-lab, enable files and set specific watch directories. Do not watch the database/output directory; doing so creates feedback events.
- Enable docker only with the actual container name. Docker access is privileged.
- Enable system_auth if SSH monitoring is needed; confirm the actual journal unit (Ubuntu often ssh.service). This does not read /var/log/auth.log.
- Leave response.mode as notify_only. Other modes are rejected.

All members can use the same code with different config.json values. Defaults are examples, not discovery of your VM.

## 4. Start live agent and dashboard

Terminal 1 on Ubuntu (sudo enables lab capture/system visibility):

```bash
sudo .venv/bin/python agent.py --config config.json
```

Terminal 2 on Ubuntu:

```bash
sudo .venv/bin/python dashboard.py --database runs/ba-test-1.db
```

Open http://127.0.0.1:8080 inside Ubuntu. Check collector status history for failures. A failed collector leaves the remaining collectors running, so counts alone do not prove all monitoring is healthy. Status history is not a heartbeat.

## 5. Live BA tests on Kali

Keep Juice Shop running. Start the agent BEFORE requests. For a below-threshold test:

```bash
for attempt in 1 2; do
  curl -s -o /dev/null -w 'HTTP %{http_code}\n' \
    -X POST http://192.168.100.100:3000/rest/user/login \
    -H 'Content-Type: application/json' \
    --data '{"email":"edr-test@example.invalid","password":"wrong-password"}'
  sleep 1
done
```

Expected: two 401 responses, two authentication_failure events, zero BA alerts. Total event count will be higher because other collectors generate events.

Stop the agent with Ctrl+C. Change config database to runs/ba-test-2.db, restart agent and point dashboard to that database. Run the same Kali command with `for attempt in 1 2 3 4 5; do`. Expected: five 401s within ten seconds → one BA-001 alert → one response. Examine evidence_event_ids and timestamps in the alert. HTTP delays can push the test outside the window; use recorded times.

All logged times use UTC; your Sydney local time differs. For real evidence use screenshots of live mode, not the synthetic demo.

## 6. Record evaluation trials

Use one separately controlled attack or normal trial per time window, and preferably a fresh agent/database per test. Capture actual trial start/end UTC times (not invented values). The end must allow sufficient observation time for delayed detection. Example shape, replacing the placeholder timestamps:

```bash
sudo .venv/bin/python evaluate.py --database runs/ba-test-2.db \
  --trial-id ba-attack-1 --scenario broken-auth --rule BA-001 --label attack \
  --start 'ACTUAL_START_UTC' --end 'ACTUAL_END_UTC'
```

Use --label normal for normal activity tests. Duplicate IDs and overlapping windows for the same rule are rejected. Evaluation counts a matching non-synthetic alert within the window; avoid unrelated simultaneous activity, and manually check attribution. It does not automatically launch attacks or establish causality.

For multiple repetitions, keep trials in one experiment database with nonoverlapping windows (and wait >10 seconds between BA trials to re-arm). Reports group by scenario/rule in that database. If using separate databases per run, consolidate reviewed trial results externally; cross-database aggregation is not implemented.

Detection rate = TP/(TP+FN); false-positive rate = FP/(FP+TN). MTTD here averages detected attack trials using detection timestamp minus the supplied trial start. Missed attacks remain FN and are not assigned a fabricated time. Five trials per scenario yield 20% increments: meeting >=90% requires 5/5; ten trials can represent 90%.

BA alerts also include time from the first observed failure and from the threshold-satisfying failure. They use capture response timestamps, not true attacker onset. Threshold latency includes collection/delivery, queuing and processing. Clock changes distort wall-clock differences. Demo timings are synthetic. Process/network polling at five seconds can miss short-lived activity and add delay; collect real measurements before changing intervals.

CPU measurements are in the performance table: agent_cpu_percent (may exceed 100 on multiple cores), agent_rss_bytes, child_rss_bytes, system_cpu_percent, queue_depth and dropped_events. Agent CPU does NOT include TShark CPU; system CPU includes Juice Shop and other activity. Compare idle baseline and attack runs and use OS tools for full process-tree CPU. The concept does not provide a numeric CPU budget; agree one with the tutor before asserting compliance.

## 7. Adding a teammate's rule

Create edr/rules/their_rule.py with this interface:

```python
class TheirRule:
    rule_id = 'TEAM-002'
    def __init__(self, config):
        pass
    def process(self, event):
        # Filter event_type and check verified attack behaviour.
        # Return [] when no match; otherwise return a list of alert dictionaries.
        return []
```

Import/register the class in edr/rules/registry.py, then add its enabled settings to config.json. Alerts must include alert_id, rule_id, attack, severity (1–5), severity_label, host, detection_timestamp, evidence_event_ids and recommended_action. Include timing fields where meaningful. Response and dashboard then reuse the existing handler. Add a collector only if existing events cannot provide the required evidence. Never label placeholder rules as detections.

See SCHEMA.md for shared fields. A team rule needs real attack evidence plus normal tests. IDOR requires authorization context; forged JWT requires verified token context; network connections alone are insufficient.

## Current limitations and next work

This first build supports BA only. Docker/application parsing, additional selected rules and controlled containment require further work. Watchdog records changes, not a reliable audit of file reads or attribution to a process. Process/network events are sampled observations, not complete execution/connection history. HTTP collector covers IPv4 plaintext HTTP/1.1 with simple per-stream request/response pairing; missing packets, pipelining or multiple messages per packet may break correlation. HTTPS needs application logs or appropriate endpoint instrumentation. Authentication payloads and raw Docker logs are not persisted.

Database records accumulate until the test is stopped; no retention/rotation yet. Queue overflow counts dropped events; shutdown records unprocessed events. Enabled collectors must be checked for errors. Agent restarts reset BA state. Duplicate alerts are suppressed while a group's active window remains above threshold.

A later response module can support allowlisted, reversible lab containment with outcome and rollback records; this release only notifies. Running everything as root is a lab simplification, not the final privilege model.

The dashboard remains basic: status and evidence, no editing or action buttons. Extend it after rule integration instead of building a large UI early.
