# Team EDR8

A modular Python endpoint monitoring and detection tool for authorised Juice Shop lab environments. One agent runs on each monitored Ubuntu VM, combining telemetry collection, detection rules, alert storage and a local dashboard.

This README covers the EDR architecture, installation and operation, followed by detection scenarios and verification procedures.

## Contents

1. [EDR Tool implementation](#1-common-edr-implementation)
2. [Installation and configuration](#2-installation-and-configuration)
3. [Running the EDR](#3-running-the-edr)
4. [Detection module interface](#4-detection-module-interface)
5. [BA-001: Repeated failed logins](#5-ba-001-repeated-failed-logins)
6. [Detection scenario template](#6-detection-scenario-template)
7. [Evaluation and evidence](#7-evaluation-and-evidence)

## 1. EDR Tool implementation

### Architecture

Collectors gather activity and produce events in a common format. The agent receives those events through a bounded queue, saves them in SQLite and passes them to registered detection rules. When a rule returns an alert, the agent saves it and invokes the response handler. A separate dashboard reads the database.

### Shared components

| Component | Purpose |
|---|---|
| `agent.py` | Loads configuration and coordinates collection, processing, detection and response |
| `edr/collectors/` | Collects activity and converts it into common events |
| `edr/rules/` | Contains separate detection modules |
| `edr/rules/registry.py` | Registers rules and loads enabled rules |
| `config.json` | Sets the database, collectors, lab settings and rule options |
| SQLite storage | Saves events, alerts, responses, collector status and performance records |
| `edr/response.py` | Records notification outcomes and recommendations |
| `dashboard.py` | Displays saved events, alerts, evidence and collector status |
| `evaluate.py` | Evaluates labelled trials |
| `SCHEMA.md` | Defines shared event and alert fields |
| `tests/` | Contains automated checks |

### Collectors

| Collector | What it gathers | Notes |
|---|---|---|
| Process | Newly observed and disappeared processes using `psutil` | Polling can miss short-lived processes |
| Network | Newly observed connections using `psutil` | Does not inspect packet contents |
| HTTP authentication | Juice Shop login requests and responses using TShark | Produces failed-login events for BA-001 |
| Filesystem | File creation, modification, deletion and movement using `watchdog` | Does not provide reliable file-read auditing |
| Docker logs | Observes container log lines | Records occurrence and length; does not extract attack indicators |
| System authentication | Common SSH failed-password/public-key messages from the configured journal unit | Does not feed the Juice Shop BA rule |

Enable only the collectors required for the configured detection scenarios. Collector requirements are documented with each scenario.

### Alerts, response and dashboard

The current response mode is `notify_only`: alerts and notification outcomes are recorded. Automatic IP blocking and file quarantine are not implemented in this release.

The dashboard shows counts, recent alerts, event evidence, timing and collector status history. It refreshes every three seconds and is read-only on localhost. Status history is not a continuous heartbeat.

## 2. Installation and configuration

### Lab requirements

- Ubuntu VM running Juice Shop and the EDR.
- Kali VM for generating test activity.
- Network connectivity between the VMs.
- Python 3, virtual-environment support and TShark on Ubuntu.
- Internet access or locally available packages for installation.

Example Juice Shop address: `http://192.168.100.100:3000`. Replace it with the actual lab address throughout these instructions.

### Install the project

Copy or clone the project onto Ubuntu, open a terminal in the project folder and run:

```bash
sudo apt update
sudo apt install python3-venv tshark
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

Install dependencies before switching to a host-only network if necessary. Preserve existing configuration and test evidence when upgrading.

### Configure the agent

Find the interface and, if required, the container name:

```bash
ip -br address
sudo tshark -D
docker ps --format '{{.Names}}'
nano config.json
```

Update the existing configuration:

- Set `database` to the database for the current test, such as `runs/ba-normal-1.db`.
- Enable `http_auth` and set the actual capture interface, Juice Shop IP and port.
- Keep process/network collection enabled if broader host visibility is required.
- Enable the required rules and set their thresholds.
- Keep `response.mode` as `notify_only`; other modes are rejected by this release.
- Enable Docker collection only with the correct container name and access permissions.
- For filesystem collection, create the selected watch directory first. Do not watch the database or output directory, which can create feedback events.
- For SSH collection, confirm the actual journal unit, commonly `ssh.service` on Ubuntu.

Each monitored VM uses the same source code with configuration values appropriate to that VM.

## 3. Running the EDR

### Optional synthetic preview

```bash
.venv/bin/python agent.py --demo
.venv/bin/python dashboard.py --database runs/demo.db
```

Open `http://127.0.0.1:8080` inside Ubuntu. Each demo execution produces five synthetic events and one synthetic alert. This checks the interface and detection path; it is not evidence of live collection.

Stop the preview dashboard with Ctrl+C before starting the live dashboard on the same port.

### Live monitoring

Start Juice Shop before testing.

In Ubuntu terminal 1, from the project folder:

```bash
sudo .venv/bin/python agent.py --config config.json
```

In Ubuntu terminal 2:

```bash
sudo .venv/bin/python dashboard.py --database runs/ba-normal-1.db
```

Use the same database path in `config.json` and the dashboard command. Open `http://127.0.0.1:8080` inside Ubuntu.

Check collector status for failures before running an attack. Other collectors may continue producing events even when the required collector has failed. Stop the agent and dashboard with Ctrl+C when finished.

## 4. Detection module interface

Detection modules use the common event schema and return alerts through the shared agent pipeline. A module consists of:

1. A defined detection scenario and its required telemetry.
2. A collector or parser that supplies the required event fields.
3. A rule module in `edr/rules/`.
4. An entry in `edr/rules/registry.py` and settings in `config.json`.
5. Automated checks and repeatable attack and control tests.
6. Documentation of configuration, expected results and limitations.

Example rule interface:

```python
class ExampleRule:
    rule_id = 'RULE-002'

    def __init__(self, config):
        pass

    def process(self, event):
        # Return [] when there is no match.
        # Return a list of alert dictionaries when detection conditions match.
        return []
```

Alerts must include:

- `alert_id`
- `rule_id`
- `attack`
- `severity` (1–5)
- `severity_label`
- `host`
- `detection_timestamp`
- `evidence_event_ids`
- `recommended_action`

Include timing fields where meaningful. Follow `SCHEMA.md` for shared formats.

All detection modules reuse the agent, storage, response handler and dashboard. Verify modules together to check that existing detections continue to operate correctly.

## 5. BA-001: Repeated failed logins

**Contributor:** Yasiru Weerasinghe  
**Category:** Broken Authentication  
**Scope:** Repeated failed Juice Shop logins; this does not cover every authentication attack.

### Implementation

The HTTP authentication collector uses TShark to match login requests with responses. A `POST /rest/user/login` request returning HTTP `401` produces an `authentication_failure` event.

The rule in `edr/rules/broken_auth.py` alerts on **five failures within ten seconds**, grouped by monitored host, source IP, target IP and target port.

The alert includes matching event IDs and timing evidence. The shared response handler records a notification; it does not block the source.

### Required configuration

- HTTP authentication collection enabled with the correct interface, target IP and port.
- `BA-001` enabled with a five-failure threshold and ten-second window.
- A fresh database for each independent test below.

### Test A: Below threshold

1. Set the database to `runs/ba-normal-1.db` in `config.json`.
2. Start the live agent and dashboard using Section 3.
3. On Kali, run:

```bash
for attempt in 1 2; do
  curl -s -o /dev/null -w 'HTTP %{http_code}\n' \
    -X POST http://192.168.100.100:3000/rest/user/login \
    -H 'Content-Type: application/json' \
    --data '{"email":"edr-test@example.invalid","password":"wrong-password"}'
  sleep 1
done
```

**Expected result:**

- Two HTTP `401` responses.
- Two `authentication_failure` events.
- No BA-001 alert.

Other collectors may increase the total event count. This is a below-threshold control, not a complete normal-traffic evaluation.

### Test B: Repeated failed-login attack

1. Stop the agent and dashboard.
2. Change the configuration database to `runs/ba-attack-1.db`, using a filename that does not already contain test data.
3. Restart both programs, pointing the dashboard to `runs/ba-attack-1.db`.
4. On Kali, run:

```bash
for attempt in 1 2 3 4 5; do
  curl -s -o /dev/null -w 'HTTP %{http_code}\n' \
    -X POST http://192.168.100.100:3000/rest/user/login \
    -H 'Content-Type: application/json' \
    --data '{"email":"edr-test@example.invalid","password":"wrong-password"}'
  sleep 1
done
```

**Expected result:**

- Five HTTP `401` responses within ten seconds.
- One BA-001 alert.
- One recorded notification response.

Check the captured timestamps: slow requests can push the test outside the detection window.

### Evidence to record

- Kali output showing the HTTP responses.
- Dashboard alert with source, target, rule ID and timestamps.
- Matching authentication events and notification outcome.
- Below-threshold test showing recorded failures without a BA-001 alert.

Keep results tied to the code version and configuration used. Historical VM results are separate evidence and are not automatically reproduced by downloading the repository.

## 6. Detection scenario template

The following template defines the documentation format for an additional detection scenario. It describes no enabled capability until its placeholders are completed and its implementation is verified.

### [Rule ID]: [Attack name]

**Contributor:** [Name]  
**Category:** [Attack category]  
**Implementation status:** [State verified support and any restrictions]

#### Implementation

- **Files added or changed:** [Paths]
- **Telemetry:** [Collector, event type and required fields]
- **Detection condition:** [Exact conditions, grouping, threshold and window]
- **Alert and response:** [What is generated and what action is actually taken]
- **Detection limits:** [What the evidence can and cannot establish]

#### Setup and configuration

[List dependencies, test accounts, required collector/rule settings and any additional setup.]

#### Attack test

1. [Start the EDR with the required configuration.]
2. [State which VM runs the attack.]
3. [Provide exact commands or script filename and arguments.]
4. [State the expected events, alert and response.]

#### Normal or below-threshold test

[Provide repeatable steps and expected results using an independent test state.]

#### Evidence and results

[Link reviewed screenshots, sample events and measured results. Include code version and configuration. Do not include passwords or session tokens.]

For basket enumeration, distinguish a request-based alert from confirmed unauthorised access. Confirmation requires successful access and evidence that the basket belongs to a different account.
### 6.1 SQLI-001: SQL Injection – Data Exfiltration

**Contributor:** Sohana Tasnim Faiza  
**Category:** SQL Injection  
**Implementation status:** Implemented; automated tests passed and a High-severity alert was observed on the dashboard.

#### Implementation

- **Files:** `edr/rules/sqli_exfiltration.py`, `edr/collectors/http_auth.py`, `edr/rules/registry.py`, `config.json`
- **Telemetry:** HTTP request events collected using TShark from the configured Juice Shop target.
- **Target endpoint:** `/rest/products/search`
- **Detection condition:** Detects suspicious SQL injection patterns, including `UNION SELECT`, in relevant product-search requests.
- **Alert:** `SQLI-001`, High severity (4).
- **Response:** The configured `notify_only` mode records alerts and recommendations without automatically blocking the source.

#### Setup and configuration

1. Start OWASP Juice Shop on the Ubuntu lab VM.
2. Configure the HTTP collector with the correct interface, target IP and port in `config.json`.
3. Enable `SQLI-001`.
4. Start the EDR agent and dashboard using Section 3 of this README.

#### Attack test

From the authorised Kali lab VM, send a controlled SQL injection test request to the Juice Shop product-search endpoint:

```bash
curl -G 'http://192.168.241.128:3000/rest/products/search' \
  --data-urlencode "q=qwert')) UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users--"
```

**Expected result:** The HTTP collector captures the request and the rule generates a `SQLI-001` alert if the request matches the detection conditions.

#### Normal/control test

Send a normal product search request:

```bash
curl -G 'http://192.168.241.128:3000/rest/products/search' \
  --data-urlencode "q=orange"
```

**Expected result:** No `SQLI-001` alert should be generated for the normal search.

#### Evidence and results

- Automated test command: `.venv/bin/python -m unittest discover -s tests -v`
- **Automated result:** 10 tests passed (`OK`).
- **Dashboard result:** A `SQLI-001` alert with severity `4 / High` was observed.
- Evidence includes the terminal test output and dashboard screenshot.

#### Limitations

- Pattern-based detection may miss obfuscated SQL injection payloads.
- A suspicious request does not, by itself, prove successful data exfiltration.
- The current `notify_only` response mode does not automatically block attacks.

## 7. Evaluation and evidence

Record controlled attack and normal trials with actual UTC start/end times. Allow observation time for delayed alerts.

Example:

```bash
sudo .venv/bin/python evaluate.py --database runs/ba-attack-1.db \
  --trial-id ba-attack-1 --scenario broken-auth --rule BA-001 --label attack \
  --start 'ACTUAL_START_UTC' --end 'ACTUAL_END_UTC'
```

Replace the timestamps before running. Use `--label normal` for normal/control trials. Duplicate IDs and overlapping windows for the same rule are rejected.

### Detection metrics

| Metric | Meaning |
|---|---|
| Detection rate | TP / (TP + FN) |
| False-positive rate | FP / (FP + TN) |
| Evaluation MTTD | Average detection timestamp minus supplied trial start for detected attack trials |
| BA alert timing | Time from the first observed failed-login response and from the threshold-satisfying response |

BA alert timings differ from trial-start MTTD.

The evaluator does not launch attacks or prove alert attribution. Review evidence manually and avoid unrelated simultaneous activity. Missed attacks count as false negatives and receive no invented detection time.

Use fresh agent/database instances for independent tests.

For repeated trials in one experiment database, use nonoverlapping windows and allow more than ten seconds between BA trials to re-arm.

Cross-database aggregation is not implemented. Consolidate reviewed results separately if using separate databases.

### Performance monitoring

Performance records include:

- Agent CPU usage.
- Agent and child-process memory usage.
- System CPU usage.
- Queue depth.
- Dropped events.

Agent CPU excludes TShark CPU, while system CPU includes other workloads. Compare idle and attack measurements before making performance claims.


