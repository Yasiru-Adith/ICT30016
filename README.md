# Team EDR8

A modular Python endpoint monitoring and detection tool for authorised Juice Shop lab environments. One agent runs on each monitored Ubuntu VM, combining telemetry collection, detection rules, alert storage and a local dashboard.

This README covers the EDR architecture, installation and operation, followed by detection scenarios and verification procedures.

## Contents

1. [EDR Tool implementation](#1-edr-tool-implementation)
2. [Installation and configuration](#2-installation-and-configuration)
3. [Running the EDR](#3-running-the-edr)
4. [Detection module interface](#4-detection-module-interface)
5. [BA-001: Repeated failed logins](#5-ba-001-repeated-failed-logins)
6. [IIV-001: Improper Input Validation – File Upload Type](#6-iiv-001-improper-input-validation--file-upload-type)
7. [IDOR-001: Basket Enumeration (Broken Access Control)](#8-idor-001-basket-enumeration-broken-access-control)
8. [SQLI-001: SQL Injection – Data Exfiltration](#7-sqli-001-sql-injection--data-exfiltration)
9. [AFW-002: Arbitrary File Write 2](#9-arbitrary-file-write-2)
10. [Evaluation and evidence](#8-evaluation-and-evidence)

## 1. EDR Tool implementation

### Architecture

Collectors gather activity and produce events in a common format. The agent receives those events through a bounded queue, saves them in SQLite and passes them to registered detection rules. When a rule returns an alert, the agent saves it and invokes the response handler. A separate dashboard reads the database.

### Shared components

| Component | Purpose |
| --- | --- |
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
| --- | --- | --- |
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

## 5 BA-001: Repeated Failed Logins

**Contributor:** Yasiru Weerasinghe  
**Category:** Broken Authentication  
**Scope:** Detects repeated failed login attempts against Juice Shop.

### Implementation

The HTTP authentication collector uses TShark to match login requests with their responses. A `POST /rest/user/login` request returning HTTP `401` produces an `authentication_failure` event.

The detection rule in `edr/rules/broken_auth.py` generates a **Possible Brute-Force Authentication** alert when it observes **five failed logins within ten seconds**, grouped by monitored host, source IP, target IP and target port.

The alert includes the supporting event IDs, source and target details, and detection timing. The response handler records a notification. It does not automatically block the source.

Repeated failures indicate possible brute-force activity; they do not prove malicious intent or successful account access.

### Requirements and Configuration

- Ubuntu VM running Juice Shop and the EDR.
- Kali VM with network access to Juice Shop.
- HTTP authentication collector enabled with the correct capture interface, target IP and port.
- `BA-001` enabled with a five-failure threshold and ten-second window.
- Response mode set to `notify_only`.

The commands below assume:

| Setting | Example value |
| --- | --- |
| Ubuntu project folder | `~/team-edr` |
| Juice Shop IP | `192.168.100.100` |
| Juice Shop port | `3000` |
| Kali IP | `192.168.100.200` |

Replace these values where they differ from the deployed lab environment. Run the tests only against an authorised lab instance.

### Test A: Below-Threshold Activity

This test checks that two failed logins are recorded without triggering BA-001.

#### 1. Configure an independent test

Stop any running agent and dashboard with **Ctrl+C**.

On Ubuntu:

```bash
cd ~/team-edr
nano config.json
```

Set the existing `database` field to:

```json
"database": "runs/ba-normal-1.db",
```

Use a filename that does not already contain test data. Preserve the remaining configuration.

#### 2. Start the agent

In Ubuntu terminal 1:

```bash
cd ~/team-edr
sudo .venv/bin/python agent.py --config config.json
```

Leave the terminal running and check that the HTTP authentication collector starts without an error.

#### 3. Start the dashboard

In Ubuntu terminal 2:

```bash
cd ~/team-edr
sudo .venv/bin/python dashboard.py --database runs/ba-normal-1.db
```

Open `http://127.0.0.1:8080` in the Ubuntu browser.

#### 4. Generate two failed logins

On Kali:

```bash
for attempt in 1 2; do
  curl -s -o /dev/null -w 'HTTP %{http_code}\n' \
    -X POST http://192.168.100.100:3000/rest/user/login \
    -H 'Content-Type: application/json' \
    --data '{"email":"edr-test@example.invalid","password":"wrong-password"}'
  sleep 1
done
```

#### Expected Result

- Two HTTP `401` responses.
- Two matching `authentication_failure` events.
- No BA-001 alert or associated notification response.

Other collectors may increase the dashboard's total event count. This is a below-threshold control, not a complete evaluation of normal traffic.

### Test B: Repeated Failed-Login Attack

This test checks that five failed logins within ten seconds trigger BA-001.

#### 1. Start an independent test

Stop the agent and dashboard with **Ctrl+C**.

On Ubuntu:

```bash
cd ~/team-edr
nano config.json
```

Change the existing `database` field to:

```json
"database": "runs/ba-attack-1.db",
```

Use a filename that does not already contain test data.

#### 2. Restart the agent and dashboard

In Ubuntu terminal 1:

```bash
cd ~/team-edr
sudo .venv/bin/python agent.py --config config.json
```

In Ubuntu terminal 2:

```bash
cd ~/team-edr
sudo .venv/bin/python dashboard.py --database runs/ba-attack-1.db
```

Refresh `http://127.0.0.1:8080` and confirm that the required collector has started.

#### 3. Generate five failed logins

On Kali:

```bash
for attempt in 1 2 3 4 5; do
  curl -s -o /dev/null -w 'HTTP %{http_code}\n' \
    -X POST http://192.168.100.100:3000/rest/user/login \
    -H 'Content-Type: application/json' \
    --data '{"email":"edr-test@example.invalid","password":"wrong-password"}'
  sleep 1
done
```

#### Expected Result

- Five HTTP `401` responses.
- Five matching `authentication_failure` events within ten seconds.
- One BA-001 alert linked to the five supporting events.
- One recorded notification response.

Check the captured event timestamps. Slow requests can place the failures outside the detection window.

### Alert Evidence and Timing

Expand **Evidence and timing** in the dashboard to inspect:

| Field | Meaning |
| --- | --- |
| `source_ip` | Address that sent the login attempts |
| `target_ip` and `target_port` | Monitored Juice Shop service |
| `failed_attempts` | Number of failures supporting the alert |
| `window_seconds` | Configured detection window |
| `evidence_event_ids` | Identifiers linking the alert to its supporting events |
| `attack_to_detection_seconds` | Time from the first observed failed-login response to alert generation |
| `threshold_to_detection_seconds` | Time from the threshold-satisfying failure to alert generation |
| `synthetic` | `false` for live monitoring evidence |

In one observed live trial, five failures occurred within approximately **4.13 seconds**. The alert was generated approximately **4.57 seconds after the first observed failure**, or **0.44 seconds after the fifth failure**. These are individual trial measurements, not guaranteed performance.

### Evidence to Retain

For each test, retain:

- Kali terminal output showing HTTP response codes.
- Matching authentication events.
- The dashboard alert and notification response for the attack test.
- Evidence that the below-threshold test recorded failures without a BA-001 alert.
- The code version, configuration, database filename and test timestamps.

Exclude passwords, session tokens and other sensitive values from shared evidence.

### Repeating a Demonstration

An existing database such as `runs/live.db` may be reused for demonstrations. The agent configuration and dashboard command must reference the same database.

Previous events and alerts remain visible. Allow more than ten seconds without failed-login activity between demonstrations and identify new alerts by their timestamps.

For independent evaluation trials, restart the agent and use a fresh database filename.


## 6 IIV-001: Improper Input Validation – File Upload Type

**Contributor:** Maxwell Forrestal  
**Category:** Improper Input Validation / File Upload Type  
**Scope:** Detects file uploads to Juice Shop that use a disallowed filename extension and retains abnormal HTTP response detection as a secondary indicator.

### Implementation

The existing shared HTTP collector in `edr/collectors/http_auth.py` is extended to inspect Juice Shop `/file-upload` traffic using TShark. The collector continues to produce the existing events used by the other detection modules and additionally exposes multipart upload metadata, including the uploaded filename and MIME type, when available.

The detection rule is implemented in `edr/rules/improper_input.py` and registered as `IIV-001` in `edr/rules/registry.py`.

The rule uses two detection paths:

1. **Disallowed file extension:** A `POST /file-upload` request containing a filename whose extension is not in the configured allowlist generates an alert with the reason `disallowed_file_extension`.
2. **Abnormal upload response:** A `/file-upload` request that receives a configured abnormal HTTP response, currently HTTP `500`, generates an alert with the reason `abnormal_upload_response`.

The default allowed extensions are `.pdf` and `.zip`. These values are configurable in `config.json`.

The rule avoids generating a second IIV alert for the same observed upload stream when the disallowed-extension condition has already produced an alert and the request later produces an abnormal response.

The configured `notify_only` response mode records the alert and recommendation without automatically blocking the source or modifying the uploaded file.

### Requirements and Configuration

- Ubuntu VM running Juice Shop and the EDR.
- Kali VM with network access to Juice Shop.
- TShark installed on Ubuntu.
- HTTP collector enabled with the correct capture interface, Juice Shop IP and port.
- `IIV-001` enabled in `config.json`.
- Response mode set to `notify_only`.

Confirm that the installed TShark version exposes the multipart fields used by the collector:

```bash
tshark -G fields | grep "mime_multipart.header.content-disposition"
tshark -G fields | grep "mime_multipart.header.content-type"
```

The relevant rule configuration is:

```json
"IIV-001": {
  "enabled": true,
  "severity": 3,
  "status_codes": [500],
  "allowed_extensions": [
    ".pdf",
    ".zip"
  ]
}
```

Set the HTTP collector's `target_ip` to the actual Juice Shop VM address before testing. The examples below use `192.168.100.100`; replace it with the current lab address.

Start the EDR agent and dashboard using Section 3 of this README.

### Test A: Allowed File-Type Control

This test checks that an allowed `.zip` upload does not trigger IIV-001.

On Kali:

```bash
cd ~/Desktop
echo "Allowed upload test" > allowed.txt
zip -q allowed.zip allowed.txt

curl -i \
  -F "file=@/home/maxwell/Desktop/allowed.zip;type=application/zip" \
  http://192.168.100.100:3000/file-upload
```

**Expected result:**

- The request is visible to the HTTP collector.
- The `.zip` extension is in the configured allowlist.
- No `IIV-001` alert is generated.

### Test B: Disallowed File-Type Upload

This test checks that a structurally valid multipart upload using a disallowed `.txt` extension triggers IIV-001.

On Kali:

```bash
cd ~/Desktop
echo "ICT30016 improper input validation test" > test.txt

curl -i \
  -F "file=@/home/maxwell/Desktop/test.txt;type=text/plain" \
  http://192.168.100.100:3000/file-upload
```

**Expected result:**

- The collector observes `POST /file-upload`.
- The multipart metadata exposes the filename `test.txt`.
- The rule identifies `.txt` as outside the configured `.pdf` and `.zip` allowlist.
- An `IIV-001` alert is generated with the reason `disallowed_file_extension`.

### Test C: Malformed Upload / HTTP 500 Fallback

This test verifies the secondary abnormal-response detection path.

Using Firefox Developer Tools on Kali:

1. Perform a file upload to create a `POST /file-upload` request.
2. Open **Network**, select the upload request and use **Edit and Resend**.
3. Keep the request directed to `/file-upload` but make the multipart form incomplete, such as by removing its final closing boundary.
4. Resend the request.

**Expected result:**

- Juice Shop returns HTTP `500`.
- The collector creates the corresponding upload-response event.
- `IIV-001` generates an alert with the reason `abnormal_upload_response`.

This fallback identifies abnormal upload behaviour; it does not by itself prove that a restricted file was successfully stored.

### Integration Test

Run the agent with `BA-001`, `SQLI-001`, `IDOR-001` and `IIV-001` enabled together.

After confirming that the IIV tests still behave as expected, generate five failed Juice Shop login attempts using the BA-001 procedure in Section 5.

**Expected result:**

- The file-upload test generates `IIV-001`.
- The failed-login sequence generates `BA-001`.
- The failed-login sequence does not generate `IIV-001`.
- Both detections operate through the same agent, HTTP collector, storage and dashboard pipeline.

### Evidence and Results

- Automated test command: `.venv/bin/python -m unittest discover -s tests -v`
- **Automated result:** 22 tests passed (`OK`).
- A live `.txt` upload generated an `IIV-001` alert using the `disallowed_file_extension` detection path.
- A live allowed `.zip` control upload did not generate an `IIV-001` alert.
- A malformed upload producing HTTP `500` generated `IIV-001` using the `abnormal_upload_response` fallback.
- During integration testing, both `IIV-001` and `BA-001` generated their expected alerts while running in the same EDR agent.
- Evidence retained includes the Kali request/output, dashboard alerts, event details and automated test output.

### Limitations

- The file-type rule validates the observed filename extension; it does not inspect the uploaded file contents to prove that the content matches the extension or MIME type.
- The detector currently focuses on the Juice Shop `/file-upload` endpoint rather than every possible Improper Input Validation issue in the application.
- Multipart filename detection depends on TShark exposing the required `mime_multipart` fields.
- The HTTP `500` path is a secondary indicator of abnormal upload behaviour and does not by itself prove a successful validation bypass.
- `notify_only` records detections and recommendations but does not automatically block the source or quarantine files.


## 8 IDOR-001: Basket Enumeration (Broken Access Control)

**Contributor:** Devidboston Seang  
**Category:** Broken Access Control (IDOR)  
**Scope:** Detects one user reading several other users' baskets by changing the basket ID.

### Implementation

The HTTP collector uses TShark to read Juice Shop requests. A `GET /rest/basket/<id>` request produces a `basket_access` event.

The detection rule in `edr/rules/idor.py` generates a **Possible IDOR Basket Enumeration** alert when one source IP accesses **three or more different basket IDs within ten seconds**, grouped by monitored host and source IP.

The alert includes the supporting event IDs, the baskets accessed, and detection timing. The response handler records a notification; it does not automatically block the source.

Reading several different baskets indicates enumeration. It does not, by itself, prove the baskets belong to other accounts.

### Requirements and Configuration

- Ubuntu VM running Juice Shop and the EDR.
- Kali VM with network access to Juice Shop.
- HTTP collector enabled with the correct capture interface, target IP and port.
- `IDOR-001` enabled with a three-basket threshold and ten-second window.
- Response mode set to `notify_only`.

The attack script is in the repository at `attack_scripts/idor_basket_enum.py`. Copy it to the Kali VM (or clone the project there) before running the attack.

The commands below assume:

| Setting | Example value |
| --- | --- |
| Ubuntu project folder | `~/team-edr` |
| Capture interface | `ens33` |
| Juice Shop IP | `192.168.100.104` |
| Juice Shop port | `3000` |
| Kali IP | `192.168.100.200` |

Replace these values where they differ from the deployed lab environment. Run the tests only against an authorised lab instance.

### Test Accounts

The tests use two accounts, `usera` and `userb`. Juice Shop seeds baskets 1–5 automatically, so on a freshly started Juice Shop the two accounts you register receive the next IDs: **usera gets basket 6** and **userb gets basket 7**. Register `usera` first, then `userb`, to keep these IDs consistent. Juice Shop resets its accounts on restart, so recreate them each session, either way:

**On the Juice Shop website:** open `http://192.168.100.104:3000`, go to **Account → Login → Not yet a customer?**, and register `usera@test.com` then `userb@test.com` (password `Test1234!`).
add an item to the basket if empty.
**Or in a terminal:**

```bash
curl -s -X POST http://192.168.100.104:3000/api/Users/ -H 'Content-Type: application/json' \
  -d '{"email":"usera@test.com","password":"Test1234!","passwordRepeat":"Test1234!"}'
curl -s -X POST http://192.168.100.104:3000/api/Users/ -H 'Content-Type: application/json' \
  -d '{"email":"userb@test.com","password":"Test1234!","passwordRepeat":"Test1234!"}'
```

Basket 6 is usera's own basket (used in the normal test). Baskets 1–5 and 7 belong to others (read during the attack test to confirm the IDOR).

### Test A: Normal Activity

This test checks that reading only your own basket does not trigger IDOR-001.

#### 1. Configure an independent test

Stop any running agent and dashboard with **Ctrl+C**. On Ubuntu:

```bash
cd ~/team-edr
nano config.json
```

Set the `database` field to:

```json
"database": "runs/idor-normal-1.db",
```

#### 2. Start the agent

```bash
cd ~/team-edr
sudo .venv/bin/python agent.py --config config.json
```

Check that the HTTP collector starts without an error.

#### 3. Start the dashboard

```bash
cd ~/team-edr
sudo .venv/bin/python dashboard.py --database runs/idor-normal-1.db
```

Open `http://127.0.0.1:8080` in the Ubuntu browser.

#### 4. Read your own basket

On Kali:

```bash
python3 idor_basket_enum.py \
  --target-ip 192.168.100.104 --email usera@test.com --password 'Test1234!' \
  --start-id 6 --end-id 6
```

#### Expected Result

- Basket 6 is accessible.
- `basket_access` events are recorded.
- No IDOR-001 alert.

### Test B: Basket Enumeration Attack

This test checks that reading three or more baskets within ten seconds triggers IDOR-001.

#### 1. Start an independent test

Stop the agent and dashboard with **Ctrl+C**. On Ubuntu, change the `database` field to:

```json
"database": "runs/idor-attack-1.db",
```

#### 2. Restart the agent and dashboard

```bash
cd ~/team-edr
sudo .venv/bin/python agent.py --config config.json
```

```bash
cd ~/team-edr
sudo .venv/bin/python dashboard.py --database runs/idor-attack-1.db
```

Refresh `http://127.0.0.1:8080` and confirm the HTTP collector has started.

#### 3. Enumerate baskets

On Kali:

```bash
python3 idor_basket_enum.py \
  --target-ip 192.168.100.104 --email usera@test.com --password 'Test1234!' \
  --start-id 1 --end-id 7
```

#### Expected Result

- Baskets 1–7 are accessible using one account's token.
- One IDOR-001 alert linked to the first three distinct baskets.
- One recorded notification response.

### Alert Evidence and Timing

Expand **Evidence and timing** in the dashboard to inspect:

| Field | Meaning |
| --- | --- |
| `source_ip` | Address that sent the basket requests |
| `target_ip` and `target_port` | Monitored Juice Shop service |
| `distinct_baskets` | Number of different baskets accessed |
| `basket_ids` | The basket IDs that were read |
| `window_seconds` | Configured detection window |
| `evidence_event_ids` | Identifiers linking the alert to its supporting events |
| `attack_to_detection_seconds` | Time from the first basket request to alert generation |
| `threshold_to_detection_seconds` | Time from the third distinct basket to alert generation |
| `synthetic` | `false` for live monitoring evidence |

In one observed live trial, the alert was generated approximately **0.41 seconds after the first basket request**, or **0.36 seconds after the third distinct basket**. These are individual trial measurements, not guaranteed performance.

### Evidence to Retain

- Kali terminal output showing the baskets accessed.
- The matching `basket_access` events.
- The dashboard alert and notification response for the attack test.
- Evidence that the normal test recorded basket reads without an IDOR-001 alert.
- The code version, configuration, database filename and test timestamps.

## 7 SQLI-001: SQL Injection – Data Exfiltration

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


## 9. Arbitrary File Write 2

### 9.1 Implementation

The AFW2 detection rule is implemented in `edr/rules/afw.py`.

The rule detects a possible Arbitrary File Write 2 attack by correlating two artefacts collected by the EDR agent:

1. An HTTP `POST` request to the Juice Shop `/file-upload` endpoint.
2. A subsequent modification of the targeted `legal.md` file.

The rule uses the existing HTTP and filesystem event collectors rather than creating separate collectors. It maintains recent upload and file-modification events and compares their timestamps.

An alert is generated when the two events occur within the configured correlation window. This prevents a normal file upload or an unrelated file modification from automatically being classified as an AFW2 attack.

The rule generates an `AFW2-001` alert containing the relevant evidence event IDs, source and target information, timestamps and the affected file path.

### 9.2 Requirements and Configuration

The AFW2 rule requires the following components of the EDR agent to be enabled:

- HTTP/network event collection using `tshark`
- Filesystem event collection
- Juice Shop running and accessible to the EDR agent
- `AFW2-001` enabled in `config.json`

The rule uses a configurable correlation window. The default value is **10 seconds**.

The rule is registered with the EDR rule registry so that it receives events alongside the existing Broken Authentication, SQL Injection and IDOR detection rules.

### 9.3 Testing

#### Test A – Normal Activity

Perform normal Juice Shop activity without attempting to modify the protected `legal.md` file.

**Expected result:**

No `AFW2-001` alert should be generated.

This test verifies that normal application activity does not trigger the AFW2 detection.

#### Test B – AFW2 Attack

Perform the authorised Arbitrary File Write 2 attack against the Juice Shop instance.

The attack uses the file-upload functionality and sends a crafted ZIP archive containing the path-traversal filename:

```text
../../ftp/legal.md


## 8. Evaluation and evidence

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
| --- | --- |
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


## 8. Evaluation and evidence

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
| --- | --- |
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

