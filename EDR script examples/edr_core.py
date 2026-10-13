
import argparse
import datetime
import json
import os
import time
from dataclasses import dataclass, field, asdict

LAB_DIR = os.path.expanduser(os.environ.get("EDR_LAB_DIR", "~/edr_lab"))
ALERT_LOG = os.path.join(LAB_DIR, "alerts.jsonl")

COLOURS = {"LOW": "\033[94m", "MEDIUM": "\033[93m", "HIGH": "\033[91m"}
RESET = "\033[0m"


@dataclass
class Alert:
    agent: str
    severity: str            # LOW | MEDIUM | HIGH
    title: str
    details: dict = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now().isoformat(timespec="seconds"))


def raise_alert(alert: Alert) -> None:
    """ALERT step: show on screen and keep a permanent record."""
    colour = COLOURS.get(alert.severity, "")
    print(f"{colour}[{alert.timestamp}] [{alert.severity}] "
          f"{alert.agent}: {alert.title}{RESET}")
    for key, value in alert.details.items():
        print(f"      {key}: {value}")
    os.makedirs(LAB_DIR, exist_ok=True)
    with open(ALERT_LOG, "a") as log:
        log.write(json.dumps(asdict(alert)) + "\n")


class Agent:
    """Base class. Subclasses override collect(), detect() and respond()."""
    name = "base-agent"

    def __init__(self, respond: bool = False, interval: float = 2.0):
        self.respond_enabled = respond
        self.interval = interval

    # ---- the three methods each agent implements ----
    def collect(self):
        raise NotImplementedError

    def detect(self, telemetry) -> list:
        raise NotImplementedError

    def respond(self, alert: Alert) -> None:
        pass  # optional

    # ---- helper so every response respects dry-run mode ----
    def act(self, description: str, action) -> None:
        if self.respond_enabled:
            try:
                action()
                print(f"      \033[92m[RESPONSE] {description}{RESET}")
            except Exception as err:  # never let a response crash the agent
                print(f"      [RESPONSE FAILED] {description}: {err}")
        else:
            print(f"      [DRY-RUN] would: {description}  (use --respond)")

    # ---- the main loop ----
    def run_once(self) -> None:
        for alert in self.detect(self.collect()):
            raise_alert(alert)
            self.respond(alert)

    def run(self) -> None:
        mode = "RESPOND" if self.respond_enabled else "DRY-RUN"
        print(f"[*] {self.name} started ({mode}, every {self.interval}s). Ctrl+C to stop.")
        try:
            while True:
                self.run_once()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print(f"\n[*] {self.name} stopped.")


def base_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--respond", action="store_true",
                        help="actually perform responses (default is dry-run)")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="seconds between checks (default 2)")
    return parser
