
import os
import re
import subprocess
import time
from collections import defaultdict, deque

from edr_core import Agent, Alert, LAB_DIR, base_parser

LINE = re.compile(r'^(?P<ip>\S+).*?"(?P<method>\S+)\s(?P<path>\S+).*?"\s(?P<status>\d{3})')

SIGNATURES = {
    "SQL injection":  re.compile(r"('|%27)|(--)|(\bor\b\s+\d+=\d+)|union\s+select|sleep\(", re.I),
    "XSS":            re.compile(r"<script|%3cscript|onerror\s*=|javascript:", re.I),
    "Path traversal": re.compile(r"\.\./|\.\.%2f|/etc/passwd|%2e%2e", re.I),
    "Command inject": re.compile(r";\s*(cat|ls|id|whoami|nc)\b|\|\s*(bash|sh)\b", re.I),
}
LOGIN_PATH = re.compile(r"/(rest/user/login|login)", re.I)
BRUTE_WINDOW = 15        # seconds
BRUTE_LIMIT = 5          # failed logins from one IP in the window


class WebAttackAgent(Agent):
    name = "web-agent"

    def __init__(self, log_path, **kwargs):
        super().__init__(**kwargs)
        self.log_path = log_path
        self.failures = defaultdict(deque)   # ip -> timestamps of 401/500 logins
        self.blocked = set()
        open(log_path, "a").close()          # make sure it exists
        self.fh = open(log_path, "r")
        self.fh.seek(0, os.SEEK_END)          # only read new lines

    def collect(self):
        return self.fh.readlines()

    def detect(self, lines):
        alerts = []
        now = time.time()
        for raw in lines:
            m = LINE.match(raw)
            if not m:
                continue
            ip, path, status = m["ip"], m["path"], m["status"]
            for label, rx in SIGNATURES.items():
                if rx.search(path):
                    alerts.append(Alert(self.name, "HIGH", f"{label} attempt",
                                        {"ip": ip, "path": path[:120], "status": status}))
                    break
            if LOGIN_PATH.search(path) and status in ("401", "403", "500"):
                hits = self.failures[ip]
                hits.append(now)
                while hits and now - hits[0] > BRUTE_WINDOW:
                    hits.popleft()
                if len(hits) >= BRUTE_LIMIT:
                    alerts.append(Alert(self.name, "HIGH", "Brute-force login",
                                        {"ip": ip, "failures": len(hits),
                                         "window_s": BRUTE_WINDOW}))
                    hits.clear()
        return alerts

    def respond(self, alert):
        ip = alert.details.get("ip")
        if not ip or ip in self.blocked:
            return
        self.blocked.add(ip)

        def block():
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                           check=True, capture_output=True)

        self.act(f"iptables DROP all traffic from {ip}", block)


if __name__ == "__main__":
    p = base_parser("Web attack detection agent (Juice Shop)")
    p.add_argument("--log", default=os.path.join(LAB_DIR, "access.log"),
                   help="access log to monitor")
    a = p.parse_args()
    WebAttackAgent(a.log, respond=a.respond, interval=a.interval).run()
