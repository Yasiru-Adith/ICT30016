
import hashlib
import os
import shutil
import stat
import time

from edr_core import Agent, Alert, LAB_DIR, base_parser

RISKY_EXTENSIONS = (".sh", ".py", ".elf", ".bin", ".so", ".php")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class FileIntegrityAgent(Agent):
    name = "fim-agent"

    def __init__(self, watch_dir, quarantine_dir, **kwargs):
        super().__init__(**kwargs)
        self.watch_dir = watch_dir
        self.quarantine_dir = quarantine_dir
        os.makedirs(watch_dir, exist_ok=True)
        os.makedirs(quarantine_dir, exist_ok=True)
        self.baseline = self.collect()
        print(f"[*] Baseline: {len(self.baseline)} files in {watch_dir}")

    def collect(self):
        hashes = {}
        for root, _dirs, files in os.walk(self.watch_dir):
            for name in files:
                path = os.path.join(root, name)
                try:
                    hashes[path] = sha256(path)
                except (PermissionError, FileNotFoundError):
                    pass
        return hashes

    def detect(self, current):
        alerts = []
        for path, digest in current.items():
            if path not in self.baseline:
                executable = os.access(path, os.X_OK)
                risky = executable or path.endswith(RISKY_EXTENSIONS)
                alerts.append(Alert(self.name, "HIGH" if risky else "MEDIUM",
                                    "New file created",
                                    {"path": path, "executable": executable,
                                     "sha256": digest[:16] + "..."}))
            elif self.baseline[path] != digest:
                alerts.append(Alert(self.name, "HIGH", "File modified",
                                    {"path": path, "old": self.baseline[path][:16] + "...",
                                     "new": digest[:16] + "..."}))
        for path in self.baseline.keys() - current.keys():
            alerts.append(Alert(self.name, "MEDIUM", "File deleted", {"path": path}))
        self.baseline = current  # accept the new state so we alert only once
        return alerts

    def respond(self, alert):
        if alert.severity != "HIGH" or alert.title == "File deleted":
            return
        src = alert.details["path"]
        dest = os.path.join(self.quarantine_dir,
                            f"{int(time.time())}_{os.path.basename(src)}")

        def quarantine():
            shutil.move(src, dest)
            os.chmod(dest, stat.S_IRUSR)          # read-only, not executable
            self.baseline.pop(src, None)

        self.act(f"quarantine {src} -> {dest}", quarantine)


if __name__ == "__main__":
    p = base_parser("File Integrity Monitoring agent")
    p.add_argument("--watch", default=os.path.join(LAB_DIR, "watched"))
    p.add_argument("--quarantine", default=os.path.join(LAB_DIR, "quarantine"))
    a = p.parse_args()
    FileIntegrityAgent(a.watch, a.quarantine,
                       respond=a.respond, interval=a.interval).run()
