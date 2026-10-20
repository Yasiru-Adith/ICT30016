from edr.rules.broken_auth import BrokenAuth
from edr.rules.sqli_exfiltration import SQLiExfiltration
from edr.rules.idor import IDOR

RULES = {
    "BA-001": BrokenAuth,
    "SQLI-001": SQLiExfiltration,
    "IDOR-001": IDOR,
}


def load_rules(config):
    result = []

    for name, settings in config.items():
        if settings.get("enabled"):
            if name not in RULES:
                raise ValueError(f"Unknown rule: {name}")

            result.append(RULES[name](settings))

    return result
