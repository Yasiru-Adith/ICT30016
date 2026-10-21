from edr.rules.broken_auth import BrokenAuth
from edr.rules.sqli_exfiltration import SQLiExfiltration
from edr.rules.idor import IDOR
from edr.rules.afw2 import AFW2
from edr.rules.improper_input import ImproperInputValidation


RULES = {
    "BA-001": BrokenAuth,
    "SQLI-001": SQLiExfiltration,
    "IDOR-001": IDOR,
    "AFW2-001": AFW2,
    "IIV-001": ImproperInputValidation,
}


def load_rules(config):
    result = []

    for name, settings in config.items():
        if settings.get("enabled"):
            if name not in RULES:
                raise ValueError(f"Unknown rule: {name}")

            result.append(RULES[name](settings))

    return result
