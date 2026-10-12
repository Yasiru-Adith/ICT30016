from edr.rules.broken_auth import BrokenAuth

RULES = {'BA-001': BrokenAuth}


def load_rules(config):
    result = []
    for name, settings in config.items():
        if settings.get('enabled'):
            if name not in RULES:
                raise ValueError(f'Unknown rule: {name}')
            result.append(RULES[name](settings))
    return result
