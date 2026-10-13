
import os
import time

from edr_core import LAB_DIR, base_parser
from agent_fim import FileIntegrityAgent
from agent_process import ProcessAgent
from agent_web import WebAttackAgent


def main():
    p = base_parser("Mini EDR - all agents together")
    a = p.parse_args()
    os.makedirs(LAB_DIR, exist_ok=True)

    agents = [
        FileIntegrityAgent(os.path.join(LAB_DIR, "watched"),
                           os.path.join(LAB_DIR, "quarantine"),
                           respond=a.respond, interval=a.interval),
        ProcessAgent(respond=a.respond, interval=a.interval),
        WebAttackAgent(os.path.join(LAB_DIR, "access.log"),
                       respond=a.respond, interval=a.interval),
    ]
    mode = "RESPOND" if a.respond else "DRY-RUN"
    print(f"[*] Mini-EDR online with {len(agents)} agents ({mode}). Ctrl+C to stop.\n")
    try:
        while True:
            for agent in agents:
                agent.run_once()
            time.sleep(a.interval)
    except KeyboardInterrupt:
        print("\n[*] Mini-EDR shut down.")


if __name__ == "__main__":
    main()
