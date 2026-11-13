from __future__ import annotations

import getpass
import os
import sys

from config import parse_orgs, token_var

try:
    import keyring
except ImportError:
    print("ERROR: the optional 'keyring' extra is not installed.")
    print("Run:  pip install '.[keyring]'")
    sys.exit(1)

KEYRING_SERVICE = "okta-change-auditor"


def main() -> None:
    orgs = parse_orgs(os.environ.get("OKTA_ORGS", ""))
    TOKENS = [(token_var(name), f"{name} ({url})") for name, url in orgs.items()]

    print("\nOkta Change Auditor — Token Setup")
    print("=" * 42)
    print("Tokens will be stored in your OS credential store.")
    print("Press Enter to keep an existing token unchanged.\n")

    changed = 0
    for var, label in TOKENS:
        existing = keyring.get_password(KEYRING_SERVICE, var)
        hint = " [already set]" if existing else " [not set]"
        value = getpass.getpass(f"{label}{hint}\n  Enter token (Enter to skip): ")
        if value.strip():
            keyring.set_password(KEYRING_SERVICE, var, value.strip())
            print(f"  ✓ {var} saved.\n")
            changed += 1
        else:
            print(f"  – {var} unchanged.\n")

    print(f"Done. {changed} token(s) updated.")
    if changed:
        print("Restart the app to pick up the new tokens.\n")


if __name__ == "__main__":
    main()
