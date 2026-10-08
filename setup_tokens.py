from __future__ import annotations

import getpass
import sys

try:
    import keyring
except ImportError:
    print("ERROR: 'keyring' package not installed.")
    print("Run:  pip install keyring")
    sys.exit(1)

KEYRING_SERVICE = "okta-change-auditor"

TOKENS = [
    ("OKTA_AUDITOR_DEV_API_TOKEN",  "DEV  (https://host.example.com)"),
    ("OKTA_AUDITOR_STG_API_TOKEN",  "STG  (https://host.example.com)"),
    ("OKTA_AUDITOR_PROD_API_TOKEN", "PROD (https://host.example.com)"),
]


def main() -> None:
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
