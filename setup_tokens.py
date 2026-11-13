from __future__ import annotations

import getpass
import logging
import os
import sys

from config import parse_orgs, token_var

log = logging.getLogger("okta-change-auditor.setup")

try:
    import keyring
except ImportError:
    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(levelname)s: %(message)s")
    log.error("the optional 'keyring' extra is not installed. Run: pip install '.[keyring]'")
    sys.exit(1)

KEYRING_SERVICE = "okta-change-auditor"


def _say(text: str = "") -> None:
    """Write interactive wizard text to stdout."""
    sys.stdout.write(text + "\n")


def main() -> None:
    orgs = parse_orgs(os.environ.get("OKTA_ORGS", ""))
    tokens = [(token_var(name), f"{name} ({url})") for name, url in orgs.items()]

    _say("\nOkta Change Auditor — Token Setup")
    _say("=" * 42)
    _say("Tokens will be stored in your OS credential store.")
    _say("Press Enter to keep an existing token unchanged.\n")

    changed = 0
    for var, label in tokens:
        existing = keyring.get_password(KEYRING_SERVICE, var)
        hint = " [already set]" if existing else " [not set]"
        value = getpass.getpass(f"{label}{hint}\n  Enter token (Enter to skip): ")
        if value.strip():
            keyring.set_password(KEYRING_SERVICE, var, value.strip())
            _say(f"  ✓ {var} saved.\n")
            changed += 1
        else:
            _say(f"  – {var} unchanged.\n")

    _say(f"Done. {changed} token(s) updated.")
    if changed:
        _say("Restart the app to pick up the new tokens.\n")


if __name__ == "__main__":
    main()
