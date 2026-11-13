import re
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"


def _cmd_line() -> str:
    for line in DOCKERFILE.read_text().splitlines():
        if line.startswith("CMD"):
            return line
    raise AssertionError("Dockerfile has no CMD")


def test_cmd_flags_are_separated_by_spaces():
    cmd = _cmd_line()
    # A flag value must not run into the next flag (for example "2--threads").
    assert not re.search(r"\w--\w", cmd)
    assert "--workers 2 --threads 4" in cmd


def test_cmd_reads_port():
    assert "${PORT}" in _cmd_line()
