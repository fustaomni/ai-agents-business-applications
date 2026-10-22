# tests/test_strict_gateway.py
"""The gateway starts, decides and records on strict models, proven before they are (D.147).

The last models on the ratchet sit under every run. If a strict one refused a value the gateway
builds, the gateway would stop, and with it every governed way to undo the change. So this proof
runs the gateway in a separate process from strict copies of those modules, ahead of the real
ones on the path. Once the repository's own are strict, the copies equal them and the proof
still shows the gateway runs end to end in a fresh process.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
MODULES = ("spine.py", "command_outcome.py", "claim.py", "signing.py", "git_isolation.py")
LAX = 'model_config = ConfigDict(frozen=True, extra="forbid")'
STRICT = 'model_config = ConfigDict(frozen=True, extra="forbid", strict=True)'

DRIVE = """
import sys
from pathlib import Path

from securesystemslib.signer import CryptoSigner

import command_outcome
import spine
from run_task import main

if spine.Decision.model_config.get("strict") is not True:
    raise SystemExit("the strict copy of spine was not the one imported")
if command_outcome.CommandOutcome.model_config.get("strict") is not True:
    raise SystemExit("the strict copy of command_outcome was not the one imported")
signer = CryptoSigner.generate_ed25519()
ledger = Path(sys.argv[1])
launcher = (sys.executable, sys.argv[2])
declared = frozenset({"ok"})
if main(["ok"], ledger=ledger, launcher=launcher, declared=declared, signer=signer) != 0:
    raise SystemExit("a declared task did not run")
if main(["nope"], ledger=ledger, launcher=launcher, declared=declared, signer=signer) != 2:
    raise SystemExit("an undeclared task was not refused")
decision = spine.decide(spine.unknown("probe", "probe", Path(sys.argv[3]), "probe"))
command_outcome.announce("probe", decision, "probed", "a JSON payload", {"pair": ["a", "b"]})
"""


def test_the_gateway_runs_on_strict_models(tmp_path: Path) -> None:
    copies = tmp_path / "strict"
    copies.mkdir()
    for name in MODULES:
        text = (SCRIPTS / name).read_text(encoding="utf-8")
        (copies / name).write_text(text.replace(LAX, STRICT), "utf-8")
    task = tmp_path / "task.py"
    task.write_text('print("hi")\n', encoding="utf-8")
    environment = {**os.environ, "PYTHONPATH": os.pathsep.join((str(copies), str(SCRIPTS)))}
    done = subprocess.run(
        [sys.executable, "-c", DRIVE, str(tmp_path / "ledger.jsonl"), str(task), str(tmp_path)],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr[-4000:]
