# tests/test_bounded.py
"""A bounded runner ends a child's whole process group at its deadline (D.169).

REAL PROCESSES, NOTHING STUBBED: what is proven is the operating system's behaviour -- a
grandchild in the group, a signal that is ignored -- so no fake may stand in for it. The child
programs are one-line python -c scripts with no escape sequences; paths travel as arguments.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from bounded import Exited, LaunchFailed, Signaled, TimedOut, run

PYTHON = sys.executable
GRANDCHILD = (
    "import os, signal, sys, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
    "open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(60)"
)
PARENT = (
    "import subprocess, sys, time; "
    "subprocess.Popen([sys.executable, '-c', sys.argv[2], sys.argv[1]]); time.sleep(60)"
)
IGNORES_TERM = "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"


def _gone(pid: int, within: float = 5.0) -> bool:
    end = time.monotonic() + within
    while time.monotonic() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def test_a_grandchild_ignoring_sigterm_is_gone_after_the_timeout(tmp_path: Path) -> None:
    """subprocess.run(timeout=) would leave this grandchild running."""
    mark = tmp_path / "grandchild.pid"
    result = run([PYTHON, "-c", PARENT, str(mark), GRANDCHILD], deadline=3.0, grace=0.5)
    assert isinstance(result.termination, TimedOut), result
    assert mark.is_file(), "the grandchild never started, so nothing was proven"
    assert _gone(int(mark.read_text(encoding="utf-8"))), "the grandchild outlived the timeout"


def test_a_leader_ignoring_sigterm_is_killed_within_its_grace() -> None:
    """SIGTERM ignored is escalated to SIGKILL, and the run stays bounded by deadline and grace."""
    result = run([PYTHON, "-c", IGNORES_TERM], deadline=1.0, grace=0.5)
    assert isinstance(result.termination, TimedOut), result
    assert result.termination.escalated, result
    assert result.duration_seconds < 4.0, result


def test_a_cooperative_child_needs_no_escalation() -> None:
    result = run([PYTHON, "-c", "import time; time.sleep(60)"], deadline=1.0, grace=2.0)
    assert isinstance(result.termination, TimedOut), result
    assert not result.termination.escalated, result


def test_a_signal_death_is_reported_by_name() -> None:
    program = "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"
    result = run([PYTHON, "-c", program], deadline=10.0)
    assert result.termination == Signaled(name="SIGKILL", number=9), result


def test_a_missing_program_is_launch_failed() -> None:
    result = run(["definitely-not-a-program-d169"], deadline=10.0)
    assert isinstance(result.termination, LaunchFailed), result
    assert result.termination.program == "definitely-not-a-program-d169", result


def test_an_exit_code_and_output_are_kept() -> None:
    program = "import sys; print('hello'); sys.exit(3)"
    result = run([PYTHON, "-c", program], deadline=10.0)
    assert result.termination == Exited(code=3), result
    assert result.stdout.strip() == "hello", result


def test_a_deadline_is_positive() -> None:
    with pytest.raises(ValueError, match="positive deadline"):
        run([PYTHON, "-c", "pass"], deadline=0)
