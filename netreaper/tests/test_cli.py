import os
import subprocess
import sys
from pathlib import Path

from netreaper import __version__

SRC = Path(__file__).resolve().parents[1] / "src"


def test_version_command():
    env = dict(os.environ)
    # Works whether or not the package has been pip-installed
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-m", "netreaper", "version"],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    assert __version__ in result.stdout
