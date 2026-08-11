#!/usr/bin/env python3

import os
import signal
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER = REPO_ROOT / "tools" / "testsuite" / "run-isolated.sh"


class RunIsolatedPortabilityTest(unittest.TestCase):
    def run_with_minimal_path(self, driver_source: str, timeout: int = 15):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()

            required_commands = (
                "bash",
                "basename",
                "date",
                "dirname",
                "grep",
                "head",
                "mkdir",
                "mktemp",
                "python3",
                "rm",
                "sed",
                "seq",
                "sleep",
                "sort",
                "tail",
                "tr",
                "uniq",
                "wc",
            )
            for command in required_commands:
                source = shutil.which(command)
                self.assertIsNotNone(source, f"required test command missing: {command}")
                (bin_dir / command).symlink_to(source)

            driver = tmp_path / "driver"
            driver.write_text(
                textwrap.dedent(driver_source),
                encoding="ascii",
            )
            driver.chmod(driver.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment["PATH"] = str(bin_dir)
            process = subprocess.Popen(
                [
                    str(bin_dir / "bash"),
                    str(RUNNER),
                    "--driver",
                    str(driver),
                    "--timeout",
                    "5",
                    "--mode",
                    "audit",
                ],
                cwd=REPO_ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                output, _ = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                os.killpg(process.pid, signal.SIGKILL)
                output, _ = process.communicate()
                self.fail(
                    f"runner did not finish within {timeout} seconds:\n"
                    f"{error.output or output}"
                )

            return process.returncode, output

    def test_runner_works_without_gnu_timeout_or_stdbuf(self):
        sandboxes_before = set(
            (REPO_ROOT / "testsuite").glob(".run-isolated-??????")
        )
        returncode, output = self.run_with_minimal_path(
            """\
            #!/usr/bin/env bash
            set -euo pipefail
            for argument in "$@"; do
              if [ "$argument" = "-ftest" ]; then
                echo "Checks succeeded."
                exit 0
              fi
            done
            trap 'exit 0' TERM INT
            echo "init_user_conn: port 0 assigned actual port 41001 for telnet"
            echo "init_user_conn: port 0 assigned actual port 41002 for websocket"
            echo "init_user_conn: port 0 assigned actual port 41003 for websocket"
            echo "init_user_conn: port 0 assigned actual port 41004 for telnet"
            echo "Accepting telnet connections on 127.0.0.1:41001."
            echo "Accepting websocket connections on 127.0.0.1:41002."
            echo "Accepting websocket connections on 127.0.0.1:41003."
            echo "Accepting telnet connections on 127.0.0.1:41004."
            while true; do
              sleep 1
            done
            """
        )

        self.assertEqual(returncode, 0, output)
        self.assertIn("LPC assertions ok", output)
        self.assertIn("41001 41002 41003 41004", output)
        self.assertFalse(
            (REPO_ROOT / "testsuite" / ".run-isolated.lockdir").exists(),
            "mkdir fallback lock was not released",
        )
        self.assertSetEqual(
            set((REPO_ROOT / "testsuite").glob(".run-isolated-??????")),
            sandboxes_before,
            "isolated runner left a new sandbox behind",
        )

    def test_non_bind_driver_failure_is_not_retried(self):
        returncode, output = self.run_with_minimal_path(
            """\
            #!/usr/bin/env bash
            set -euo pipefail
            for argument in "$@"; do
              if [ "$argument" = "-ftest" ]; then
                echo "init_user_conn: port 0 assigned actual port 41001 for telnet"
                echo "test fixture failure"
                exit 42
              fi
            done
            exit 42
            """
        )

        self.assertEqual(returncode, 1, output)
        self.assertEqual(output.count("== run-isolated: round="), 1, output)
        self.assertNotIn("bind failure; retrying", output)


if __name__ == "__main__":
    unittest.main()
