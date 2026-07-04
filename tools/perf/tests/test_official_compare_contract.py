import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OFFICIAL_COMPARE = ROOT / "perf" / "official_compare"


class OfficialCompareContractTest(unittest.TestCase):
    def test_loadtest_help_exposes_required_arguments(self):
        result = subprocess.run(
            [sys.executable, str(OFFICIAL_COMPARE / "portable_fluffos_loadtest.py"), "--help"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=True,
        )
        help_text = result.stdout
        for token in (
            "--users",
            "--duration",
            "--ramp-up",
            "--sync-start",
            "--think-min",
            "--think-max",
            "--report-json",
            "--driver-checksum",
        ):
            self.assertIn(token, help_text)

    def test_runner_help_exposes_fixed_comparison_surface(self):
        result = subprocess.run(
            [sys.executable, str(OFFICIAL_COMPARE / "run_official_vs_xk.py"), "--help"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=True,
        )
        help_text = result.stdout
        for token in (
            "--official-master-ref",
            "--official-stable-ref",
            "--official-master-source",
            "--official-master-build",
            "--xk-source",
            "--xk-common-build",
            "--skip-build",
            "--report-json",
            "--base-port",
        ):
            self.assertIn(token, help_text)

    def test_portable_mudlib_contains_common_only_entrypoints(self):
        mudlib = OFFICIAL_COMPARE / "portable_mudlib"
        for relative in (
            "etc/config.template",
            "single/master.c",
            "single/simul_efun.c",
            "clone/login.c",
            "clone/user.c",
            "std/bench_target.c",
        ):
            self.assertTrue((mudlib / relative).exists(), relative)
        bench = (mudlib / "std/bench_target.c").read_text(encoding="utf-8")
        self.assertIn("call_other", bench)
        self.assertIn("destruct(ob)", bench)
        self.assertNotIn("vm_owner_", bench)
        self.assertNotIn("gateway", bench.lower())

    def test_analyzer_accepts_minimal_runner_json(self):
        sample = {
            "schema": "fluffos_official_vs_xk_runner_v1",
            "targets": [
                {
                    "target": "official_master",
                    "commit": "abcdef123456",
                    "driver_exit_status": 0,
                    "loadtest_report": "/tmp/official.json",
                    "driver_log": "/tmp/official.log",
                    "summary": {
                        "commands_per_second": 100.0,
                        "failures": 0,
                        "latency_ms": {"p50": 1.0, "p95": 2.0, "p99": 3.0},
                    },
                },
                {
                    "target": "xk_common_gateway_off",
                    "commit": "123456abcdef",
                    "driver_exit_status": 0,
                    "loadtest_report": "/tmp/xk.json",
                    "driver_log": "/tmp/xk.log",
                    "summary": {
                        "commands_per_second": 90.0,
                        "failures": 0,
                        "latency_ms": {"p50": 1.1, "p95": 2.5, "p99": 4.0},
                    },
                },
            ],
        }
        tmp = Path("/tmp/official_compare_contract.json")
        out = Path("/tmp/official_compare_contract.md")
        tmp.write_text(json.dumps(sample), encoding="utf-8")
        subprocess.run(
            [
                sys.executable,
                str(OFFICIAL_COMPARE / "analyze_official_vs_xk.py"),
                str(tmp),
                "--output-md",
                str(out),
            ],
            check=True,
        )
        report = out.read_text(encoding="utf-8")
        self.assertIn("xk_common_gateway_off", report)
        self.assertIn("common-path regression", report)
        self.assertIn("中文摘要", report)


if __name__ == "__main__":
    unittest.main()
