import json
import importlib.util
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

    def test_truth_gate_help_exposes_required_arguments(self):
        result = subprocess.run(
            [sys.executable, str(OFFICIAL_COMPARE / "run_perf_truth_gate.py"), "--help"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=True,
        )
        help_text = result.stdout
        for token in (
            "--matrix",
            "--runner-json",
            "--report-json",
            "--skip-build",
            "--microbench-summary",
            "--skip-stable",
            "--evaluate-only",
        ):
            self.assertIn(token, help_text)

    def test_runner_records_progress_resources_and_log_tail(self):
        source = (OFFICIAL_COMPARE / "run_official_vs_xk.py").read_text(encoding="utf-8")
        for token in (
            "[official_compare] configure/build target=",
            "[official_compare] starting driver target=",
            "[official_compare] running loadtest target=",
            "[official_compare] finished target=",
            '"timing"',
            '"load_generator_resource"',
            '"driver_process_start_snapshot"',
            '"driver_process_end_snapshot"',
            '"driver_log_tail"',
            '"runtime_config_overrides"',
            "multicore mode : off",
            "multicore mode : audit",
        ):
            self.assertIn(token, source)

    def test_truth_gate_records_schema_and_regression_rules(self):
        source = (OFFICIAL_COMPARE / "run_perf_truth_gate.py").read_text(encoding="utf-8")
        for token in (
            "fluffos_perf_truth_gate_v1",
            "gate_result",
            "top_regressions",
            "top_improvements",
            "clone_destruct",
            "call_other_self",
            "xk_common_p99_vs_official",
            "xk_common_cps_vs_official",
        ):
            self.assertIn(token, source)

    def test_runner_and_gate_treat_empty_path_defaults_as_unset(self):
        for module_name, file_name in (
            ("run_official_vs_xk", "run_official_vs_xk.py"),
            ("run_perf_truth_gate", "run_perf_truth_gate.py"),
        ):
            spec = importlib.util.spec_from_file_location(module_name, OFFICIAL_COMPARE / file_name)
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            self.assertIsNone(module.optional_path(Path("")))
            self.assertIsNone(module.optional_path(Path(".")))
            self.assertEqual(module.optional_path(Path("/tmp/fluffos-xk")), Path("/tmp/fluffos-xk"))

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

    def test_truth_gate_evaluator_accepts_minimal_reports(self):
        spec = importlib.util.spec_from_file_location(
            "run_perf_truth_gate", OFFICIAL_COMPARE / "run_perf_truth_gate.py"
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        sys.modules["run_perf_truth_gate"] = module
        spec.loader.exec_module(module)
        runner = {
            "schema": "fluffos_official_vs_xk_runner_v1",
            "targets": [
                {
                    "target": "official_master",
                    "summary": {
                        "commands_per_second": 1000.0,
                        "failures": 0,
                        "timeouts": 0,
                        "disconnected": 0,
                        "latency_ms": {"p99": 2.0},
                    },
                },
                {
                    "target": "xk_common_gateway_off",
                    "summary": {
                        "commands_per_second": 600.0,
                        "failures": 0,
                        "timeouts": 0,
                        "disconnected": 0,
                        "latency_ms": {"p99": 4.0},
                    },
                },
            ],
        }
        microbench = {
            "schema": "fluffos_portable_bench_v1",
            "drivers": {
                "official_master_common": {
                    "runs": [
                        {
                            "metrics": {
                                "clone_destruct": {"per_ns": 100.0},
                                "call_other_self": {"per_ns": 100.0},
                            }
                        }
                    ]
                },
                "xk_common_gateway_off": {
                    "runs": [
                        {
                            "metrics": {
                                "clone_destruct": {"per_ns": 250.0},
                                "call_other_self": {"per_ns": 120.0},
                            }
                        }
                    ]
                },
            },
        }
        stage_gate = module.evaluate_gate("stage", runner, microbench, 0)
        self.assertEqual(stage_gate["status"], "pass")
        final_gate = module.evaluate_gate("final", runner, microbench, 0)
        self.assertEqual(final_gate["status"], "fail")
        failed_names = {item["name"] for item in final_gate["top_regressions"]}
        self.assertIn("clone_destruct", failed_names)
        self.assertIn("xk_common_cps_vs_official", failed_names)


if __name__ == "__main__":
    unittest.main()
