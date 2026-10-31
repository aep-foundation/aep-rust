import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch


REPOSITORY = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "exception_check", REPOSITORY / "scripts/check-advisory-exception.py"
)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class AdvisoryExceptionTest(unittest.TestCase):
    def audit(self, dependencies, expected, diagnostic=None, config=None):
        with tempfile.TemporaryDirectory(prefix="aep-advisory-test-") as temporary:
            probe = Path(temporary)
            (probe / "src").mkdir()
            (probe / "src/lib.rs").write_text("")
            (probe / "Cargo.toml").write_text(
                '[package]\nname = "advisory-test"\nversion = "0.0.0"\n'
                'edition = "2021"\n[dependencies]\n' + dependencies
            )
            config_path = REPOSITORY / "deny.toml"
            if config is not None:
                config_path = probe / "deny.toml"
                config_path.write_text(config)
            result = subprocess.run(
                ["cargo", "deny", "--format", "json", "check", "advisories",
                 "--disable-fetch", "--config", str(config_path)],
                cwd=probe, capture_output=True, text=True, timeout=180,
            )
            self.assertEqual(result.returncode, expected, result.stderr)
            if diagnostic:
                self.assertIn(diagnostic, result.stderr)

    def test_current_vulnerability_is_excepted(self):
        self.audit('crypto-bigint = "=0.5.5"\n', 0)

    def test_patched_dependency_requires_exception_removal(self):
        self.audit('crypto-bigint = "0.7.6"\n', 1, "advisory-not-detected")

    def test_removed_dependency_requires_exception_removal(self):
        self.audit("", 1, "advisory-not-detected")

    def test_partially_upgraded_graph_still_needs_exception(self):
        self.audit(
            'old = { package = "crypto-bigint", version = "=0.5.5" }\n'
            'patched = { package = "crypto-bigint", version = "0.7.6" }\n', 0,
        )

    def test_unexcepted_vulnerability_still_fails(self):
        self.audit('crypto-bigint = "=0.5.5"\n', 1, "vulnerability", "[advisories]\n")

    def test_configuration_ignores_only_the_approved_advisory(self):
        config = tomllib.loads((REPOSITORY / "deny.toml").read_text())
        self.assertEqual(
            [entry["id"] for entry in config["advisories"]["ignore"]],
            ["RUSTSEC-2026-0387"],
        )
        self.assertEqual(config["advisories"]["unused-ignored-advisory"], "deny")

    def test_probe_retains_features_but_not_current_version_constraints(self):
        workspace = tomllib.loads((REPOSITORY / "Cargo.toml").read_text())["workspace"]
        probe = tomllib.loads(CHECK.probe_manifest(workspace))["dependencies"]
        for name in ("jwt-compact", "p256"):
            self.assertEqual(probe[name]["version"], "*")
            for field in ("features", "default-features"):
                self.assertEqual(probe[name][field], workspace["dependencies"][name][field])

    def test_failed_resolution_does_not_allow_exception_and_cleans_up(self):
        with patch.object(CHECK.subprocess, "run") as run:
            run.side_effect = subprocess.TimeoutExpired("cargo", 180)
            with self.assertRaises(subprocess.TimeoutExpired):
                CHECK.check(REPOSITORY)
            self.assertEqual(run.call_count, 1)
            self.assertFalse(Path(run.call_args.kwargs["cwd"]).exists())


if __name__ == "__main__":
    unittest.main()
