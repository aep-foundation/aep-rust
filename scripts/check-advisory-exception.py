#!/usr/bin/env python3
"""Fail when stable upstream signing dependencies no longer need the exception."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib


def probe_manifest(workspace):
    lines = [
        '[package]',
        'name = "aep-advisory-probe"',
        'version = "0.0.0"',
        'edition = "2021"',
        'resolver = "2"',
        '[dependencies]',
    ]
    for name in ("jwt-compact", "p256"):
        dependency = workspace["dependencies"][name]
        features = json.dumps(dependency["features"])
        defaults = str(dependency.get("default-features", True)).lower()
        lines.append(
            f'{name} = {{ version = "*", default-features = {defaults}, features = {features} }}'
        )
    return "\n".join(lines) + "\n"


def check(repository):
    workspace = tomllib.loads((repository / "Cargo.toml").read_text())["workspace"]
    with tempfile.TemporaryDirectory(prefix="aep-advisory-") as temporary:
        probe = Path(temporary)
        manifest = probe / "Cargo.toml"
        manifest.write_text(probe_manifest(workspace))
        (probe / "src").mkdir()
        (probe / "src/lib.rs").write_text("")
        subprocess.run(
            ["cargo", "generate-lockfile", "--manifest-path", str(manifest)],
            cwd=probe,
            check=True,
            timeout=180,
        )
        subprocess.run(
            [
                "cargo", "deny", "--manifest-path", str(manifest), "--locked",
                "check", "advisories", "--config", str(repository / "deny.toml"),
            ],
            cwd=probe,
            check=True,
            timeout=180,
        )
    print("RUSTSEC-2026-0387 exception is still required by stable upstream signing dependencies.")


if __name__ == "__main__":
    try:
        check(Path(__file__).resolve().parent.parent)
    except (subprocess.SubprocessError, OSError, KeyError, ValueError) as error:
        print(
            "Advisory exception check failed. An advisory-not-detected error means "
            "upstream is patched: update the signing dependencies and remove the exception "
            "and its probe. Other errors require investigation; the check was not skipped. "
            f"{error}",
            file=sys.stderr,
        )
        sys.exit(1)
