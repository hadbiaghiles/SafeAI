#!/usr/bin/env python3
"""Local end-to-end integration for the SafeAI GitHub Action (no bash).

Simulates the composite action on a machine without a GitHub runner: builds
the distribution, installs the wheel into a throwaway virtualenv, runs the
scan through the same ``python -m safeai`` module interface the action uses,
and validates the produced SARIF and exit code.

Usage::

    python scripts/run_local_integration.py <scan-dir> [--fail-on critical|high|medium]
        [--sarif PATH] [--expect-exit 0|1|2]

All artifacts are created under a temporary directory that is cleaned up on
success.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import venv
import zipfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def build_wheel(out_dir):
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", out_dir],
        cwd=REPO_ROOT,
        check=True,
    )
    wheels = [n for n in os.listdir(out_dir) if n.endswith(".whl")]
    if len(wheels) != 1:
        raise SystemExit(f"expected exactly one wheel in {out_dir}, got {wheels}")
    return os.path.join(out_dir, wheels[0])


def install_into_venv(venv_dir, wheel):
    venv.create(venv_dir, with_pip=True, system_site_packages=True)
    py = os.path.join(venv_dir, "Scripts", "python.exe") if os.name == "nt" else os.path.join(venv_dir, "bin", "python")
    subprocess.run([py, "-m", "pip", "install", "--no-deps", "--quiet", wheel], check=True)
    return py


def run_scan(python, scan_dir, fail_on, sarif):
    args = [python, "-m", "safeai", "scan", scan_dir, "--fail-on", fail_on, "--no-registry"]
    if sarif:
        args += ["--sarif", sarif]
    env = dict(os.environ)
    env["PYTHONPATH"] = ""  # do not leak the source tree
    return subprocess.run(args, cwd=tempfile.mkdtemp(prefix="safeai-local-"), env=env, check=False)


def validate_sarif(sarif):
    if not sarif or not os.path.exists(sarif):
        raise SystemExit(f"SARIF file missing: {sarif}")
    with open(sarif, encoding="utf-8") as fh:
        doc = json.load(fh)
    if doc.get("version") != "2.1.0" or "runs" not in doc:
        raise SystemExit(f"invalid SARIF document: {sarif}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan_dir")
    parser.add_argument("--fail-on", default="critical", choices=["critical", "high", "medium"])
    parser.add_argument("--sarif", default="safeai-results.sarif")
    parser.add_argument("--expect-exit", type=int, default=0)
    args = parser.parse_args(argv)

    scan_dir = os.path.abspath(args.scan_dir)
    if not os.path.isdir(scan_dir):
        raise SystemExit(f"scan directory does not exist: {scan_dir}")

    tmp = tempfile.mkdtemp(prefix="safeai-local-")
    try:
        wheel = build_wheel(tmp)
        print(f"built wheel: {wheel}")

        with zipfile.ZipFile(wheel) as zf:
            names = set(zf.namelist())
            for required in (
                "safeai/rules/base_rules.yaml",
                "safeai/cmd/cli.py",
                "safeai/report/sarif.py",
            ):
                if required not in names:
                    raise SystemExit(f"wheel missing package data: {required}")
        print("wheel contains package data: OK")

        venv_dir = os.path.join(tmp, "venv")
        python = install_into_venv(venv_dir, wheel)

        sarif = os.path.join(tmp, args.sarif)
        proc = run_scan(python, scan_dir, args.fail_on, sarif)
        validate_sarif(sarif)
        if args.expect_exit is not None and proc.returncode != args.expect_exit:
            raise SystemExit(
                f"exit code {proc.returncode} != expected {args.expect_exit}"
            )
        print(f"scan exit code {proc.returncode}: OK")
        print(f"SARIF valid (2.1.0): OK -> {sarif}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())