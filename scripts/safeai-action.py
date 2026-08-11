#!/usr/bin/env python3
"""Driver for the SafeAI GitHub composite action.

Runs inside ``action.yml``. The composite action passes every input to this
script through the ``INPUT_*`` environment variables that GitHub Actions
exposes to composite-action steps, so no user-controlled value ever reaches a
shell command line.

Behavior:

* Validates inputs (severity threshold, version, path existence, extra-args).
* Installs ``SafeAI-Static-Analyzer`` from PyPI by default; installs the exact
  version when ``INPUT_VERSION`` is set. Install can be skipped with the
  ``SAFEAI_ACTION_SKIP_INSTALL=true`` env var (used by local tests only).
* Builds the ``python -m safeai scan ...`` argv as a plain Python list and
  executes it without a shell, preserving SafeAI's native exit code.
* Resolves ``path``/``sarif`` to absolute paths against the workspace and runs
  the scan from a neutral working directory, so the CLI runs the *installed*
  package rather than any ``safeai/`` directory the checked-out repository may
  contain.
* Creates the SARIF parent directory and leaves the SARIF artifact in place
  even when the scan returns a policy-failure exit code, so a later
  ``upload-sarif`` step with ``if: always()`` still has a file to upload.
* Writes ``sarif-path`` to ``$GITHUB_OUTPUT``.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

DIST = "SafeAI-Static-Analyzer"
FAIL_ON_CHOICES = ("critical", "high", "medium")
# PEP 440 public-version shape; restrictive enough that a caller-supplied
# version cannot smuggle extra pip arguments or shell metacharacters.
_PEP440_SAFE_RE = re.compile(
    r"^[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc|\.dev|\.post)[0-9]+)?\Z"
)


def env_val(name, default=""):
    """Read an environment variable, stripping whitespace."""
    return os.environ.get(name, default).strip()


def action_input(name, default=""):
    """Read the ``INPUT_*`` env var GitHub sets for an action input."""
    return env_val(f"INPUT_{name.upper().replace('-', '_')}", default)


def as_bool(value):
    return str(value).strip().lower() in {"true", "1", "yes", "on"}


def build_install_command(version):
    """Return the argv that installs SafeAI at ``version`` (no shell)."""
    if version:
        spec = f"{DIST}=={version}"
    else:
        spec = DIST
    return [sys.executable, "-m", "pip", "install", "--quiet", spec]


def build_scan_argv(path, fail_on, sarif, rules="", baseline="", fail_on_new=False,
                    fail_on_escalation="", no_registry=True, extra_args=None):
    """Build the ``python -m safeai scan`` argv as a list (no shell)."""
    argv = [sys.executable, "-m", "safeai", "scan", path]
    if sarif:
        argv += ["--sarif", sarif]
    argv += ["--fail-on", fail_on]
    if rules:
        argv += ["--rules", rules]
    if baseline:
        argv += ["--baseline", baseline]
    if fail_on_new:
        argv += ["--fail-on-new"]
    if fail_on_escalation:
        argv += ["--fail-on-escalation", fail_on_escalation]
    if no_registry:
        argv += ["--no-registry"]
    if extra_args:
        argv += list(extra_args)
    return argv


def parse_extra_args(raw):
    """Parse ``extra-args`` input (JSON array of strings) without eval."""
    raw = (raw or "[]").strip()
    if not raw:
        return []
    parsed = json.loads(raw)
    if not isinstance(parsed, list):
        raise TypeError("extra-args must be a JSON array of strings")
    for item in parsed:
        if not isinstance(item, str):
            raise TypeError("extra-args elements must be strings")
    return parsed


def validate_version(version):
    """Return None if ``version`` is safe, else an error message."""
    if not version:
        return None
    if not _PEP440_SAFE_RE.match(version):
        return (
            f"version {version!r} is not a safe PyPI version; "
            "expected e.g. '1.5.0' or '1.5.0rc1'"
        )
    return None


def workspace_root():
    """Return the GitHub workspace (or the process cwd as a fallback)."""
    return os.environ.get("GITHUB_WORKSPACE") or os.getcwd()


def resolve_path(value):
    """Resolve an input path to absolute against the GitHub workspace."""
    if not value:
        return ""
    return os.path.abspath(os.path.join(workspace_root(), value))


def validate_no_control_chars(value, label):
    """Return an error message if ``value`` contains control characters.

    GitHub Actions parses ``$GITHUB_OUTPUT`` line-by-line; a newline smuggled
    through a path input would inject additional output keys. The same applies
    to ``::error::``/``::warning::`` messages, which are newline-delimited.
    """
    for char in value:
        if ord(char) < 0x20 or char == "\x7f":
            return (
                f"{label} contains a control character "
                f"(U+{ord(char):04X}), which is not allowed"
            )
    return None


def write_outputs(sarif_path):
    """Append action outputs to ``$GITHUB_OUTPUT`` when present."""
    out_file = os.environ.get("GITHUB_OUTPUT")
    if not out_file or not os.path.isabs(sarif_path):
        return
    with open(out_file, "a", encoding="utf-8") as fh:
        fh.write(f"sarif-path={sarif_path}\n")


def main(argv=None):
    scan_dir = action_input("path", ".") or "."
    version = action_input("version")
    fail_on = action_input("fail-on", "critical") or "critical"
    sarif = action_input("sarif", "safeai-results.sarif")
    rules = action_input("rules")
    baseline = action_input("baseline")
    fail_on_new = as_bool(action_input("fail-on-new", "false"))
    fail_on_escalation = action_input("fail-on-escalation")
    no_registry = as_bool(action_input("no-registry", "true"))
    skip_install = as_bool(env_val("SAFEAI_ACTION_SKIP_INSTALL"))

    scan_dir = resolve_path(scan_dir)
    sarif = resolve_path(sarif)
    rules = resolve_path(rules)
    baseline = resolve_path(baseline)

    for label, value in (
        ("path", scan_dir),
        ("sarif", sarif),
        ("rules", rules),
        ("baseline", baseline),
    ):
        if value:
            error = validate_no_control_chars(value, label)
            if error:
                print(f"::error::{error}", file=sys.stderr)
                return 2

    if fail_on not in FAIL_ON_CHOICES:
        print(
            f"::error::fail-on must be one of {', '.join(FAIL_ON_CHOICES)}; got {fail_on!r}",
            file=sys.stderr,
        )
        return 2
    if fail_on_escalation and fail_on_escalation not in FAIL_ON_CHOICES:
        print(
            f"::error::fail-on-escalation must be one of "
            f"{', '.join(FAIL_ON_CHOICES)}; got {fail_on_escalation!r}",
            file=sys.stderr,
        )
        return 2
    version_error = validate_version(version)
    if version_error:
        print(f"::error::{version_error}", file=sys.stderr)
        return 2

    try:
        extra_args = parse_extra_args(action_input("extra-args", "[]"))
    except (TypeError, json.JSONDecodeError) as exc:
        print(f"::error::extra-args: {exc}", file=sys.stderr)
        return 2

    if not os.path.exists(scan_dir):
        print(f"::error::scan path does not exist: {scan_dir}", file=sys.stderr)
        return 2

    if not skip_install:
        install_cmd = build_install_command(version)
        install_rc = subprocess.call(install_cmd)
        if install_rc != 0:
            print(
                f"::error::failed to install {DIST}"
                + (f"=={version}" if version else "")
                + f" (pip exit code {install_rc})",
                file=sys.stderr,
            )
            # Install failure is an operational error, not a scan/policy
            # outcome, so it must not be conflated with exit code 1.
            return 2

    if sarif:
        sarif_dir = os.path.dirname(os.path.abspath(sarif))
        if sarif_dir:
            try:
                os.makedirs(sarif_dir, exist_ok=True)
            except OSError as exc:
                print(
                    f"::error::could not create SARIF directory {sarif_dir!r}: {exc}",
                    file=sys.stderr,
                )
                return 2

    cmd = build_scan_argv(
        scan_dir,
        fail_on,
        sarif,
        rules=rules,
        baseline=baseline,
        fail_on_new=fail_on_new,
        fail_on_escalation=fail_on_escalation,
        no_registry=no_registry,
        extra_args=extra_args,
    )
    # Run from a neutral working directory so ``python -m safeai`` imports the
    # installed PyPI package, never a ``safeai/`` directory in the consumer's
    # checked-out tree. All report paths are already absolute.
    neutral_cwd = os.environ.get("RUNNER_TEMP") or tempfile.mkdtemp(prefix="safeai-action-")
    proc = subprocess.run(cmd, cwd=neutral_cwd, check=False)

    if sarif and not os.path.exists(sarif):
        print(
            f"::warning::no SARIF artifact was generated at {sarif}; "
            f"the scan failed before report output (exit code {proc.returncode})",
            file=sys.stderr,
        )

    if sarif and os.path.exists(sarif):
        try:
            write_outputs(os.path.abspath(sarif))
        except OSError as exc:
            print(
                f"::error::could not write action output to $GITHUB_OUTPUT: {exc}",
                file=sys.stderr,
            )
            return 2

    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())