#!/usr/bin/env python3
"""Validate a built SafeAI wheel/sdist before release.

Checks that the wheel carries the console entry point, the rule data files,
and the expected top-level modules, so the published package is not missing
package data that the scanner relies on.
"""

import argparse
import os
import sys
import zipfile


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", help="path to the built .whl file")
    args = parser.parse_args(argv)

    if not args.wheel.endswith(".whl"):
        raise SystemExit(f"not a wheel: {args.wheel}")
    if not os.path.exists(args.wheel):
        raise SystemExit(f"wheel does not exist: {args.wheel}")

    with zipfile.ZipFile(args.wheel) as zf:
        names = set(zf.namelist())

    required_file = {
        "safeai/rules/base_rules.yaml",
        "safeai/cmd/cli.py",
        "safeai/cmd/postprocess.py",
        "safeai/engine/scan.py",
        "safeai/report/sarif.py",
        "safeai/report/html.py",
    }
    entry_points = [n for n in names if n.endswith("entry_points.txt")]
    missing = sorted(required_file - names)
    if missing:
        raise SystemExit(f"wheel missing required files: {missing}")

    if not entry_points:
        raise SystemExit("wheel has no entry_points.txt (console script missing)")

    with zipfile.ZipFile(args.wheel) as zf:
        ep_text = ""
        for ep in entry_points:
            member = zf.read(ep).decode("utf-8")
            ep_text += member
        if "safeai = safeai.cmd.cli:main" not in ep_text:
            raise SystemExit("entry points do not define safeai console script")

        dist_infos = []
        for n in names:
            if ".dist-info/" in n and n.endswith("METADATA"):
                dist_infos.append(n[: n.index(".dist-info/") + len(".dist-info/")])
        if not dist_infos:
            raise SystemExit("no dist-info metadata in wheel")
        for di in dict.fromkeys(dist_infos):
            meta = zf.read(di + "METADATA").decode("utf-8")
            if "Name: SafeAI-Static-Analyzer" not in meta:
                raise SystemExit(f"METADATA missing distribution name: {di}")

    print(f"wheel OK: {os.path.basename(args.wheel)} ({len(names)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())