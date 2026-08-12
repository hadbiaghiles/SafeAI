#!/usr/bin/env python3
"""Render the Reddit draft and maintainer notification from a sanitised summary.

Both outputs are generated as Markdown. The Reddit draft is safe for public
review; the maintainer notification is intended to remain private.
"""
from __future__ import annotations

import argparse
import json
import os
from typing import Any

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except ImportError:  # pragma: no cover
    Environment = None  # type: ignore


def _load_templates(template_dir: str) -> Any:
    if Environment is None:
        raise SystemExit("::error::jinja2 is required to render templates")
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env


def render(summary: dict[str, Any], template_dir: str, target_public: bool) -> dict[str, str]:
    env = _load_templates(template_dir)
    reddit_tpl = env.get_template("reddit-post.md.j2")
    public_tpl = env.get_template("public-summary.md.j2")
    maintainer_tpl = env.get_template("maintainer-notification.md.j2")

    reddit_text = reddit_tpl.render(**summary)
    public_text = public_tpl.render(**summary)
    maintainer_text = maintainer_tpl.render(**summary)
    return {
        "reddit": reddit_text,
        "public": public_text,
        "maintainer": maintainer_text,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render Reddit and maintainer drafts.")
    parser.add_argument("--summary", required=True, help="Sanitised summary JSON")
    parser.add_argument("--template-dir", default="community-scans/templates")
    parser.add_argument("--reddit-out", required=True)
    parser.add_argument("--public-out", required=True)
    parser.add_argument("--maintainer-out", required=True)
    args = parser.parse_args(argv)

    with open(args.summary, "r", encoding="utf-8") as fh:
        summary = json.load(fh)

    rendered = render(summary, args.template_dir, True)

    os.makedirs(os.path.dirname(args.reddit_out), exist_ok=True)
    os.makedirs(os.path.dirname(args.public_out), exist_ok=True)
    os.makedirs(os.path.dirname(args.maintainer_out), exist_ok=True)

    with open(args.reddit_out, "w", encoding="utf-8") as fh:
        fh.write(rendered["reddit"])
    with open(args.public_out, "w", encoding="utf-8") as fh:
        fh.write(rendered["public"])
    with open(args.maintainer_out, "w", encoding="utf-8") as fh:
        fh.write(rendered["maintainer"])

    print(f"Wrote Reddit draft: {args.reddit_out}")
    print(f"Wrote public summary: {args.public_out}")
    print(f"Wrote maintainer notification: {args.maintainer_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
