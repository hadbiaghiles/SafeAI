"""Stable project and agent identity derivation.

Identities are deterministic: the same project, agent, and source layout
always produce the same IDs. No timestamps, no random values.

Project ID priority:
  1. Explicit configured project ID (``.safeai/config.yml`` ``project_id``)
  2. Fingerprint of normalized Git remote + repository root directory name
  3. Persisted local UUID in ``.safeai/config.yml`` (created once)

Agent ID derivation:
  ``sha256(project_id | framework | semantic name | primary path | type)``
  truncated to a stable, readable prefix. Renaming or moving the primary
  source file creates a new identity; aliasing/migration is future work.
"""

import os
import re
import subprocess
import uuid

import yaml

from safeai.kya.util import sha256_text

_SAFEAI_DIR = ".safeai"
_CONFIG_FILE = "config.yml"


def _config_path(root):
    return os.path.join(root, _SAFEAI_DIR, _CONFIG_FILE)


def load_local_config(root):
    """Load ``.safeai/config.yml`` if present; return ``{}`` otherwise."""
    path = _config_path(root)
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return data if isinstance(data, dict) else {}
    except OSError:
        return {}
    except yaml.YAMLError:
        return {}


def save_local_config(root, config):
    """Persist ``.safeai/config.yml``, creating ``.safeai/`` if needed."""
    directory = os.path.join(root, _SAFEAI_DIR)
    os.makedirs(directory, exist_ok=True)
    with open(_config_path(root), "w", encoding="utf-8") as fh:
        yaml.safe_dump(config, fh, sort_keys=True)


def _git_remote_fingerprint(root):
    """Return a one-way fingerprint of the primary Git remote, or ``None``.

    The raw remote URL (which may embed credentials or private hostnames)
    is never returned or persisted; only a normalized SHA-256 fingerprint.
    """
    try:
        result = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    url = (result.stdout or "").strip()
    if result.returncode != 0 or not url:
        return None
    # Normalize: lowercase, strip credentials, strip trailing .git and slashes.
    normalized = re.sub(r"^[^@/]+@", "", url.strip().lower())
    normalized = re.sub(r"\.git$", "", normalized).rstrip("/")
    return sha256_text(normalized)


def git_metadata(root):
    """Best-effort Git metadata (commit SHA, branch, tag). All optional."""
    meta = {"commit_sha": None, "branch": None, "tag": None}

    def _git(*args):
        try:
            result = subprocess.run(
                ["git", *args], cwd=root, capture_output=True, text=True, timeout=5, check=False
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        return (result.stdout or "").strip() or None

    meta["commit_sha"] = _git("rev-parse", "HEAD")
    meta["branch"] = _git("rev-parse", "--abbrev-ref", "HEAD")
    meta["tag"] = _git("describe", "--tags", "--exact-match", "HEAD")
    return meta


def resolve_project_id(root, config=None, persist=True):
    """Resolve the stable project ID for a scan root.

    Returns ``(project_id, remote_fingerprint)``. When no configured or
    derivable identity exists, a local UUID is generated once and
    persisted to ``.safeai/config.yml`` (unless ``persist=False``).
    """
    config = config if config is not None else load_local_config(root)

    configured = config.get("project_id")
    if configured:
        return str(configured), _git_remote_fingerprint(root)

    remote_fp = _git_remote_fingerprint(root)
    if remote_fp:
        root_name = os.path.basename(os.path.abspath(root)) or "root"
        return f"git-{remote_fp[:16]}-{sha256_text(root_name)[:8]}", remote_fp

    persisted = config.get("local_project_uuid")
    if not persisted:
        persisted = str(uuid.uuid4())
        if persist:
            config["local_project_uuid"] = persisted
            save_local_config(root, config)
    return f"local-{persisted}", None


def derive_agent_id(project_id, framework, name, primary_path, agent_type):
    """Derive a deterministic, stable agent identifier.

    Uses project ID, framework, semantic name (if discovered), the
    normalized primary source path, and agent type. Deterministic: the
    same inputs always produce the same ID. Contains no timestamps.
    """
    material = "\n".join([
        str(project_id or "project"),
        str(framework or "unknown").lower(),
        str(name or "unnamed").strip().lower(),
        str(primary_path or "").replace("\\", "/"),
        str(agent_type or "unknown").lower(),
    ])
    digest = sha256_text(material)
    slug = re.sub(r"[^a-z0-9]+", "-", str(name or "agent").lower()).strip("-") or "agent"
    return f"{slug[:24]}-{digest[:12]}"
