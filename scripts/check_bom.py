"""Dependency intake check for the model weights (proposal section 3). Run before the model server starts.

    python scripts/check_bom.py                       # verify models/ against bom.yaml, exit 1 on any problem
    python scripts/check_bom.py --models-dir /srv/models
    python scripts/check_bom.py --record Qwen2.5-14B-Instruct-AWQ   # print the `files:` block to paste into bom.yaml

What is checked for every model in bom.yaml:
  * `revision` is a real commit hash, not a placeholder
  * `files` is not empty, and every listed file exists with the recorded SHA-256
  * no file in the model folder is missing from the list (nothing unrecorded gets loaded)
  * no pickle-format file is present (.bin .pt .pth .pkl .ckpt): safetensors only
  * config.json does not ask for remote code (`auto_map`), so trust_remote_code can stay False

It fails closed: an unfilled BOM is an error, not a warning.
Each model lives in <models-dir>/<name>/ . Model weights never go in the repository.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PICKLE_SUFFIXES = {".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt"}
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _files_in(folder: Path) -> list[Path]:
    return sorted(p for p in folder.rglob("*") if p.is_file() and ".git" not in p.parts and ".cache" not in p.parts)


def check_model(model: dict, models_dir: Path) -> list[str]:
    """Return the list of problems for one bom.yaml model entry (empty = clean)."""
    name = str(model.get("name", "?"))
    problems: list[str] = []
    if not _REVISION_RE.match(str(model.get("revision", ""))):
        problems.append(f"{name}: revision is not a 40-character commit hash")
    recorded = {str(f["path"]): str(f["sha256"]).lower() for f in (model.get("files") or [])}
    if not recorded:
        problems.append(f"{name}: no files recorded")
    folder = models_dir / name
    if not folder.is_dir():
        return problems + [f"{name}: folder {folder} does not exist"]
    present = {p.relative_to(folder).as_posix(): p for p in _files_in(folder)}
    for rel, digest in recorded.items():
        if rel not in present:
            problems.append(f"{name}: {rel} is recorded but missing")
        elif sha256_file(present[rel]) != digest:
            problems.append(f"{name}: {rel} does not match its recorded SHA-256")
    for rel, path in present.items():
        if rel not in recorded:
            problems.append(f"{name}: {rel} is present but not recorded")
        if path.suffix.lower() in PICKLE_SUFFIXES:
            problems.append(f"{name}: {rel} is a pickle-format file (safetensors only)")
    config = folder / "config.json"
    if config.exists():
        try:
            if "auto_map" in json.loads(config.read_text(encoding="utf-8")):
                problems.append(f"{name}: config.json has auto_map (would need trust_remote_code)")
        except (ValueError, UnicodeDecodeError):
            problems.append(f"{name}: config.json is not valid JSON")
    return problems


def check_bom(bom_path: Path, models_dir: Path) -> list[str]:
    bom = yaml.safe_load(bom_path.read_text(encoding="utf-8")) or {}
    models = bom.get("models") or []
    if not models:
        return ["bom.yaml lists no model"]
    return [p for m in models for p in check_model(m, models_dir)]


def record(name: str, models_dir: Path) -> str:
    folder = models_dir / name
    lines = ["    files:"]
    for p in _files_in(folder):
        lines.append(f"      - {{path: {p.relative_to(folder).as_posix()}, sha256: {sha256_file(p)}}}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bom", default=str(ROOT / "bom.yaml"))
    ap.add_argument("--models-dir", default=str(ROOT / "models"))
    ap.add_argument("--record", metavar="NAME", help="print the files block for <models-dir>/NAME and exit")
    args = ap.parse_args()
    if args.record:
        print(record(args.record, Path(args.models_dir)))
        return 0
    problems = check_bom(Path(args.bom), Path(args.models_dir))
    for p in problems:
        print("BOM CHECK FAILED:", p, file=sys.stderr)
    if not problems:
        print("BOM check passed")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
