"""Update manifest.json version from setuptools_scm."""

from __future__ import annotations

import json
from pathlib import Path

from setuptools_scm import get_version


def main() -> None:
    manifest_path = Path("manifest.json")
    manifest_data = json.loads(manifest_path.read_text())

    manifest_data["version"] = get_version()
    manifest_path.write_text(json.dumps(manifest_data, indent=2) + "\n")


if __name__ == "__main__":
    main()
