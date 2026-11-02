"""Regenerate the AppSec vocabulary enums in the WAF rule schema from CrowdSec's Go source.

Zones, transforms, match types and body types are four maps in the engine's
`pkg/appsec/appsec_rule/modsecurity.go`. Hand-copying them into the schema is
what let it drift: it ended up rejecting 19 transforms the engine accepts and
accepting two zone names that do not exist. This script re-reads the maps and
rewrites the blocks marked BEGIN/END GENERATED in the schema.

    python tools/sync_appsec_vocabulary.py --crowdsec ../crowdsec
    python tools/sync_appsec_vocabulary.py --check

The crowdsec checkout defaults to $CROWDSEC_REPO, then to a sibling directory.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_FILE = PROJECT_ROOT / "src" / "crowdsec_local_mcp" / "yaml-schemas" / "appsec_rules_schema.yaml"
MODSECURITY_GO = Path("pkg") / "appsec" / "appsec_rule" / "modsecurity.go"

# Coraza operators by the shape of their argument. The Go map only tells us
# key -> operator; whether that operator takes a number, a string or nothing is
# a property of coraza, so it has to live here. Anything unlisted is treated as
# string-valued and reported, so a newly added match type gets a human look.
VALUELESS_OPERATORS = frozenset({"@detectSQLi", "@detectXSS"})
NUMERIC_OPERATORS = frozenset({"@gt", "@lt", "@ge", "@le", "@eq"})
STRING_OPERATORS = frozenset({"@rx", "@streq", "@beginsWith", "@endsWith", "@contains", "@pmFromFile"})

GO_MAP_RE = r"var\s+{name}\s*=\s*map\[string\]string\{{(.*?)\n\}}"
GO_ENTRY_RE = re.compile(r'^\s*"([^"]+)"\s*:\s*"([^"]+)"', re.MULTILINE)
# Transforms the builder handles itself instead of looking them up in the map.
GO_SPECIAL_TRANSFORM_RE = re.compile(r'slices\.Contains\(rule\.Transform,\s*"([^"]+)"\)')


def parse_go_map(source: str, name: str) -> list[tuple[str, str]]:
    """Return the (key, value) pairs of a Go string map, in source order."""
    match = re.search(GO_MAP_RE.format(name=re.escape(name)), source, re.DOTALL)
    if match is None:
        raise SystemExit(f"could not find `var {name} = map[string]string{{...}}` in {MODSECURITY_GO}")

    entries = GO_ENTRY_RE.findall(match.group(1))
    if not entries:
        raise SystemExit(f"`{name}` parsed as empty; the map syntax probably changed")

    return entries


def classify_match_types(entries: list[tuple[str, str]]) -> dict[str, list[str]]:
    """Split match types by the argument shape of the coraza operator they map to."""
    groups: dict[str, list[str]] = {"valueless": [], "string": [], "numeric": []}
    unknown: list[str] = []

    for key, operator in entries:
        if operator in VALUELESS_OPERATORS:
            groups["valueless"].append(key)
        elif operator in NUMERIC_OPERATORS:
            groups["numeric"].append(key)
        else:
            groups["string"].append(key)
            if operator not in STRING_OPERATORS:
                unknown.append(f"{key} -> {operator}")

    if unknown:
        print(
            "note: unrecognised coraza operator(s), assumed to take a string argument:\n  "
            + "\n  ".join(unknown)
            + f"\nAdd them to one of the *_OPERATORS sets in {Path(__file__).name} if that is wrong.",
            file=sys.stderr,
        )

    return groups


def read_vocabulary(crowdsec_repo: Path) -> dict[str, list[str]]:
    go_file = crowdsec_repo / MODSECURITY_GO
    if not go_file.is_file():
        raise SystemExit(f"{go_file} not found; pass --crowdsec <path to a crowdsec checkout>")

    source = go_file.read_text(encoding="utf-8")

    transforms = [key for key, _ in parse_go_map(source, "transformMap")]
    # `count` never reaches transformMap: the builder turns it into the `&`
    # collection-count prefix before the lookup.
    transforms += [name for name in GO_SPECIAL_TRANSFORM_RE.findall(source) if name not in transforms]

    match_types = classify_match_types(parse_go_map(source, "matchMap"))

    return {
        "zones": [key for key, _ in parse_go_map(source, "zonesMap")],
        "transforms": transforms,
        "match-types-valueless": match_types["valueless"],
        "match-types-string": match_types["string"],
        "match-types-numeric": match_types["numeric"],
        "body-types": [key for key, _ in parse_go_map(source, "bodyTypeMatch")],
    }


def splice(schema_text: str, block: str, values: list[str]) -> str:
    """Replace the body of one BEGIN/END GENERATED block, keeping its indentation."""
    pattern = re.compile(
        rf"^(?P<indent>[ ]*)# BEGIN GENERATED {re.escape(block)}\b.*?\n"
        rf".*?"
        rf"^[ ]*# END GENERATED {re.escape(block)}\b.*?\n",
        re.DOTALL | re.MULTILINE,
    )

    match = pattern.search(schema_text)
    if match is None:
        raise SystemExit(f"no `# BEGIN GENERATED {block}` marker in {SCHEMA_FILE.name}")

    indent = match.group("indent")
    lines = [f"{indent}# BEGIN GENERATED {block} (tools/sync_appsec_vocabulary.py)", f"{indent}enum:"]
    lines += [f"{indent}  - {value}" for value in values]
    lines.append(f"{indent}# END GENERATED {block}")

    return schema_text[: match.start()] + "\n".join(lines) + "\n" + schema_text[match.end() :]


def default_crowdsec_repo() -> Path:
    from_env = os.environ.get("CROWDSEC_REPO")
    if from_env:
        return Path(from_env).expanduser()

    return PROJECT_ROOT.parent / "crowdsec"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--crowdsec",
        type=Path,
        default=default_crowdsec_repo(),
        help="path to a crowdsec checkout (default: $CROWDSEC_REPO, else ../crowdsec)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="report whether the schema is stale instead of rewriting it",
    )
    args = parser.parse_args()

    vocabulary = read_vocabulary(args.crowdsec.resolve())

    original = SCHEMA_FILE.read_text(encoding="utf-8")
    updated = original
    for block, values in vocabulary.items():
        updated = splice(updated, block, values)

    if updated == original:
        print(f"{SCHEMA_FILE.name} is up to date with {args.crowdsec}")
        return 0

    if args.check:
        print(f"{SCHEMA_FILE.name} is stale; run tools/sync_appsec_vocabulary.py to update it")
        return 1

    SCHEMA_FILE.write_text(updated, encoding="utf-8")
    for block, values in vocabulary.items():
        print(f"  {block}: {len(values)} value(s)")
    print(f"updated {SCHEMA_FILE.relative_to(PROJECT_ROOT)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
