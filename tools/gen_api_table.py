"""Renders the bridge's live /_tools index as a markdown table.

Kept as a script (rather than inlined in a shell command) because the markdown it
emits contains backticks and quotes that shells mangle.

    python tools/gen_api_table.py <tools.json> <out.md>
"""
import json
import sys

ORDER = ["meta", "program", "memory", "function", "variable", "symbol",
         "data", "type", "comment", "analysis", "script", "legacy"]


def main() -> int:
    source, destination = sys.argv[1], sys.argv[2]
    with open(source, encoding="utf-8") as handle:
        index = json.load(handle)

    # Paths registered for both verbs (router.any/lookup) collapse into one row.
    merged: dict[tuple[str, str], dict] = {}
    for category, items in index["categories"].items():
        for item in items:
            key = (category, item["path"])
            entry = merged.setdefault(key, {"methods": set(), "summary": item["summary"]})
            entry["methods"].add(item["method"])

    lines: list[str] = []
    for category in ORDER:
        rows = sorted((k[1], v) for k, v in merged.items() if k[0] == category)
        if not rows:
            continue
        lines.append(f"### {category} ({len(rows)})")
        lines.append("")
        lines.append("| Method | Path | Purpose |")
        lines.append("|---|---|---|")
        for path, entry in rows:
            methods = "/".join(sorted(entry["methods"]))
            lines.append(f"| `{methods}` | `{path}` | {entry['summary']} |")
        lines.append("")

    with open(destination, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))

    print(f"{len(merged)} distinct paths written to {destination}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
