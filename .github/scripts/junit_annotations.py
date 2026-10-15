"""Turn pytest JUnit failures into GitHub annotations.

Annotations are visible on the run page and through the public check-runs API,
so a red build can be diagnosed without downloading logs. Only test names and
the first lines of the failure message are emitted.
"""

from __future__ import annotations

import os
import sys
import xml.etree.ElementTree as ET  # trusted input: our own pytest output


def _escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    # Workflow-command properties are split on ':' and ','.
    return _escape(text).replace(":", "%3A").replace(",", "%2C")


def main(path: str) -> None:
    if not os.path.exists(path):  # pytest never ran (e.g. install failed)
        print(f"no {path}; nothing to annotate")
        return
    root = ET.parse(path).getroot()
    count = 0
    for case in root.iter("testcase"):
        for tag in ("failure", "error"):
            node = case.find(tag)
            if node is None:
                continue
            name = f"{case.get('classname')}::{case.get('name')}"
            detail = "\n".join((node.get("message") or node.text or "").splitlines()[:15])
            print(f"::error title={_escape_property(name)}::{_escape(detail[:1500])}")
            count += 1
            if count >= 40:
                return


if __name__ == "__main__":
    main(sys.argv[1])
