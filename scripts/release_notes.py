#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Print the CHANGELOG.md section for a version:  python scripts/release_notes.py v0.1.0"""
import re
import sys

version = (sys.argv[1] if len(sys.argv) > 1 else "").lstrip("v")
with open("CHANGELOG.md", encoding="utf-8") as f:
    text = f.read()
m = re.search(rf"^## \[?{re.escape(version)}\]?[^\n]*\n(.*?)(?=^## |\Z)", text, re.S | re.M)
if not version or not m:
    sys.exit(f"No CHANGELOG entry for '{version}'")
print(m.group(1).strip())
