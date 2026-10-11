#!/usr/bin/env python3
"""Translate AxonOS INI/tristate configuration into Make and C headers."""
import json
import os
from pathlib import Path
import re
import sys
import tempfile


def generate(config, output):
    values = {}
    for number, raw in enumerate(config.read_text().splitlines(), 1):
        line = raw.strip()
        disabled = re.fullmatch(r"#\s*([A-Za-z_]\w*)\s+is\s+not\s+set", line)
        if disabled:
            values[disabled[1]] = "n"
        elif not line or line.startswith("#") or re.fullmatch(r"\[.*\]", line):
            continue
        else:
            entry = re.fullmatch(r"([A-Za-z_]\w*)\s*=\s*(.*)", line)
            if not entry:
                raise ValueError(f"{config}:{number}: invalid configuration")
            values[entry[1]] = entry[2].strip()
    conf = ["# Generated; do not edit", "# m is linked in until modules exist"]
    header = ["/* Generated; do not edit */", "#pragma once"]
    for key, value in values.items():
        conf.append(f"# {key} is not set" if value == "n" else f"{key}={value}")
        if value == "n":
            continue
        if value in ("y", "m"):
            literal = "1"
        elif re.fullmatch(r"[0-9]+|0[xX][0-9a-fA-F]+", value):
            literal = value
        else:
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            literal = json.dumps(value)
        header.append(f"#define {key} {literal}")
    for relative, lines in (("config/auto.conf", conf), ("generated/autoconf.h", header)):
        target = output / relative
        content = "\n".join(lines) + "\n"
        if target.exists() and target.read_text() == content:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=target.parent)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(content)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        print(f"GEN\t\t{target}")


if __name__ == "__main__":
    try:
        generate(Path(sys.argv[1] if len(sys.argv) > 1 else "config.cfg"),
                 Path(sys.argv[2] if len(sys.argv) > 2 else "build/include"))
    except (OSError, ValueError) as error:
        sys.exit(f"genconfig: {error}")
