#!/usr/bin/env python3
"""Keep service configuration and website content out of kernel boot setup."""
from pathlib import Path

source = (Path(__file__).resolve().parents[1] / "core/entry/init.c").read_text()
start = source.index("void start_kernel(")
boot = source[start:]
for path in ("/etc/nginx/nginx.conf", "/srv/www/index.html"):
    assert path not in boot, f"kernel boot must not modify {path}"
print("PASS: kernel boot does not seed or overwrite nginx configuration or site content")
