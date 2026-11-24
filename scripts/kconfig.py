#!/usr/bin/env python3
"""Run Linux Kconfig frontends without clobbering legacy AxonOS settings."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def frontend_env(conf):
    env = os.environ.copy()
    generated = Path(conf).resolve().parent / "frontend"
    env["KCONFIG_AUTOCONFIG"] = str(generated / "config" / "auto.conf")
    env["KCONFIG_AUTOHEADER"] = str(generated / "generated" / "autoconf.h")
    env["KCONFIG_RUSTCCFG"] = str(generated / "generated" / "rustc_cfg")
    return env


def entries(path, legacy):
    result = {}
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        prefix = "" if legacy else "CONFIG_"
        disabled = re.fullmatch(r"#\s+" + prefix + r"([A-Za-z_]\w*)\s+is\s+not\s+set", line)
        enabled = re.fullmatch(prefix + r"([A-Za-z_]\w*)=(.*)", line)
        if disabled:
            key, value = disabled[1], "n"
        elif enabled:
            key, value = enabled[1], enabled[2].strip()
        elif not line or line.startswith("#") or (legacy and re.fullmatch(r"\[.*\]", line)):
            continue
        else:
            raise ValueError(f"{path}:{number}: invalid configuration entry")
        if value not in ("y", "n"):
            raise ValueError(f"{path}:{number}: unsupported {key}={value}; modules are not implemented")
        result[key] = value
    return result


def normalize(conf, config):
    env = frontend_env(conf)
    env.update(KCONFIG_CONFIG=str(config), KCONFIG_WARN_UNKNOWN_SYMBOLS="1", KCONFIG_WERROR="1")
    result = subprocess.run([conf, "--olddefconfig", "Kconfig"], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        raise ValueError(result.stderr.strip() or "Kconfig validation failed")


def prepare(conf, target, legacy):
    source = target if target.exists() else legacy
    requested = entries(source, legacy=source != target)
    with tempfile.TemporaryDirectory(prefix="axon-kconfig-") as tmp:
        normalized = Path(tmp) / ".config"
        normalized.write_text("\n".join(
            f"CONFIG_{k}=y" if v == "y" else f"# CONFIG_{k} is not set"
            for k, v in requested.items()) + "\n")
        normalize(conf, normalized)
        resolved = entries(normalized, legacy=False)
        if source != target:
            for key, value in requested.items():
                if resolved.get(key, "n") != value:
                    raise ValueError(f"{key}={value} violates Kconfig dependencies; import stopped")
            target.parent.mkdir(parents=True, exist_ok=True)
            # Exclusive creation prevents overwriting a configuration created
            # concurrently after the existence check above.
            with target.open("x") as out:
                out.write(normalized.read_text())
            print(f"KCONFIG: imported {legacy} into {target}", flush=True)


def main():
    if len(sys.argv) != 6 or sys.argv[1] not in ("menuconfig", "olddefconfig"):
        sys.exit("usage: kconfig.py {menuconfig|olddefconfig} OUTPUT LEGACY CONF MCONF")
    command, target, legacy = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    conf, mconf = os.path.abspath(sys.argv[4]), os.path.abspath(sys.argv[5])
    prepare(conf, target, legacy)
    env = frontend_env(conf)
    env["KCONFIG_CONFIG"] = str(target)
    if command == "menuconfig":
        # Linux mconf's default lxdialog theme matches the familiar blue menu.
        os.execve(mconf, [mconf, "Kconfig"], env)
    os.execve(conf, [conf, "--olddefconfig", "Kconfig"], env)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        sys.exit(f"Kconfig: {error}")
