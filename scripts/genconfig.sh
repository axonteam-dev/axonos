#!/usr/bin/env bash
# Generate auto.conf + autoconf.h from config.cfg.
#
#   FOO=y                 built-in  → #define FOO 1
#   FOO=m                 module    → built-in for now (modules later)
#   FOO=n                 disabled  → omitted
#   # FOO is not set      disabled
#
# No CONFIG_ prefix — keys are used as written.
set -euo pipefail

CFG="${1:-config.cfg}"
OUTDIR="${2:-build/include}"
AUTO_CONF="${OUTDIR}/config/auto.conf"
AUTOCONF_H="${OUTDIR}/generated/autoconf.h"

if [[ ! -f "$CFG" ]]; then
	echo "genconfig: config file not found: $CFG" >&2
	exit 1
fi

mkdir -p "$(dirname "$AUTO_CONF")" "$(dirname "$AUTOCONF_H")"

tmp_conf="$(mktemp)"
tmp_hdr="$(mktemp)"
trap 'rm -f "$tmp_conf" "$tmp_hdr"' EXIT

{
	echo "# Generated from ${CFG} — do not edit"
	echo "# m is treated as built-in until loadable modules exist"
	echo
} >"$tmp_conf"

{
	echo "/* Generated from ${CFG} — do not edit */"
	echo "#pragma once"
	echo
	echo "/*"
	echo " * Tristate: y and m both define FOO=1 for now."
	echo " * When modules land, m will emit FOO_MODULE instead."
	echo " */"
	echo
} >"$tmp_hdr"

declare -A SEEN=()
declare -a ORDER=()

record() {
	local key="$1" val="$2"
	if [[ -z "${SEEN[$key]+x}" ]]; then
		ORDER+=("$key")
	fi
	SEEN[$key]="$val"
}

while IFS= read -r line || [[ -n "$line" ]]; do
	line="${line%$'\r'}"
	line="${line#"${line%%[![:space:]]*}"}"
	line="${line%"${line##*[![:space:]]}"}"
	[[ -z "$line" ]] && continue

	if [[ "$line" =~ ^#[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]+is[[:space:]]+not[[:space:]]+set$ ]]; then
		record "${BASH_REMATCH[1]}" "n"
		continue
	fi

	[[ "$line" == \#* ]] && continue

	if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
		key="${BASH_REMATCH[1]}"
		val="${BASH_REMATCH[2]}"
		val="${val#"${val%%[![:space:]]*}"}"
		val="${val%"${val##*[![:space:]]}"}"
		if [[ "$val" =~ ^\".*\"$ ]] || [[ "$val" =~ ^\'.*\'$ ]]; then
			val="${val:1:-1}"
		fi
		record "$key" "$val"
		continue
	fi

	echo "genconfig: ignoring unrecognized line: $line" >&2
done <"$CFG"

for key in "${ORDER[@]}"; do
	val="${SEEN[$key]}"
	case "$val" in
	n)
		echo "# ${key} is not set" >>"$tmp_conf"
		;;
	y|m)
		echo "${key}=${val}" >>"$tmp_conf"
		echo "#define ${key} 1" >>"$tmp_hdr"
		if [[ "$val" == m ]]; then
			echo "/* ${key}=m: built-in until modules exist */" >>"$tmp_hdr"
		fi
		;;
	*)
		echo "${key}=${val}" >>"$tmp_conf"
		if [[ "$val" =~ ^[0-9]+$ ]]; then
			echo "#define ${key} ${val}" >>"$tmp_hdr"
		else
			echo "#define ${key} \"${val}\"" >>"$tmp_hdr"
		fi
		;;
	esac
done

replace_if_changed() {
	local src="$1" dst="$2"
	if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then
		return 0
	fi
	mv -f "$src" "$dst"
	: >"$src"
}

replace_if_changed "$tmp_conf" "$AUTO_CONF"
replace_if_changed "$tmp_hdr" "$AUTOCONF_H"

echo "GEN		${AUTO_CONF}"
echo "GEN		${AUTOCONF_H}"
