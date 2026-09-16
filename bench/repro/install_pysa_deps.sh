#!/usr/bin/env bash
# install_pysa_deps.sh <target> <requirements.txt>
# Builds /opt/pysa-venv/<target> from an app's requirements and links its
# site-packages to /opt/pysa-deps/<target> (Pysa's search_path for that app).
# Requirements that cannot be installed in the slim image (C builds such as
# psycopg2) are skipped one by one and listed in /opt/pysa-deps/<target>.skipped.
set -uo pipefail
target=$1
req=$2
venv=/opt/pysa-venv/$target
python -m venv "$venv"
mkdir -p /opt/pysa-deps
: > "/opt/pysa-deps/$target.skipped"
if ! "$venv/bin/pip" install --no-cache-dir -q -r "$req"; then
    while IFS= read -r line; do
        spec=${line%%#*}
        spec=$(echo "$spec" | xargs)
        [ -z "$spec" ] && continue
        "$venv/bin/pip" install --no-cache-dir -q "$spec" || echo "$spec" >> "/opt/pysa-deps/$target.skipped"
    done < "$req"
fi
site=$("$venv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
ln -s "$site" "/opt/pysa-deps/$target"
echo "pysa deps for $target: $(ls "$site" | wc -l) entries; skipped: $(tr '\n' ' ' < "/opt/pysa-deps/$target.skipped")"
