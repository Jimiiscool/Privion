#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
if [ ! -d .venv ]; then python3 -m venv .venv; fi
.venv/bin/python -m pip install -q -r requirements.txt
.venv/bin/python -m backend.manage init
exec .venv/bin/python -m backend.run
