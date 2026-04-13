#!/bin/bash
cd "$(dirname "$0")"
PYTHONPATH=logsec-toolkit/src python3 -m logsec "$@"
