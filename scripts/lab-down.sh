#!/usr/bin/env bash
# Delete the KubeShield laboratory cluster (all lab data is removed).
set -euo pipefail
kind delete cluster --name kubeshield-lab
