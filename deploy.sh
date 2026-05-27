#!/bin/bash
# SPECTR deploy — sync ~/spectr/ to /opt/spectr/
CYAN='\033[96m'
GREEN='\033[92m'
RESET='\033[0m'

echo -e "${CYAN}[SPECTR]${RESET} Syncing to /opt/spectr/..."

sudo find ~/spectr -name "*.py" ! -path "*/venv/*" ! -path "*/__pycache__/*" | while read f; do
    dest="/opt/spectr/${f#$HOME/spectr/}"
    sudo mkdir -p "$(dirname $dest)"
    sudo cp "$f" "$dest"
done

echo -e "${GREEN}[✓] Deploy completo${RESET}"
