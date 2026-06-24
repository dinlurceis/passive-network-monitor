#!/bin/bash
# Download IEEE OUI database và convert sang CSV
# Usage: ./scripts/download_oui.sh

set -e
mkdir -p data

echo "Downloading IEEE OUI database..."
curl -s "https://standards-oui.ieee.org/oui/oui.csv" -o data/oui_raw.csv

# Convert: giữ cột Registry (hex OUI) và Organization Name
# Format đầu ra: "AA:BB:CC","Vendor Name"
python3 - <<'EOF'
import csv, re

with open("data/oui_raw.csv", encoding="utf-8", errors="replace") as fin, \
     open("data/oui.csv", "w", encoding="utf-8") as fout:
    reader = csv.reader(fin)
    next(reader)  # skip header
    for row in reader:
        if len(row) < 3:
            continue
        oui_hex = row[1].strip().upper()  # "AABBCC"
        vendor  = row[2].strip()
        if len(oui_hex) == 6:
            formatted = f"{oui_hex[0:2]}:{oui_hex[2:4]}:{oui_hex[4:6]}"
            fout.write(f'"{formatted}","{vendor}"\n')

EOF

echo "OUI database saved to data/oui.csv"
wc -l data/oui.csv
