import csv, re, urllib.request, os

os.makedirs("data", exist_ok=True)
print("Downloading IEEE OUI database...")
urllib.request.urlretrieve("https://standards-oui.ieee.org/oui/oui.csv", "data/oui_raw.csv")

with open("data/oui_raw.csv", encoding="utf-8", errors="replace") as fin, \
     open("data/oui.csv", "w", encoding="utf-8", newline='') as fout:
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

print("OUI database saved to data/oui.csv")
with open("data/oui.csv", "r", encoding="utf-8") as f:
    print(f"{sum(1 for _ in f)} lines written to data/oui.csv")
