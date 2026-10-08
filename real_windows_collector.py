import subprocess
import os
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(BASE_DIR, "server_logs.txt")

print(f"[*] Live Polling Windows Events -> {OUTPUT_FILE}")

# Κρατάμε τα IDs που είδαμε για να μην γράφουμε διπλότυπα
seen_records = set()

LEVEL_MAP = {
    "1": ("CRITICAL", "401"),
    "2": ("ERROR", "401"),
    "3": ("WARNING", "403"),
    "4": ("INFO", "200"),
    "0": ("INFO", "200")
}

def fetch_latest_events():
    # Τραβάει τα τελευταία 5 events από System, Application και Security
    ps_cmd = (
        'Get-WinEvent -FilterHashtable @{LogName=@("System","Application"); Level=@(1,2,3,4)} -MaxEvents 8 | '
        'ForEach-Object { "$($_.RecordId)|$($_.TimeCreated.ToString(\'yyyy-MM-dd HH:mm:ss\'))|$($_.Id)|$($_.ProviderName.Replace(\'|\',\'/\'))|$($_.Level)" }'
    )
    
    res = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )
    
    if res.returncode != 0 or not res.stdout:
        return

    lines = res.stdout.strip().splitlines()
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        for line in reversed(lines):
            parts = line.strip().split("|")
            if len(parts) >= 5:
                rec_id = parts[0]
                if rec_id in seen_records:
                    continue
                seen_records.add(rec_id)

                timestamp = parts[1]
                event_id = parts[2]
                provider = parts[3][:25]
                level_num = parts[4]

                level_text, status = LEVEL_MAP.get(level_num, ("INFO", "200"))
                endpoint = f"/win-event/{event_id}"
                user_host = "127.0.0.1 (LocalHost)"

                log_entry = f"{timestamp} | {user_host} | {level_text} | {endpoint} | {status}\n"
                f.write(log_entry)
                f.flush()
                print(f"[LIVE NOW] {timestamp} | EventID: {event_id} | {level_text}")

print("[*] Έτοιμο. Παρακολούθηση σε πραγματικό χρόνο...")
while True:
    fetch_latest_events()
    time.sleep(2)