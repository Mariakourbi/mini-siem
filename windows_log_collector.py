import win32evtlog
import time
from datetime import datetime

OUTPUT_FILE = "server_logs.txt"
SERVER = "localhost"

# Παρακολουθούμε και το Security και το System
CHANNELS = ["Security", "System"]

EVENT_MAP = {
    # Security Events
    4625: {"type": "FAILED_LOGON", "status": "401", "endpoint": "/auth/windows-logon"},
    4624: {"type": "SUCCESS_LOGON", "status": "200", "endpoint": "/auth/windows-logon"},
    4672: {"type": "ADMIN_PRIVILEGES", "status": "200", "endpoint": "/system/admin-elevation"},
    # System Events (για να βλέπεις άμεση κίνηση)
    7036: {"type": "SERVICE_STATE", "status": "200", "endpoint": "/system/service-change"},
    10000: {"type": "DEVICE_CONNECT", "status": "200", "endpoint": "/hardware/device-event"}
}

print("[*] Windows Live Event Collector ξεκίνησε!")
print("[*] Παρακολούθηση καναλιών: Security & System...")

def process_channel(log_type, last_record):
    try:
        hand = win32evtlog.OpenEventLog(SERVER, log_type)
        total = win32evtlog.GetNumberOfEventLogRecords(hand)
        
        if last_record == 0:
            # Στην πρώτη εκτέλεση, πήγαινε κατευθείαν στα τελευταία συμβάντα
            return total
            
        if total > last_record:
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
            events = win32evtlog.ReadEventLog(hand, flags, last_record + 1)
            
            for event in events:
                event_id = event.EventID & 0xFFFF
                timestamp = event.TimeGenerated.Format("%Y-%m-%d %H:%M:%S")
                
                # Αν είναι κάποιο από τα κρίσιμα συμβάντα ή οποιοδήποτε νέο event
                meta = EVENT_MAP.get(event_id, {
                    "type": f"EVENT_{event_id}",
                    "status": "200" if log_type == "System" else "403",
                    "endpoint": f"/{log_type.lower()}/event-{event_id}"
                })
                
                user = "SYSTEM"
                if event.StringInserts and len(event.StringInserts) > 0:
                    user = str(event.StringInserts[0])[:20].strip() or "LocalHost"
                    
                log_line = f"{timestamp} | {user} | {meta['type']} | {meta['endpoint']} | {meta['status']}\n"
                
                with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                    f.write(log_line)
                    
                print(f"[LIVE WIN EVENT] Channel: {log_type} | ID: {event_id} | {log_line.strip()}")
                
            return total
        return last_record
    except Exception as err:
        return last_record

last_security = 0
last_system = 0

# Αρχικοποίηση στα πιο πρόσφατα
last_security = process_channel("Security", 0)
last_system = process_channel("System", 0)

print(f"[+] Έτοιμο! Security Base: {last_security}, System Base: {last_system}")
print("[*] Περιμένει νέα συμβάντα από το PC σου...\n")

while True:
    last_security = process_channel("Security", last_security)
    last_system = process_channel("System", last_system)
    time.sleep(1)