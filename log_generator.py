import time
import random
from datetime import datetime

# Λίστα με πιθανές IPs (κάποιες κανονικές, κάποιες επιτιθέμενες)
IPS = [
    "192.168.1.15", "192.168.1.22", "192.168.1.99",   # Normal Users
    "10.0.0.5",                                       # Brute Force Attacker
    "172.16.0.44",                                     # Scanner / Recon
    "45.33.32.156", "185.220.101.5"                   # External Suspicious IPs
]

ENDPOINTS = ["/home", "/dashboard", "/profile", "/login", "/admin", "/api/data", "/config.php"]
METHODS = ["GET", "POST"]

print("[*] Log Generator ξεκίνησε! Παράγει ζωντανά logs στο 'server_logs.txt'...")
print("[*] Πάτα CTRL + C για διακοπή.\n")

while True:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = random.choice(IPS)
    
    # Προσομοίωση σεναρίων κυβερνοεπιθέσεων
    if ip == "10.0.0.5":
        # Σενάριο Brute Force: χτυπάει μόνο το login με αποτυχίες
        endpoint = "/login"
        method = "POST"
        status = random.choices(["401", "200"], weights=[0.85, 0.15])[0]
    elif ip == "172.16.0.44":
        # Σενάριο Reconnaissance: ψάχνει ευαίσθητα paths
        endpoint = random.choice(["/admin", "/config.php"])
        method = "GET"
        status = "403"
    else:
        # Κανονικός χρήστης
        endpoint = random.choice(["/home", "/dashboard", "/profile", "/api/data"])
        method = random.choice(METHODS)
        status = random.choices(["200", "404"], weights=[0.9, 0.1])[0]

    # Δημιουργία γραμμής log
    log_line = f"{now} | {ip} | {method} | {endpoint} | {status}\n"
    
    # Εγγραφή στο αρχείο (append mode)
    with open("server_logs.txt", "a", encoding="utf-8") as f:
        f.write(log_line)
        
    print(f"[LOG] {log_line.strip()}")
    
    # Καθυστέρηση μεταξύ 0.5 και 1.5 δευτερολέπτων για ρεαλιστική ροή
    time.sleep(random.uniform(0.5, 1.5))