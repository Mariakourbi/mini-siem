import os
import json
import urllib.request
from datetime import datetime
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

LOG_FILE = "server_logs.txt"
BLOCKED_IPS_FILE = "blocked_ips.txt"

# Προσωρινή μνήμη (Cache) για να μην καλούμε το API πολλές φορές για την ίδια IP
IP_CACHE = {}

def get_client_ip():
    """Εντοπίζει την πραγματική IP ακόμα και πίσω από Proxies/Cloud/ngrok."""
    if request.headers.get('X-Forwarded-For'):
        # Το πρώτο στοιχείο στη λίστα είναι η αρχική IP του πελάτη
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def get_blocked_ips():
    if not os.path.exists(BLOCKED_IPS_FILE):
        return set()
    with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())

def add_blocked_ip(ip):
    blocked = get_blocked_ips()
    if ip not in blocked:
        with open(BLOCKED_IPS_FILE, "a", encoding="utf-8") as f:
            f.write(f"{ip}\n")

def remove_blocked_ip(ip):
    blocked = get_blocked_ips()
    if ip in blocked:
        blocked.remove(ip)
        with open(BLOCKED_IPS_FILE, "w", encoding="utf-8") as f:
            for item in blocked:
                f.write(f"{item}\n")

def lookup_ip(ip):
    """Ελέγχει αν η IP είναι τοπική ή εξωτερική και αν ανήκει σε VPN/Proxy/Datacenter."""
    if ip in ["127.0.0.1", "localhost"] or ip.startswith("192.168.") or ip.startswith("10."):
        return {
            "country": "Localhost Admin",
            "code": "LOC",
            "flag": "💻",
            "is_vpn": False,
            "org": "Internal Network"
        }

    if ip in IP_CACHE:
        return IP_CACHE[ip]

    try:
        # IP Intelligence query
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,proxy,hosting,org"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mini-SIEM-Scanner'})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                # Θεωρείται VPN αν είναι flagged ως proxy ή ανήκει σε data center / hosting provider
                is_vpn = bool(data.get("proxy", False) or data.get("hosting", False))
                result = {
                    "country": data.get("country", "Unknown"),
                    "code": data.get("countryCode", "UN"),
                    "flag": "🛡️" if is_vpn else "🌐",
                    "is_vpn": is_vpn,
                    "org": data.get("org", "Unknown ISP")
                }
                IP_CACHE[ip] = result
                return result
    except Exception as e:
        print(f"[!] Intelligence lookup failed for {ip}: {e}")

    fallback = {"country": "External IP", "code": "EXT", "flag": "🌐", "is_vpn": False, "org": "N/A"}
    IP_CACHE[ip] = fallback
    return fallback

def log_event(status_code):
    """Αποθηκεύει το HTTP αίτημα στο αρχείο καταγραφής."""
    client_ip = get_client_ip()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"{timestamp} | {client_ip} | {request.method} {request.path} | {status_code}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)

# --- Host Firewall Middleware ---
@app.before_request
def firewall_check():
    client_ip = get_client_ip()
    if client_ip in ["127.0.0.1", "localhost"]:
        return None
    blocked = get_blocked_ips()
    # Επιτρέπουμε τη διαχείριση του firewall ακόμα και αν γίνει block
    if client_ip in blocked and not request.path.startswith('/api/unblock'):
        log_event(403)
        return "<h1>403 Forbidden</h1><p>Your IP has been permanently blocked by Host WAF.</p>", 403

# --- Front End & Routes ---
@app.route('/')
def dashboard():
    log_event(200)
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Προσομοίωση: όλοι οι κωδικοί αποτυγχάνουν για να δοκιμάζουμε Brute Force
        log_event(401)
        return "<h1>401 Unauthorized</h1><p>Invalid credentials.</p>", 401
    log_event(200)
    return '''
        <h2>Protected Login Portal</h2>
        <form method="POST">
            Username: <input type="text" name="user"><br><br>
            Password: <input type="password" name="pass"><br><br>
            <input type="submit" value="Sign In">
        </form>
    '''

@app.route('/admin')
@app.route('/.env')
@app.route('/wp-login.php')
def sensitive_routes():
    log_event(403)
    return "<h1>403 Forbidden</h1><p>Access Denied to restricted administrative resources.</p>", 403

# --- API Endpoints για το SOC Dashboard ---
@app.route('/api/data')
def api_data():
    if not os.path.exists(LOG_FILE):
        return jsonify({"logs": [], "stats": {}, "alerts": []})

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    logs = []
    status_counts = {}
    ip_counts = {}
    login_fails = {}
    scan_attempts = {}
    blocked_ips = get_blocked_ips()

    # Διαβάζουμε τα τελευταία 150 συμβάντα
    for line in reversed(lines[-150:]):
        parts = [p.strip() for p in line.split('|')]
        if len(parts) == 4:
            ts, ip, req_path, code = parts
            geo = lookup_ip(ip)

            logs.append({
                "time": ts,
                "ip": ip,
                "request": req_path,
                "status": code,
                "geo": f"{geo['flag']} {geo['country']}",
                "is_vpn": geo.get("is_vpn", False),
                "isp": geo.get("org", ""),
                "is_blocked": ip in blocked_ips
            })

            status_counts[code] = status_counts.get(code, 0) + 1
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

            if "/login" in req_path and code == "401":
                login_fails[ip] = login_fails.get(ip, 0) + 1
            if code == "403" and any(r in req_path for r in ['/admin', '/.env', '/wp-login.php']):
                scan_attempts[ip] = scan_attempts.get(ip, 0) + 1

    alerts = []
    # 1. Alert: Brute Force
    for ip, count in login_fails.items():
        if count >= 3:
            alerts.append({
                "type": "danger",
                "ip": ip,
                "msg": f"🚨 Brute-Force Alert: {count} αποτυχημένες προσπάθειες εισόδου!"
            })

    # 2. Alert: Reconnaissance / Scanning
    for ip, count in scan_attempts.items():
        if count >= 2:
            alerts.append({
                "type": "warning",
                "ip": ip,
                "msg": f"⚠️ Reconnaissance Alert: Ανιχνεύθηκε σάρωση ευπαθειών ({count} restricted paths)!"
            })

    # 3. Alert: VPN / Proxy Traffic
    checked_vpn_ips = set()
    for entry in logs:
        ip = entry["ip"]
        if entry["is_vpn"] and ip not in checked_vpn_ips:
            checked_vpn_ips.add(ip)
            alerts.append({
                "type": "info",
                "ip": ip,
                "msg": f"🛡️ VPN/Proxy Detected: Κυκλοφορία μέσω ανώνυμου δικτύου ({entry['isp']})"
            })

    return jsonify({
        "logs": logs,
        "stats": {
            "status_counts": status_counts,
            "top_ips": sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        },
        "alerts": alerts
    })

@app.route('/api/block', methods=['POST'])
def api_block():
    ip = request.json.get('ip')
    if ip:
        add_blocked_ip(ip)
        return jsonify({"success": True})
    return jsonify({"success": False}), 400

@app.route('/api/unblock', methods=['POST'])
def api_unblock():
    ip = request.json.get('ip')
    if ip:
        remove_blocked_ip(ip)
        return jsonify({"success": True})
    return jsonify({"success": False}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)