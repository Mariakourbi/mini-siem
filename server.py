from flask import Flask, render_template, jsonify, request
import os
from datetime import datetime
from collections import Counter

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "server_logs.txt")
BLOCKED_FILE = os.path.join(BASE_DIR, "blocked_ips.txt")

GEO_DB = {
    "127.0.0.1": {"country": "Localhost Admin", "code": "LOC", "flag": "💻"},
    "192.168.1.15": {"country": "Local LAN", "code": "GR", "flag": "🇬🇷"}
}

def lookup_ip(ip):
    return GEO_DB.get(ip, {"country": "Internal Network", "code": "NET", "flag": "🌐"})

def get_blocked_ips():
    if not os.path.exists(BLOCKED_FILE):
        return []
    with open(BLOCKED_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def write_blocked_ips(ip_list):
    with open(BLOCKED_FILE, "w", encoding="utf-8") as f:
        for ip in ip_list:
            f.write(f"{ip}\n")

def parse_logs():
    records = []
    if not os.path.exists(LOG_FILE):
        return records

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            if len(parts) == 5:
                ip = parts[1].strip()
                geo = lookup_ip(ip)
                records.append({
                    "timestamp": parts[0].strip(),
                    "ip": ip,
                    "method": parts[2].strip(),
                    "endpoint": parts[3].strip(),
                    "status": parts[4].strip(),
                    "country": geo["country"],
                    "flag": geo["flag"]
                })
    return records

# Καταγραφή πραγματικής κίνησης
@app.after_request
def log_request_traffic(response):
    # Εξαιρούμε τα εσωτερικά endpoints του ίδιου του dashboard
    if request.path.startswith("/api/data") or request.path.startswith("/static"):
        return response

    client_ip = request.remote_addr
    method = request.method
    endpoint = request.path
    status = response.status_code
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    entry = f"{timestamp} | {client_ip} | {method} | {endpoint} | {status}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)
        f.flush()

    return response

# --- Endpoints για έλεγχο ασφαλείας ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def mock_login():
    if request.method == "POST":
        u = request.form.get("user")
        p = request.form.get("pass")
        if u == "admin" and p == "secret":
            return "<h3>✅ Success Logon!</h3>"
        return "<h3>❌ 401 Unauthorized</h3>", 401
    return '<form method="post">User: <input name="user"> Pass: <input name="pass" type="password"><button>Login</button></form>'

@app.route("/admin")
@app.route("/.env")
@app.route("/wp-login.php")
def mock_forbidden():
    return "<h3>🚫 403 Forbidden: Scanning Detected</h3>", 403

# --- SIEM REST APIs ---
@app.route("/api/data")
def api_data():
    logs = parse_logs()
    blocked_ips = get_blocked_ips()

    total_events = len(logs)
    unique_ips = len(set(log["ip"] for log in logs))

    ip_counter = Counter(log["ip"] for log in logs)
    status_counter = Counter(log["status"] for log in logs)

    alerts = []
    failed_logins = Counter(
        log["ip"] for log in logs if log["endpoint"] == "/login" and log["status"] == "401"
    )
    for ip, count in failed_logins.items():
        if count >= 3 and ip not in blocked_ips:
            geo = lookup_ip(ip)
            alerts.append({
                "type": "danger",
                "ip": ip,
                "geo": f"{geo['flag']} {geo['country']}",
                "msg": f"Brute-Force επίθεση στο /login ({count} αποτυχίες)"
            })

    recon_ips = Counter(
        log["ip"] for log in logs if log["status"] == "403"
    )
    for ip, count in recon_ips.items():
        if count >= 2 and ip not in blocked_ips:
            geo = lookup_ip(ip)
            alerts.append({
                "type": "warning",
                "ip": ip,
                "geo": f"{geo['flag']} {geo['country']}",
                "msg": f"Directory Reconnaissance Scanning ({count} 403s)"
            })

    blocked_details = [{"ip": ip, "geo": f"{lookup_ip(ip)['flag']} {lookup_ip(ip)['country']}"} for ip in blocked_ips]

    return jsonify({
        "total_events": total_events,
        "unique_ips": unique_ips,
        "blocked_ips_count": len(blocked_ips),
        "blocked_ips": blocked_details,
        "status_distribution": dict(status_counter),
        "top_ips": dict(ip_counter.most_common(5)),
        "alerts": alerts,
        "recent_logs": logs[-15:][::-1]
    })

@app.route("/api/block", methods=["POST"])
def block_ip():
    data = request.get_json()
    ip_to_block = data.get("ip")
    if ip_to_block:
        blocked = get_blocked_ips()
        if ip_to_block not in blocked:
            blocked.append(ip_to_block)
            write_blocked_ips(blocked)
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 400

@app.route("/api/unblock", methods=["POST"])
def unblock_ip():
    data = request.get_json()
    ip_to_unblock = data.get("ip")
    if ip_to_unblock:
        blocked = [ip for ip in get_blocked_ips() if ip != ip_to_unblock]
        write_blocked_ips(blocked)
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)