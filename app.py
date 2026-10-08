import streamlit as st
import pandas as pd
import os
import time

st.set_page_config(page_title="Live Security SIEM", page_icon="🚨", layout="wide")

st.title("🚨 Live Security Event Monitor (Real-Time Pipeline)")
st.markdown("Παρακολούθηση και ανάλυση ροής συμβάντων δικτύου σε πραγματικό χρόνο.")

def parse_logs():
    records = []
    if not os.path.exists("server_logs.txt"):
        return pd.DataFrame()
        
    with open("server_logs.txt", "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            if len(parts) == 5:
                records.append({
                    "Timestamp": parts[0].strip(),
                    "IP": parts[1].strip(),
                    "Method": parts[2].strip(),
                    "Endpoint": parts[3].strip(),
                    "Status": parts[4].strip()
                })
    return pd.DataFrame(records)

df = parse_logs()

if df.empty:
    st.warning("Αναμονή για δεδομένα... Βεβαιώσου ότι τρέχει το log_generator.py!")
    time.sleep(2)
    st.rerun()

# 1. Βασικά Metrics
col1, col2, col3, col4 = st.columns(4)
col1.metric("Συνολικά Events", len(df))
col2.metric("Μοναδικές IPs", df["IP"].nunique())

failed_logins = len(df[(df["Endpoint"] == "/login") & (df["Status"] == "401")])
col3.metric("Αποτυχημένα Logins", failed_logins)

forbidden = len(df[df["Status"] == "403"])
col4.metric("Απαγορευμένες Προσβάσεις (403)", forbidden)

# 2. Κανόνας Ανίχνευσης Επιθέσεων (Alerts Engine)
st.markdown("---")
st.subheader("⚠️ Ενεργές Ειδοποιήσεις Ασφαλείας (Threat Detections)")

# Έλεγχος για Brute Force: IP με πάνω από 3 αποτυχημένα logins
brute_force_ips = df[(df["Endpoint"] == "/login") & (df["Status"] == "401")]["IP"].value_counts()
flagged_brute_force = brute_force_ips[brute_force_ips >= 3].index.tolist()

# Έλεγχος για Scanning: IP με πάνω από 2 προσπάθειες σε 403 endpoints
scan_ips = df[df["Status"] == "403"]["IP"].value_counts()
flagged_scanners = scan_ips[scan_ips >= 2].index.tolist()

alert_col1, alert_col2 = st.columns(2)
with alert_col1:
    if flagged_brute_force:
        for ip in flagged_brute_force:
            st.error(f"🚨 **ALERT: Πιθανή Brute-Force επίθεση στο /login** από την IP `{ip}` ({brute_force_ips[ip]} αποτυχίες)!")
    else:
        st.success("✅ Καμία ένδειξη Brute-Force επίθεσης.")

with alert_col2:
    if flagged_scanners:
        for ip in flagged_scanners:
            st.warning(f"⚠️ **ALERT: Πιθανό Directory Scanning / Recon** από την IP `{ip}` ({scan_ips[ip]} απαγορευμένα requests)!")
    else:
        st.success("✅ Καμία ένδειξη Reconnaissance δραστηριότητας.")

st.markdown("---")

# 3. Live Γραφήματα
chart_col1, chart_col2 = st.columns(2)
with chart_col1:
    st.subheader("📊 Κορυφαίες IPs ανά Δραστηριότητα")
    st.bar_chart(df["IP"].value_counts().head(5))

with chart_col2:
    st.subheader("📌 Κατανομή HTTP Status Codes")
    st.bar_chart(df["Status"].value_counts())

# 4. Τα τελευταία 10 logs (Live Feed)
st.subheader("📜 Πρόσφατη Ροή Συμβάντων (Τελευταία 10 Logs)")
st.dataframe(df.tail(10).iloc[::-1], use_container_width=True)

# Αυτόματη ανανέωση της οθόνης κάθε 2 δευτερόλεπτα
time.sleep(2)
st.rerun()