let statusChartInstance = null;
let ipChartInstance = null;

// Διαχείριση πλοήγησης (Tabs)
function switchTab(tabId, element) {
    document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.remove("active"));
    document.querySelectorAll(".nav-links li").forEach(li => li.classList.remove("active"));
    
    document.getElementById(`tab-${tabId}`).classList.add("active");
    element.classList.add("active");

    const titles = {
        "live-monitor": "Real-Time Security Event Monitoring",
        "incident-alerts": "Threat Detection & Alert Feed",
        "firewall-rules": "Firewall Control Center",
        "log-explorer": "Raw Security Event Logs"
    };
    document.getElementById("tab-title").innerText = titles[tabId];
}

async function blockIP(ip) {
    const res = await fetch("/api/block", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: ip })
    });
    if (res.ok) fetchDashboardData();
}

async function unblockIP(ip) {
    const res = await fetch("/api/unblock", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: ip })
    });
    if (res.ok) fetchDashboardData();
}

async function fetchDashboardData() {
    try {
        const response = await fetch("/api/data");
        const data = await response.json();

        document.getElementById("last-update").innerText = `Ενημέρωση: ${new Date().toLocaleTimeString()}`;
        document.getElementById("total-events").innerText = data.total_events;
        document.getElementById("unique-ips").innerText = data.unique_ips;
        document.getElementById("active-alerts-count").innerText = data.alerts.length;
        document.getElementById("blocked-count").innerText = data.blocked_ips_count;

        // Alerts Feed
        const alertsContainer = document.getElementById("alerts-container");
        alertsContainer.innerHTML = "";
        if (data.alerts.length === 0) {
            alertsContainer.innerHTML = "<p style='color: #3fb950; font-size: 13px;'>✅ Δεν έχουν ανιχνευθεί ενεργές απειλές.</p>";
        } else {
            data.alerts.forEach(alert => {
                const alertDiv = document.createElement("div");
                alertDiv.className = `alert-item alert-${alert.type}`;
                alertDiv.innerHTML = `
                    <span>🚨 <strong>${alert.ip}</strong> [${alert.geo}]: ${alert.msg}</span>
                    <button class="block-btn" onclick="blockIP('${alert.ip}')">🚫 Block IP</button>
                `;
                alertsContainer.appendChild(alertDiv);
            });
        }

        // Firewall Table
        const blockedTableBody = document.getElementById("blocked-table-body");
        blockedTableBody.innerHTML = "";
        if (data.blocked_ips.length === 0) {
            blockedTableBody.innerHTML = "<tr><td colspan='4' style='color: #8b949e; text-align: center;'>Δεν υπάρχουν αποκλεισμένες IPs.</td></tr>";
        } else {
            data.blocked_ips.forEach(item => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td><code>${item.ip}</code></td>
                    <td>${item.geo}</td>
                    <td><span class="badge badge-401">Blocked</span></td>
                    <td><button class="unblock-btn" onclick="unblockIP('${item.ip}')">🔓 Unblock</button></td>
                `;
                blockedTableBody.appendChild(tr);
            });
        }

      
        // Logs Feed Table με Flags & VPN Detection
        const tableBody = document.getElementById("logs-table-body");
        tableBody.innerHTML = "";
        data.recent_logs.forEach(log => {
            const vpnTag = log.is_vpn 
                ? ` <span style="background: #bd561d; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold;">🛡️ VPN/PROXY</span>` 
                : '';

            const row = document.createElement("tr");
            row.innerHTML = `
                <td>${log.timestamp}</td>
                <td>${log.flag} ${log.country}</td>
                <td><code>${log.ip}</code>${vpnTag}</td>
                <td><strong>${log.method}</strong></td>
                <td>${log.endpoint}</td>
                <td><span class="badge badge-${log.status}">${log.status}</span></td>
            `;
            tableBody.appendChild(row);
        });
        // Charts
        updateCharts(data.status_distribution, data.top_ips);

    } catch (err) {
        console.error("Σφάλμα ανάκτησης δεδομένων:", err);
    }
}

function updateCharts(statusDist, topIps) {
    const statusCtx = document.getElementById("statusChart").getContext("2d");
    const statusLabels = Object.keys(statusDist);
    const statusValues = Object.values(statusDist);

    if (statusChartInstance) statusChartInstance.destroy();
    statusChartInstance = new Chart(statusCtx, {
        type: 'doughnut',
        data: {
            labels: statusLabels,
            datasets: [{
                data: statusValues,
                backgroundColor: ['#238636', '#da3633', '#d29922', '#6e7681']
            }]
        },
        options: { responsive: true, plugins: { legend: { labels: { color: '#8b949e' } } } }
    });

    const ipCtx = document.getElementById("ipChart").getContext("2d");
    const ipLabels = Object.keys(topIps);
    const ipValues = Object.values(topIps);

    if (ipChartInstance) ipChartInstance.destroy();
    ipChartInstance = new Chart(ipCtx, {
        type: 'bar',
        data: {
            labels: ipLabels,
            datasets: [{
                label: 'Requests',
                data: ipValues,
                backgroundColor: '#58a6ff'
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: { ticks: { color: '#8b949e' } },
                y: { ticks: { color: '#8b949e' } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

fetchDashboardData();
setInterval(fetchDashboardData, 2000);