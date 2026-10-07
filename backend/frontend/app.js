async function loadDashboard() {
  try {
    const [statsRes, eventsRes] = await Promise.all([
      fetch("/api/stats"),
      fetch("/api/events/recent")
    ]);
    const stats = await statsRes.json();
    const events = await eventsRes.json();

    document.getElementById("total").textContent = stats.total_events;
    document.getElementById("devices").textContent = stats.devices;
    document.getElementById("critical").textContent = stats.critical;
    document.getElementById("high").textContent = stats.high;

    const tbody = document.getElementById("events");
    tbody.innerHTML = events.map(e => `
      <tr>
        <td>${new Date(e.created_at).toLocaleTimeString()}</td>
        <td>${escapeHtml(e.device_id)}</td>
        <td>${escapeHtml(e.event_type)}</td>
        <td>${escapeHtml(e.source_ip)}</td>
        <td>${escapeHtml(e.threat || "—")}</td>
        <td><b>${e.risk_score ?? 0}/100</b></td>
        <td><span class="badge ${e.severity}">${e.severity}</span></td>
      </tr>
    `).join("");

    if (events.length) {
      const e = events[0];
      const level = (e.severity || "LOW").toLowerCase();
      document.getElementById("latest").innerHTML = `
        <div class="threat-box ${level}">
          <div class="threat">${escapeHtml(e.threat || "SECURITY EVENT")}</div>
          <div class="risk">${e.risk_score ?? 0}<small>/100</small></div>
          <div><b>Device:</b> ${escapeHtml(e.device_id)}</div>
          <div><b>Source:</b> ${escapeHtml(e.source_ip)}</div>
          <p>${escapeHtml(e.explanation || e.message || "")}</p>
          <small class="muted">AI confidence: ${e.confidence ?? "—"}%</small>
        </div>`;
    }
  } catch (err) {
    console.error(err);
  }
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#039;"
  }[c]));
}

loadDashboard();
setInterval(loadDashboard, 3000);
