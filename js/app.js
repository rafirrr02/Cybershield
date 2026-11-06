/* CyberShield — app logic (simulated data, stored in localStorage)
   Simulated tables: firewall_rules, security_logs, blacklist_ips
   Struktur SQL aslinya ada di database/cybershield.sql */
const KEY = 'cybershield_db_v2';
const $ = s => document.querySelector(s);
const fmt = n => n.toLocaleString('en-US');
const nowTime = () => new Date().toISOString().substr(11, 8);
const nowDT = () => { const d = new Date(); return d.toISOString().slice(0, 10) + ' ' + d.toISOString().substr(11, 8); };
const today = () => new Date().toISOString().slice(0, 10);
const randIp = () => `${Math.floor(Math.random()*223+1)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*254+1)}`;
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

let db, firewallOn = true, simTimer = null, trafficTimer = null, trafficOn = true;
let total = 186666, allowed = 152212, blocked = 34454;
let sessAllowed = 524, sessBlocked = 512;
let allowedHist = [], blockedHist = [];
for (let i = 0; i < 60; i++) { allowedHist.push(280 + Math.random()*320); blockedHist.push(40 + Math.random()*220); }
let ports = [
  { port: 22, name: 'SSH', count: 1879 }, { port: 3389, name: 'RDP', count: 1353 },
  { port: 23, name: 'Telnet', count: 1003 }, { port: 445, name: 'SMB', count: 795 },
  { port: 3306, name: 'MySQL', count: 452 }, { port: 1433, name: 'MSSQL', count: 39 },
];

function seed() {
  // Seed data matching the reference screenshots
  const d = today();
  return {
    rules: [
      { id: 1, name: 'Allow HTTP', ip: '*', port: 80, proto: 'TCP', action: 'ALLOW', active: true },
      { id: 2, name: 'Allow HTTPS', ip: '*', port: 443, proto: 'TCP', action: 'ALLOW', active: true },
      { id: 3, name: 'Allow DNS', ip: '*', port: 53, proto: 'UDP', action: 'ALLOW', active: true },
      { id: 4, name: 'Block Telnet', ip: '*', port: 23, proto: 'TCP', action: 'BLOCK', active: true },
      { id: 5, name: 'Allow SSH Admin (LAN)', ip: '192.168.1.0/24', port: 22, proto: 'TCP', action: 'ALLOW', active: false },
    ],
    logs: [
      { time: d + ' 02:47:58', ip: '104.179.86.20', port: 53, activity: 'Normal traffic (DNS)', action: 'ALLOWED' },
      { time: d + ' 02:47:58', ip: '203.54.142.233', port: 443, activity: 'Normal traffic (HTTPS)', action: 'ALLOWED' },
      { time: d + ' 02:47:58', ip: '192.168.1.206', port: 1433, activity: 'External database access', action: 'BLOCKED' },
      { time: d + ' 02:47:57', ip: '203.155.152.203', port: 3306, activity: 'External database access', action: 'BLOCKED' },
      { time: d + ' 02:47:57', ip: '203.65.149.93', port: 21, activity: 'FTP access attempt', action: 'BLOCKED' },
      { time: d + ' 02:47:56', ip: '192.168.1.138', port: 23, activity: 'Unauthorized Telnet access', action: 'BLOCKED' },
      { time: d + ' 02:47:56', ip: '192.168.1.135', port: 80, activity: 'Normal traffic (HTTP)', action: 'ALLOWED' },
      { time: d + ' 02:47:56', ip: '203.58.29.70', port: 22, activity: 'SSH Brute Force attempt', action: 'BLOCKED' },
    ],
    blacklist: [
      { ip: '185.220.101.45', reason: 'TOR exit node - scanning activity', date: '2026-10-31 14:32:10' },
      { ip: '45.155.205.233', reason: 'SSH brute force source', date: '2026-11-01 14:32:10' },
      { ip: '91.240.118.172', reason: 'Malware C2 server', date: '2026-11-03 09:32:10' },
    ]
  };
}
function load() { try { db = JSON.parse(localStorage.getItem(KEY)) || seed(); } catch(e) { db = seed(); } save(); }
function save() { localStorage.setItem(KEY, JSON.stringify(db)); }
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 2600); }

/* ---------- Navigasi ---------- */
function goPage(name) {
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.page === name));
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + name));
  window.scrollTo({ top: 0, behavior: 'smooth' });
}
document.querySelectorAll('.nav-item').forEach(b => b.addEventListener('click', () => goPage(b.dataset.page)));

/* ---------- Render ---------- */
function renderStats() {
  $('#statTotal').textContent = fmt(total);
  $('#statAllowed').textContent = fmt(allowed);
  $('#statBlocked').textContent = fmt(blocked);
  $('#statAllowRate').textContent = (allowed / Math.max(1, total) * 100).toFixed(1) + '%';
  const act = db.rules.filter(r => r.active);
  $('#statRules').textContent = act.length;
  $('#statRulesDetail').textContent = `${act.filter(r => r.action==='ALLOW').length} Allow / ${act.filter(r => r.action==='BLOCK').length} Block`;
  $('#navRuleCount').textContent = db.rules.length;
  $('#ruleCountText').textContent = db.rules.length;
  $('#portTotal').textContent = fmt(ports.reduce((a, p) => a + p.count, 0));
}
function renderPorts() {
  const max = Math.max(...ports.map(p => p.count));
  $('#portList').innerHTML = ports.map(p => `
    <div class="port-row"><span class="pname">${p.port} (${p.name})</span>
    <span class="port-track"><i style="width:${Math.round(p.count/max*100)}%"></i></span>
    <span class="pval">${fmt(p.count)}</span></div>`).join('');
}
function tag(action) { return action === 'BLOCKED' ? '<span class="tag tag-block">⛔ BLOCKED</span>' : '<span class="tag tag-allow">✓ ALLOWED</span>'; }
function renderLogs() {
  const q = ($('#logSearch').value || '').toLowerCase(), f = $('#logFilter').value;
  const rows = db.logs.filter(l => (!f || l.action === f) && (!q || (l.ip + ' ' + l.port + ' ' + l.activity).toLowerCase().includes(q)));
  $('#logCount').textContent = rows.length;
  const totalEl = $('#logTotal'); if (totalEl) totalEl.textContent = db.logs.length;
  $('#logTable').innerHTML = rows.slice().reverse().map(l => `<tr><td>${esc(l.time)}</td><td>${esc(l.ip)}</td><td>${l.port}</td><td>${esc(l.activity)}</td><td>${tag(l.action)}</td>
    <td>${l.action === 'BLOCKED' ? `<button class="btn btn-ghost btn-sm" onclick="blockFromLog('${esc(l.ip)}','${esc(l.activity)}')">+ Blacklist</button>` : ''}</td></tr>`).join('')
    || '<tr><td colspan="6">No matching logs.</td></tr>';
  $('#recentLogs').innerHTML = db.logs.slice(-6).reverse().map(l => `<tr><td>${esc(l.time.slice(11))}</td><td>${esc(l.ip)}</td><td>${l.port}</td><td>${esc(l.activity)}</td><td>${tag(l.action)}</td></tr>`).join('');
}
function ipLabel(ip) { return ip === '*' ? 'All IPs (*)' : esc(ip); }
function renderRules() {
  const q = ($('#ruleSearch').value || '').toLowerCase();
  const rows = db.rules.filter(r => !q || (r.name + r.ip + r.port).toLowerCase().includes(q));
  $('#ruleTable').innerHTML = rows.map(r => `<tr>
    <td><input type="checkbox" class="switch" ${r.active ? 'checked' : ''} onchange="toggleRule(${r.id},this.checked)" title="Enable / Disable"></td>
    <td>${esc(r.name)}</td>
    <td>${r.action === 'ALLOW' ? '<span class="tag tag-allow">ALLOW</span>' : '<span class="tag tag-block">BLOCK</span>'}</td>
    <td>${ipLabel(r.ip)}</td><td>${r.port}</td><td>${r.proto}</td>
    <td><button class="btn btn-red btn-sm" onclick="deleteRule(${r.id})">🗑 Delete</button></td></tr>`).join('')
    || '<tr><td colspan="7">No matching rules.</td></tr>';
  renderStats();
}
function renderBlacklist() {
  $('#blCount').textContent = db.blacklist.length;
  $('#blTable').innerHTML = db.blacklist.map(b => `<tr><td>${esc(b.ip)}</td><td>${esc(b.reason)}</td><td>${esc(b.date)}</td>
    <td><button class="btn btn-red btn-sm" onclick="deleteBlacklist('${esc(b.ip)}')">Remove from Blacklist</button></td></tr>`).join('')
    || '<tr><td colspan="4">Blacklist is empty.</td></tr>';
}
function renderAll() { renderStats(); renderPorts(); renderLogs(); renderRules(); renderBlacklist(); }

/* ---------- Log & keputusan firewall ----------
   Urutan evaluasi (sesuai screenshot #rules):
   Blacklist → BLOCK rules → ALLOW rules → automatic block (default deny) */
function ipMatch(ip, ruleIp) {
  if (ruleIp === '*' || ruleIp === '0.0.0.0/0') return true;
  if (ruleIp.includes('/')) return ip.startsWith(ruleIp.split('/')[0].slice(0, ruleIp.split('/')[0].lastIndexOf('.')));
  return ip === ruleIp;
}
function addLog(ip, port, activity, action) {
  db.logs.push({ time: nowDT(), ip, port, activity, action });
  if (db.logs.length > 500) db.logs = db.logs.slice(-500); // maks. 500 terakhir
  save(); renderLogs();
  const feed = $('#simFeed');
  if (feed) {
    feed.insertAdjacentHTML('afterbegin', `<tr><td>${nowTime()}</td><td>${esc(ip)}</td><td>${port}</td><td>${esc(activity)}</td><td>${tag(action)}</td></tr>`);
    while (feed.rows.length > 10) feed.deleteRow(-1);
  }
}
function decide(ip, port) {
  if (!firewallOn) return { action: 'ALLOWED', reason: 'Firewall OFF — all connections pass (emergency mode).' };
  if (db.blacklist.some(b => b.ip === ip || (b.ip.includes('/') && ipMatch(ip, b.ip)))) return { action: 'BLOCKED', reason: `IP ${ip} is on the Blacklist — rejected before rules are evaluated.` };
  const block = db.rules.find(r => r.active && r.action === 'BLOCK' && r.port === +port && ipMatch(ip, r.ip));
  if (block) return { action: 'BLOCKED', reason: `Matched BLOCK rule “${block.name}” (${block.ip}:${block.port}).` };
  const allow = db.rules.find(r => r.active && r.action === 'ALLOW' && r.port === +port && ipMatch(ip, r.ip));
  if (allow) return { action: 'ALLOWED', reason: `Matched ALLOW rule “${allow.name}” (${allow.ip}:${allow.port}).` };
  return { action: 'BLOCKED', reason: `Port ${port} has no ALLOW rule — automatic block (default deny).` };
}
function applyDecision(ip, port, activity) {
  const d = decide(ip, port);
  if (d.action === 'BLOCKED') { blocked++; sessBlocked++; const p = ports.find(x => x.port === +port); if (p) p.count++; }
  else { allowed++; sessAllowed++; }
  total++;
  addLog(ip, port, activity, d.action);
  const sa = $('#sessAllowed'), sb = $('#sessBlocked');
  if (sa) sa.textContent = fmt(sessAllowed) + ' allowed';
  if (sb) sb.textContent = fmt(sessBlocked) + ' blocked';
  renderStats(); renderPorts();
  return d;
}

/* ---------- CRUD: Rules ---------- */
window.toggleRule = (id, on) => { const r = db.rules.find(x => x.id === id); if (r) { r.active = on; save(); renderRules(); toast(`Rule “${r.name}” ${on ? 'ENABLED' : 'DISABLED'}.`); } };
window.deleteRule = id => { const r = db.rules.find(x => x.id === id); db.rules = db.rules.filter(x => x.id !== id); save(); renderRules(); toast(`Rule “${r ? r.name : id}” deleted.`); };
$('#ruleForm').addEventListener('submit', e => {
  e.preventDefault();
  const r = { id: Math.max(0, ...db.rules.map(x => x.id)) + 1, name: $('#ruleName').value.trim(), ip: $('#ruleIp').value.trim(), port: +$('#rulePort').value, proto: $('#ruleProto').value, action: $('#ruleAction').value, active: true };
  db.rules.push(r); save(); renderRules(); e.target.reset(); toast(`Rule “${r.name}” added & active.`);
});
$('#ruleSearch').addEventListener('input', renderRules);

/* ---------- CRUD: Blacklist ---------- */
window.deleteBlacklist = ip => { db.blacklist = db.blacklist.filter(b => b.ip !== ip); save(); renderBlacklist(); toast(`IP ${ip} removed from the blacklist.`); };
window.blockFromLog = (ip, reason) => {
  if (db.blacklist.some(b => b.ip === ip)) return toast(`IP ${ip} is already on the blacklist.`);
  db.blacklist.push({ ip, reason: reason || 'From Security Log', date: nowDT() }); save(); renderBlacklist(); toast(`IP ${ip} added to the blacklist.`);
};
$('#blacklistForm').addEventListener('submit', e => {
  e.preventDefault();
  const ip = $('#blIp').value.trim(), reason = $('#blReason').value.trim() || 'Blocked manually';
  if (db.blacklist.some(b => b.ip === ip)) return toast('That IP is already on the blacklist.');
  db.blacklist.push({ ip, reason, date: nowDT() }); save(); renderBlacklist(); e.target.reset(); toast(`IP ${ip} blocked.`);
});
$('#btnShowRuleForm').addEventListener('click', () => {
  const f = $('#ruleForm'); f.hidden = !f.hidden;
  $('#btnShowRuleForm').textContent = f.hidden ? '＋ Add Rule' : '✕ Close Form';
  if (!f.hidden) $('#ruleName').focus();
});

/* ---------- Log: filter / export / delete ---------- */
$('#logFilter').addEventListener('change', renderLogs);
$('#logSearch').addEventListener('input', renderLogs);
$('#btnClearLog').addEventListener('click', () => { if (confirm('Delete all security logs?')) { db.logs = []; save(); renderLogs(); toast('All logs deleted.'); } });
$('#btnExportCsv').addEventListener('click', () => {
  const csv = 'time,source_ip,dest_port,activity_type,action\n' + db.logs.map(l => `${l.time},${l.ip},${l.port},"${l.activity}",${l.action}`).join('\n');
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })); a.download = 'cybershield_security_logs.csv'; a.click();
  toast('Logs exported to CSV.');
});

/* ---------- Simulasi ---------- */
// Attacks are recognised by IDS/IPS from their pattern, so they are always BLOCKED while the firewall is on,
// even if their port (e.g. 80/443) is allowed for normal traffic.
document.querySelectorAll('[data-attack]').forEach(btn => btn.addEventListener('click', () => {
  const type = btn.dataset.attack, port = +btn.dataset.port;
  $('#simStatus').innerHTML = `Status: <b style="color:#ff5c7a">⚠ Simulation ${type} RUNNING…</b> 6 attempts sent to the firewall.`;
  let n = 0;
  const iv = setInterval(() => {
    const ip = randIp();
    let d;
    if (!firewallOn) { d = applyDecision(ip, port, type); }
    else { blocked++; sessBlocked++; total++; addLog(ip, port, type, 'BLOCKED'); const p = ports.find(x => x.port === port); if (p) p.count++; renderStats(); renderPorts(); const sa = $('#sessAllowed'), sb = $('#sessBlocked'); if (sa) sa.textContent = fmt(sessAllowed) + ' allowed'; if (sb) sb.textContent = fmt(sessBlocked) + ' blocked'; d = { action: 'BLOCKED' }; }
    toast(`${type} from ${ip}:${port} → ${d.action}`);
    if (++n >= 6) { clearInterval(iv); $('#simStatus').innerHTML = `Status: <b>Simulation ${type} finished.</b> Check the Security Log — all attempts are recorded.`; }
  }, 450);
}));
const TRAFFIC_SCENARIOS = [
  { port: 53, activity: 'Normal traffic (DNS)' }, { port: 443, activity: 'Normal traffic (HTTPS)' },
  { port: 80, activity: 'Normal traffic (HTTP)' }, { port: 443, activity: 'Normal traffic (HTTPS)' },
  { port: 80, activity: 'Normal traffic (HTTP)' }, { port: 1433, activity: 'External database access' },
  { port: 3306, activity: 'External database access' }, { port: 21, activity: 'FTP access attempt' },
  { port: 23, activity: 'Unauthorized Telnet access' }, { port: 22, activity: 'SSH Brute Force attempt' },
  { port: 3389, activity: 'RDP access attempt' }, { port: 8080, activity: 'Port scanning (port not allowed)' },
];
function trafficTick() {
  const s = TRAFFIC_SCENARIOS[Math.floor(Math.random() * TRAFFIC_SCENARIOS.length)];
  const ip = Math.random() < 0.3 ? '192.168.1.' + (100 + Math.floor(Math.random() * 110)) : randIp();
  applyDecision(ip, s.port, s.activity);
}
function startTraffic() {
  clearInterval(trafficTimer);
  trafficTimer = setInterval(trafficTick, +$('#trafficSpeed').value);
  trafficOn = true; $('#btnTraffic').textContent = '⏸ Pause Traffic';
  $('#simStatus').innerHTML = 'Status: <b style="color:#00f0ff">▶ Normal traffic running…</b>';
}
function stopTraffic() {
  clearInterval(trafficTimer); trafficTimer = null; trafficOn = false;
  $('#btnTraffic').textContent = '▶ Resume Traffic';
  $('#simStatus').innerHTML = 'Status: <b>Traffic paused.</b>';
}
$('#btnTraffic').addEventListener('click', () => trafficOn ? stopTraffic() : startTraffic());
$('#trafficSpeed').addEventListener('change', () => { if (trafficOn) startTraffic(); });

/* ---------- Uji koneksi manual ---------- */
$('#testForm').addEventListener('submit', e => {
  e.preventDefault();
  const ip = $('#testIp').value.trim(), port = +$('#testPort').value;
  const d = applyDecision(ip, port, 'Manual Connection Test');
  const box = $('#testResult');
  box.className = 'test-result ' + (d.action === 'BLOCKED' ? 'blocked' : 'allowed');
  box.innerHTML = `<b style="font-size:18px">${d.action === 'BLOCKED' ? '⛔ BLOCKED' : '✓ ALLOWED'}</b> — ${ip}:${port}<br>${esc(d.reason)}<br><span style="color:#8b8ba3">This result has been recorded in the Security Log.</span>`;
});

/* ---------- Power / firewall master ---------- */
$('#btnPower').addEventListener('click', () => {
  firewallOn = !firewallOn;
  $('#btnPower').textContent = firewallOn ? '⏻ Disable Firewall' : '⏻ Enable Firewall';
  $('#btnPower').classList.toggle('off', !firewallOn);
  $('#firewallStateText').textContent = firewallOn ? 'ACTIVE (ALLOW-LIST)' : 'OFF — BYPASS';
  $('#pillFirewall').style.borderColor = firewallOn ? '' : '#ff003c';
  $('#threatLevel').textContent = firewallOn ? 'MEDIUM' : 'CRITICAL';
  toast(firewallOn ? 'Firewall ENABLED again.' : '⚠ Firewall DISABLED — all connections will be allowed!');
});

/* ---------- Chart + jam + tick live ---------- */
function drawChart() {
  const c = $('#trafficChart'), ctx = c.getContext('2d');
  const W = c.width = c.clientWidth * 2, H = c.height = 520;
  ctx.clearRect(0, 0, W, H);
  ctx.strokeStyle = 'rgba(255,255,255,.08)'; ctx.lineWidth = 1;
  for (let i = 1; i < 4; i++) { ctx.beginPath(); ctx.moveTo(0, H * i / 4); ctx.lineTo(W, H * i / 4); ctx.stroke(); }
  const line = (data, color) => {
    ctx.beginPath(); ctx.strokeStyle = color; ctx.lineWidth = 3; ctx.shadowColor = color; ctx.shadowBlur = 12;
    data.forEach((v, i) => { const x = i / (data.length - 1) * W, y = H - (v / 820) * H; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
    ctx.stroke(); ctx.shadowBlur = 0;
  };
  line(allowedHist, '#00f0ff'); line(blockedHist, '#ff003c');
}
setInterval(() => {
  const a = 200 + Math.random() * 380, b = 20 + Math.random() * 260;
  allowedHist.push(a); blockedHist.push(b); allowedHist.shift(); blockedHist.shift();
  if (firewallOn) { total += Math.floor(a / 4); allowed += Math.floor(a / 5); blocked += Math.floor(b / 6); }
  const cpu = 12 + Math.floor(Math.random() * 14), mem = 38 + Math.floor(Math.random() * 12), bw = (0.8 + Math.random() * 1.4).toFixed(1);
  $('#cpuVal').textContent = cpu + '%'; $('#cpuBar').style.width = cpu + '%';
  $('#memVal').textContent = mem + '%'; $('#memBar').style.width = mem + '%';
  $('#bwVal').textContent = bw + ' MB/s'; $('#bwBar').style.width = Math.min(90, bw * 28) + '%';
  $('#clock').textContent = nowTime() + ' UTC';
  renderStats(); drawChart();
}, 1000);

window.addEventListener('resize', drawChart);
load(); renderAll(); drawChart();
$('#clock').textContent = nowTime() + ' UTC';
startTraffic(); // generator traffic jalan otomatis seperti di referensi
