const urlInput   = document.getElementById('urlInput');
const scanBtn    = document.getElementById('scanBtn');
const btnText    = document.getElementById('btnText');
const radarSweep = document.getElementById('radarSweep');
const radarLabel = document.getElementById('radarLabel');
const radarVal   = document.getElementById('radarVal');
const radarDot   = document.getElementById('radarDot');
const logOut     = document.getElementById('log-output');
const resultsEl  = document.getElementById('results');
const emptyState = document.getElementById('emptyState');
const quickStats = document.getElementById('quickStats');
const leftFooter = document.getElementById('leftFooter');

/* Escapa cualquier valor antes de insertarlo como HTML. Todo dato que venga de
   VirusTotal/urlscan.io/AbuseIPDB/WHOIS (o de la URL/IP que el usuario tipeó)
   se trata como no confiable porque el atacante dueño del sitio/IP lo controla
   (ej. el <title> de su página, el header Server, el nombre del ISP/registrar). */
function esc(val) {
  const s = String(val ?? '');
  return s.replace(/[&<>"']/g, ch => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[ch]));
}

urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });

/* Los manejadores de click se conectan aquí (en vez de onclick="" inline en el
   HTML) porque la Content-Security-Policy del servidor usa script-src 'self'
   sin 'unsafe-inline', que bloquea cualquier atributo onclick/onerror inline. */
document.getElementById('settingsGearBtn').addEventListener('click', openSettings);
document.getElementById('settingsOverlay').addEventListener('click', closeOnBg);
document.getElementById('settingsCloseBtn').addEventListener('click', closeSettings);
document.getElementById('settingsCancelBtn').addEventListener('click', closeSettings);
document.getElementById('settingsSaveBtn').addEventListener('click', saveKeys);
document.getElementById('tab-url').addEventListener('click', () => setMode('url'));
document.getElementById('tab-ip').addEventListener('click', () => setMode('ip'));
document.getElementById('scanBtn').addEventListener('click', startScan);
document.getElementById('scanIpBtn').addEventListener('click', startIpScan);

/* ── Settings ── */
async function openSettings() {
  document.getElementById('settingsOverlay').classList.add('open');
  // Load current key status
  try {
    const res = await fetch('/api/keys');
    const data = await res.json();
    document.getElementById('st-vt').textContent = data.virustotal ? '● CONFIGURADA' : '';
    document.getElementById('st-us').textContent = data.urlscan    ? '● CONFIGURADA' : '';
    document.getElementById('st-ab').textContent = data.abuseipdb  ? '● CONFIGURADA' : '';
  } catch {}
}

function closeSettings() {
  document.getElementById('settingsOverlay').classList.remove('open');
  document.getElementById('settingsMsg').style.display = 'none';
  ['k-vt','k-us','k-ab'].forEach(id => document.getElementById(id).value = '');
}

function closeOnBg(e) {
  if (e.target === document.getElementById('settingsOverlay')) closeSettings();
}

async function saveKeys() {
  const msg = document.getElementById('settingsMsg');
  const body = {
    virustotal: document.getElementById('k-vt').value.trim(),
    urlscan:    document.getElementById('k-us').value.trim(),
    abuseipdb:  document.getElementById('k-ab').value.trim(),
  };
  if (!Object.values(body).some(v => v)) {
    msg.style.display = 'block';
    msg.style.color = 'var(--orange)';
    msg.textContent = '// Ingresa al menos una API key';
    return;
  }
  try {
    const res = await fetch('/api/keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (res.ok) {
      msg.style.display = 'block';
      msg.style.color = 'var(--neon)';
      msg.textContent = '✓ Keys guardadas correctamente';
      setTimeout(closeSettings, 1200);
    }
  } catch {
    msg.style.display = 'block';
    msg.style.color = 'var(--red)';
    msg.textContent = '// Error al guardar';
  }
}

document.addEventListener('keydown', e => { if (e.key === 'Escape') closeSettings(); });

/* ── Mode switcher ── */
function setMode(mode) {
  document.getElementById('tab-url').classList.toggle('active', mode === 'url');
  document.getElementById('tab-ip').classList.toggle('active', mode === 'ip');
  document.getElementById('mode-url').style.display = mode === 'url' ? 'block' : 'none';
  document.getElementById('mode-ip').style.display = mode === 'ip' ? 'block' : 'none';
}

document.getElementById('ipTextarea')?.addEventListener('input', function() {
  const ips = this.value.split('\n').map(s=>s.trim()).filter(Boolean);
  document.getElementById('ipCount').textContent = `${ips.length} IP${ips.length !== 1 ? 's' : ''}`;
});

async function startIpScan() {
  const raw = document.getElementById('ipTextarea').value;
  const ips = raw.split('\n').map(s => s.trim()).filter(Boolean);
  if (!ips.length) return;

  const btn = document.getElementById('scanIpBtn');
  const btnTxt = document.getElementById('btnIpText');
  btn.disabled = true;
  btnTxt.textContent = '[ SCANNING... ]';
  emptyState.style.display = 'none';
  resultsEl.style.display = 'none';
  resultsEl.innerHTML = '';
  logOut.style.display = 'block';
  logOut.innerHTML = '';
  sources.forEach(s => { document.getElementById(s).className = 'src-pill'; });
  radarSweep.classList.add('active');
  setRadar('SCANNING', `${ips.length} IPs`, 'var(--neon)');
  leftFooter.textContent = `SCANNING ${ips.length} IPs...`;

  log(`Consultando ${ips.length} IPs en paralelo...`);
  srcActive('src-ab');
  srcActive('src-geo');

  try {
    const res = await fetch('/api/scan-ips', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ips })
    });
    if (res.status === 429) {
      log('ERROR: Demasiadas solicitudes. Espera un momento antes de reintentar.');
      radarSweep.classList.remove('active');
      setRadar('LIMITADO', '!', 'var(--orange)');
      return;
    }
    const data = await res.json();
    log(`Análisis completado — ${data.results.length} resultados.`);
    renderIpResults(data.results);
  } catch(e) {
    log('ERROR: No se pudo conectar con el servidor.');
    radarSweep.classList.remove('active');
    setRadar('ERROR', '!', 'var(--red)');
  } finally {
    btn.disabled = false;
    btnTxt.textContent = '[ SCAN IPs ]';
  }
}

let ipScanRows = [];
let ipSortKey  = null;
let ipSortDir  = 1;

const ipSortGetters = {
  ip:            r => r.ip.split('.').map(n => n.padStart(3,'0')).join('.'),
  abuse_score:   r => r.abuse_score || 0,
  org:           r => (r.org || r.isp || '').toLowerCase(),
  location:      r => [r.city, r.country].filter(Boolean).join(', ').toLowerCase(),
  type:          r => (r.is_tor ? 'tor' : r.is_hosting ? 'hosting' : (r.usage_type || '')).toLowerCase(),
  total_reports: r => r.total_reports || 0,
  last_reported: r => r.last_reported || '',
};

const IP_TBL_COLS = [
  { label: '#',              key: null },
  { label: 'IP ADDRESS',     key: 'ip' },
  { label: 'ABUSE SCORE',    key: 'abuse_score' },
  { label: 'ORGANIZACIÓN',   key: 'org' },
  { label: 'UBICACIÓN',      key: 'location' },
  { label: 'TIPO',           key: 'type' },
  { label: 'REPORTES',       key: 'total_reports' },
  { label: 'ÚLTIMO REPORTE', key: 'last_reported' },
];

function sortIpRows(key) {
  if (ipSortKey === key) { ipSortDir *= -1; } else { ipSortKey = key; ipSortDir = 1; }
  renderIpTable();
}

function getSortedIpRows() {
  if (!ipSortKey) return ipScanRows;
  const get = ipSortGetters[ipSortKey];
  return [...ipScanRows].sort((a, b) => {
    const va = get(a), vb = get(b);
    if (va < vb) return -1 * ipSortDir;
    if (va > vb) return 1 * ipSortDir;
    return 0;
  });
}

function csvEscape(val) {
  let s = String(val ?? '');
  // Evita CSV/formula injection (=, +, -, @) si se abre en Excel/Sheets
  if (/^[=+\-@]/.test(s)) s = "'" + s;
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function exportIpCsv() {
  if (!ipScanRows.length) return;
  const header = ['IP', 'Abuse Score', 'Organizacion', 'Ubicacion', 'Tipo', 'Reportes', 'Ultimo Reporte'];
  const lines = [header.join(',')];
  getSortedIpRows().forEach(row => {
    const org = row.org || row.isp || '';
    const loc = [row.city, row.country].filter(Boolean).join(', ');
    const tip = row.is_tor ? 'TOR' : row.is_hosting ? 'HOSTING' : (row.usage_type || '');
    const lastRep = row.last_reported ? row.last_reported.split('T')[0] : '';
    lines.push([row.ip, `${row.abuse_score}%`, org, loc, tip, row.total_reports, lastRep].map(csvEscape).join(','));
  });
  const blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ip-scan-${new Date().toISOString().slice(0,19).replace(/[:T]/g,'-')}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function ipTableHeadHtml() {
  return IP_TBL_COLS.map(c => {
    if (!c.key) return `<th>${c.label}</th>`;
    const arrow = ipSortKey === c.key ? (ipSortDir === 1 ? ' ▲' : ' ▼') : '';
    return `<th class="sortable" data-sort-key="${c.key}">${c.label}${arrow}</th>`;
  }).join('');
}

function attachIpTableHeadListeners() {
  const head = document.getElementById('ipTableHead');
  if (!head) return;
  head.querySelectorAll('th.sortable').forEach(th => {
    th.addEventListener('click', () => sortIpRows(th.dataset.sortKey));
  });
}

function ipTableRowsHtml(rows) {
  return rows.map((row, i) => {
    const col = row.abuse_score > 50 ? 'var(--red)' : row.abuse_score > 20 ? 'var(--orange)' : 'var(--neon)';
    const barW = row.abuse_score;
    const org  = esc(row.org || row.isp || '—');
    const loc  = esc([row.city, row.country].filter(Boolean).join(', ') || '—');
    const tip  = row.is_tor ? '⚠️ TOR' : row.is_hosting ? 'HOSTING' : esc(row.usage_type || '—');
    const lastRep = row.last_reported ? esc(row.last_reported.split('T')[0]) : '—';
    const rowBg = row.abuse_score > 50 ? 'rgba(225,29,72,.05)' : row.abuse_score > 20 ? 'rgba(245,158,11,.04)' : '';
    return `<tr style="background:${rowBg}">
      <td style="color:var(--muted)">${i+1}</td>
      <td><span class="ip-addr">${esc(row.ip)}</span></td>
      <td>
        <span style="color:${col};font-weight:700;font-family:'Space Mono',monospace">${row.abuse_score}%</span>
        <div class="abuse-bar" style="margin-top:4px"><div class="abuse-fill" style="width:${barW}%;background:${col}"></div></div>
      </td>
      <td style="color:var(--muted2);font-size:.68rem">${org}</td>
      <td style="font-size:.68rem">${loc}</td>
      <td style="color:var(--muted2);font-size:.68rem">${tip}</td>
      <td style="font-family:'Space Mono',monospace;font-size:.68rem">${row.total_reports}</td>
      <td style="color:var(--muted2);font-family:'Space Mono',monospace;font-size:.65rem">${lastRep}</td>
    </tr>`;
  }).join('');
}

function renderIpTable() {
  const rows = getSortedIpRows();
  const head = document.getElementById('ipTableHead');
  const body = document.getElementById('ipTableBody');
  if (head) head.innerHTML = ipTableHeadHtml();
  if (body) body.innerHTML = ipTableRowsHtml(rows);
  attachIpTableHeadListeners();
}

function renderIpResults(rows) {
  ipScanRows = rows;
  ipSortKey  = null;
  ipSortDir  = 1;

  const malCount  = rows.filter(r => r.abuse_score > 50).length;
  const suspCount = rows.filter(r => r.abuse_score > 20 && r.abuse_score <= 50).length;

  radarSweep.classList.remove('active');
  const vColor = malCount ? 'var(--red)' : suspCount ? 'var(--orange)' : 'var(--neon)';
  setRadar(malCount ? 'THREAT' : suspCount ? 'CAUTION' : 'CLEAN', `${rows.length} IPs`, vColor);
  radarDot.style.display = 'block';
  radarDot.setAttribute('fill', vColor);
  srcResult('src-ab', malCount ? 'danger' : suspCount ? 'warning' : 'safe');
  srcResult('src-geo', 'safe');
  leftFooter.textContent = `LAST SCAN: ${new Date().toLocaleTimeString()}`;

  logOut.style.display = 'none';

  let html = `<div class="block">
    <div class="block-head">
      <span class="block-num">01</span>
      <span class="block-icon">🕵️</span>
      <span class="block-title col-${malCount ? 'red' : suspCount ? 'orange' : 'neon'}">REPUTACIÓN DE IPs</span>
      <span class="block-badge col-${malCount ? 'red' : suspCount ? 'orange' : 'neon'}">${malCount ? `${malCount} MALICIOSAS` : suspCount ? `${suspCount} SOSPECHOSAS` : 'TODAS LIMPIAS'}</span>
      <button class="btn-export" id="exportIpCsvBtn">⬇ EXPORTAR CSV</button>
    </div>
    <div style="overflow-x:auto">
    <table class="ip-tbl">
      <thead><tr id="ipTableHead">${ipTableHeadHtml()}</tr></thead>
      <tbody id="ipTableBody">${ipTableRowsHtml(rows)}</tbody>
    </table>
    </div>
  </div>`;
  html += `<div style="height:40px"></div>`;
  resultsEl.innerHTML = html;
  resultsEl.style.display = 'block';
  document.getElementById('exportIpCsvBtn').addEventListener('click', exportIpCsv);
  attachIpTableHeadListeners();
  document.getElementById('rightPanel').scrollTo({ top: 0 });
}

const sources = ['src-vt','src-us','src-ab','src-geo','src-wh'];

function setRadar(label, val, color) {
  radarLabel.textContent = label;
  radarVal.textContent = val;
  radarVal.style.color = color;
}

function srcActive(id) {
  document.getElementById(id).classList.add('active');
}
function srcResult(id, cls) {
  const el = document.getElementById(id);
  el.classList.remove('active');
  el.classList.add(cls);
}

function log(msg) {
  const line = document.createElement('div');
  line.className = 'log-line';
  line.textContent = msg;
  logOut.appendChild(line);
  logOut.scrollIntoView({ behavior: 'smooth', block: 'end' });
}

async function startScan() {
  const url = urlInput.value.trim();
  if (!url) return;

  // Reset UI
  scanBtn.disabled = true;
  btnText.textContent = '[ SCANNING... ]';
  emptyState.style.display = 'none';
  resultsEl.style.display = 'none';
  resultsEl.innerHTML = '';
  logOut.style.display = 'block';
  logOut.innerHTML = '';
  quickStats.style.display = 'none';
  sources.forEach(s => {
    const el = document.getElementById(s);
    el.className = 'src-pill';
  });
  radarDot.style.display = 'none';

  radarSweep.classList.add('active');
  setRadar('SCANNING', '...', 'var(--neon)');
  leftFooter.textContent = 'SCANNING TARGET...';

  log(`Iniciando análisis de ${url}`);
  log('Consultando VirusTotal...');
  srcActive('src-vt');

  setTimeout(() => { log('Consultando URLscan.io...'); srcActive('src-us'); }, 800);
  setTimeout(() => { log('Consultando AbuseIPDB...'); srcActive('src-ab'); }, 1400);
  setTimeout(() => { log('Resolviendo GeoIP...'); srcActive('src-geo'); }, 1900);
  setTimeout(() => { log('Consultando WHOIS/RDAP...'); srcActive('src-wh'); }, 2400);

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    if (res.status === 429) {
      log('ERROR: Demasiadas solicitudes. Espera un momento antes de reintentar.');
      radarSweep.classList.remove('active');
      setRadar('LIMITADO', '!', 'var(--orange)');
      return;
    }
    const data = await res.json();
    log('Análisis completado.');
    renderResults(data);
  } catch (e) {
    log('ERROR: No se pudo conectar con el servidor.');
    radarSweep.classList.remove('active');
    setRadar('ERROR', '!', 'var(--red)');
  } finally {
    scanBtn.disabled = false;
    btnText.textContent = '[ SCAN TARGET ]';
  }
}

/* ── Render ── */
function renderResults(d) {
  const vt     = d.virustotal || {};
  const abuse  = d.abuseipdb  || {};
  const us     = d.urlscan    || {};
  const geo    = d.geo        || {};
  const whois  = d.whois      || {};
  const cias   = d.contacted_ips_analysis || [];

  const vtMal  = vt.malicious   || 0;
  const vtSusp = vt.suspicious  || 0;
  const vtHarm = vt.harmless    || 0;
  const vtUnd  = vt.undetected  || 0;
  const vtTotal= vtMal + vtSusp + vtHarm + vtUnd;
  const aScore = abuse.abuse_score || 0;
  const usScore= us.score || 0;
  const usMal  = us.malicious;

  // Verdict
  let vLabel, vVal, vColor;
  if (vtMal > 2 || aScore > 50 || usMal) {
    vLabel = 'THREAT'; vVal = 'MALICIOUS'; vColor = 'var(--red)';
  } else if (vtMal > 0 || vtSusp > 0 || aScore > 20 || usScore > 20) {
    vLabel = 'CAUTION'; vVal = 'SUSPICIOUS'; vColor = 'var(--orange)';
  } else {
    vLabel = 'STATUS'; vVal = 'CLEAN'; vColor = 'var(--neon)';
  }

  radarSweep.classList.remove('active');
  setRadar(vLabel, vVal, vColor);
  radarDot.style.display = 'block';
  radarDot.setAttribute('fill', vColor);

  // Source status pills
  srcResult('src-vt', vtMal > 0 ? 'danger' : 'safe');
  srcResult('src-us', usMal || usScore > 20 ? 'danger' : 'safe');
  srcResult('src-ab', aScore > 50 ? 'danger' : aScore > 20 ? 'warning' : 'safe');
  srcResult('src-geo', 'safe');
  srcResult('src-wh', 'safe');

  // Quick stats
  document.getElementById('qs-vt').textContent = `${vtMal}/${vtTotal}`;
  document.getElementById('qs-vt').style.color = vtMal > 0 ? 'var(--red)' : 'var(--neon)';
  document.getElementById('qs-ab').textContent = `${aScore}%`;
  document.getElementById('qs-ab').style.color = aScore > 50 ? 'var(--red)' : aScore > 20 ? 'var(--orange)' : 'var(--neon)';
  document.getElementById('qs-us').textContent = `${usScore}`;
  document.getElementById('qs-us').style.color = usMal ? 'var(--red)' : 'var(--blue)';
  document.getElementById('qs-ips').textContent = cias.length || (us.ips_contacted||[]).length;
  quickStats.style.display = 'grid';
  leftFooter.textContent = `LAST SCAN: ${new Date().toLocaleTimeString()}`;

  logOut.style.display = 'none';

  function scoreCol(s) { return s > 50 ? 'var(--red)' : s > 20 ? 'var(--orange)' : 'var(--neon)'; }
  function bar(pct, col) { return `<div class="vt-bar-track"><div class="vt-bar-fill" style="width:${pct}%;background:${col}"></div></div>`; }
  function logRow(key, val, cls='') {
    return `<div class="log-row"><span class="log-key">${key}</span><span class="log-sep"> </span><span class="log-val ${cls}">${val}</span></div>`;
  }
  function block(num, icon, title, badgeText, badgeCol, body) {
    return `<div class="block">
      <div class="block-head">
        <span class="block-num">${String(num).padStart(2,'0')}</span>
        <span class="block-icon">${icon}</span>
        <span class="block-title col-${badgeCol}">${title}</span>
        <span class="block-badge col-${badgeCol}">${badgeText}</span>
      </div>
      <div class="block-body">${body}</div>
    </div>`;
  }
  function ring(val, max, col, title, sub) {
    const r = 21, c = 2*Math.PI*r, dash = Math.min(val/max,1)*c;
    return `<div class="ring-row">
      <div class="ring-mini">
        <svg width="52" height="52" viewBox="0 0 52 52">
          <circle cx="26" cy="26" r="${r}" fill="none" stroke="#112240" stroke-width="5"/>
          <circle cx="26" cy="26" r="${r}" fill="none" stroke="${col}" stroke-width="5"
            stroke-dasharray="${dash} ${c}" stroke-linecap="round"/>
        </svg>
        <div class="ring-mini-num" style="color:${col}">${val}</div>
      </div>
      <div class="ring-info">
        <div class="ring-title">${title}</div>
        <div class="ring-sub" style="color:${col}">${sub}</div>
      </div>
    </div>`;
  }

  let html = '';

  /* 01 — VirusTotal */
  let vtBody = '';
  if (vt.error) {
    vtBody = `<p class="err-txt">${esc(vt.error)}</p>`;
  } else {
    vtBody += `<div class="vt-section">
      <div class="vt-counter">
        <div class="vt-counter-num" style="color:var(--red)">${vtMal}</div>
        <div class="vt-counter-label">Maliciosos</div>
      </div>
      <div class="vt-counter">
        <div class="vt-counter-num" style="color:var(--orange)">${vtSusp}</div>
        <div class="vt-counter-label">Sospechosos</div>
      </div>
    </div>`;
    const p = n => vtTotal > 0 ? (n/vtTotal*100).toFixed(0) : 0;
    vtBody += `<div class="vt-bar-wrap">
      ${['Malicioso','Sospechoso','Inofensivo','Sin detec.'].map((l,i) => {
        const vals=[vtMal,vtSusp,vtHarm,vtUnd], cols=['var(--red)','var(--orange)','var(--neon)','var(--muted)'];
        return `<div class="vt-bar-row">
          <span class="vt-bar-lbl">${l}</span>
          ${bar(p(vals[i]), cols[i])}
          <span class="vt-bar-n" style="color:${cols[i]}">${vals[i]}</span>
        </div>`;
      }).join('')}
    </div>`;
    if (vt.categories?.length) vtBody += logRow('categorias', esc(vt.categories.join(', ')), 'v-blue');
    if (vt.tags?.length) vtBody += `<div class="log-row"><span class="log-key">tags</span><span class="log-sep"> </span><span class="log-val"><div class="t-wrap">${vt.tags.map(t=>`<span class="t t-blue">${esc(t)}</span>`).join('')}</div></span></div>`;
    if (vt.redirection) vtBody += logRow('redireccion', esc(vt.redirection), 'v-orange');
  }
  const vtBadge = vtMal > 2 ? `${vtMal} DETECCIONES` : vtMal > 0 ? `${vtMal} DETECCIÓN` : 'LIMPIO';
  const vtCol   = vtMal > 2 ? 'red' : vtMal > 0 ? 'orange' : 'neon';
  html += block(1,'🛡','VIRUSTOTAL', vtBadge, vtCol, vtBody);

  /* 02 — URLscan */
  let usBody = '';
  if (us.error && !us.report_url) {
    usBody = `<p class="err-txt">${esc(us.error)}</p>`;
  } else {
    usBody += ring(usScore, 100, scoreCol(usScore), 'THREAT SCORE', usMal ? 'MALICIOSO' : usScore > 20 ? 'SOSPECHOSO' : 'LIMPIO');
    if (us.page_title)    usBody += logRow('page_title', esc(us.page_title));
    if (us.brands?.length) usBody += logRow('brand_target', `🎯 ${esc(us.brands.join(', '))}`, 'v-red');
    if (us.categories?.length) usBody += logRow('categories', esc(us.categories.join(', ')), 'v-yellow');
    if (us.server)        usBody += logRow('server', esc(us.server), 'v-muted');
    if (us.total_requests) usBody += logRow('http_requests', us.total_requests);
    if (us.report_url)    usBody += logRow('report', `<a href="${esc(us.report_url)}" target="_blank" rel="noopener noreferrer">${esc(us.report_url)}</a>`);
  }
  const usBadge = usMal ? 'MALICIOSO' : usScore > 20 ? 'SOSPECHOSO' : 'OK';
  const usCol   = usMal ? 'red' : usScore > 20 ? 'orange' : 'neon';
  html += block(2,'📡','URLSCAN.IO', usBadge, usCol, usBody);

  /* 03 — Motores */
  if (vt.detections?.length) {
    let detBody = `<div class="det-list">`;
    vt.detections.forEach(det => {
      const isMal = det.category === 'malicious';
      detBody += `<div class="det-row ${isMal ? 'mal' : 'susp'}">
        <span class="det-engine col-muted">${esc(det.engine)}</span>
        <span class="det-result" style="color:${isMal ? 'var(--red)' : 'var(--orange)'}">${esc(det.result || det.category)}</span>
      </div>`;
    });
    detBody += `</div>`;
    html += block(3,'☣','MOTORES POSITIVOS', `${vt.detections.length} ENGINES`, 'red', detBody);
  }

  /* 04 — Infraestructura */
  let infraBody = '';
  // GeoIP
  infraBody += `<div style="margin-bottom:14px;padding-bottom:14px;border-bottom:1px solid var(--border)">`;
  infraBody += logRow('ip_address', `<span style="color:var(--blue)">${esc(d.ip || 'N/A')}</span>`);
  if (geo.country) infraBody += logRow('country', esc(geo.country));
  if (geo.is_hosting != null) infraBody += logRow('hosting_vps', geo.is_hosting ? 'YES ⚠️' : 'NO', geo.is_hosting ? 'v-orange' : 'v-neon');
  infraBody += `</div>`;
  // AbuseIPDB
  infraBody += ring(aScore, 100, scoreCol(aScore), 'ABUSEIPDB · ABUSE SCORE', `${abuse.total_reports||0} reportes en 90 días`);
  if (!abuse.error) {
    if (abuse.isp)         infraBody += logRow('isp', esc(abuse.isp), 'v-muted');
    if (abuse.usage_type)  infraBody += logRow('usage_type', esc(abuse.usage_type), 'v-muted');
    if (abuse.distinct_users != null) infraBody += logRow('distinct_users', abuse.distinct_users);
    infraBody += logRow('tor_node', abuse.is_tor ? 'YES ⚠️' : 'NO', abuse.is_tor ? 'v-red' : 'v-neon');
    if (abuse.last_reported) infraBody += logRow('last_report', esc(abuse.last_reported.split('T')[0]), 'v-muted');
  }
  html += block(4,'🌐','INFRAESTRUCTURA', esc(d.ip || 'N/A'), 'blue', infraBody);

  /* 05 — WHOIS */
  let whoBody = '';
  if (!whois.registered && !whois.registrar) {
    whoBody = `<p class="err-txt" style="color:var(--muted2)">// DATOS NO DISPONIBLES PARA ESTE DOMINIO</p>`;
  } else {
    if (whois.registrar)    whoBody += logRow('registrar', esc(whois.registrar));
    if (whois.registered)   whoBody += logRow('registered', esc(whois.registered.split('T')[0]));
    if (whois.expires)      whoBody += logRow('expires', esc(whois.expires.split('T')[0]), 'v-yellow');
    if (whois.last_changed) whoBody += logRow('last_changed', esc(whois.last_changed.split('T')[0]), 'v-muted');
    if (whois.nameservers?.length) whoBody += logRow('nameservers', esc(whois.nameservers.join(' | ')), 'v-muted');
    if (whois.status?.length) whoBody += `<div class="log-row"><span class="log-key">status</span><span class="log-sep"> </span><span class="log-val"><div class="t-wrap">${whois.status.map(s=>`<span class="t">${esc(s)}</span>`).join('')}</div></span></div>`;
  }
  html += block(5,'📋','WHOIS / DOMAIN', esc(d.hostname || '—'), 'purple', whoBody);

  /* 06 — Red y tecnologías */
  const hasTech   = us.technologies?.length;
  const hasDomains= us.domains_contacted?.length;
  if (hasTech || hasDomains) {
    let netBody = '';
    if (hasTech) {
      netBody += `<div class="log-row" style="flex-direction:column;gap:6px;align-items:flex-start">
        <span class="log-key">technologies</span>
        <div class="t-wrap">${us.technologies.map(t=>`<span class="t t-blue">${esc(t)}</span>`).join('')}</div>
      </div>`;
    }
    if (us.countries_contacted?.length) netBody += logRow('countries', esc(us.countries_contacted.join(', ')), 'v-blue');
    if (hasDomains) {
      netBody += `<div class="log-row" style="flex-direction:column;gap:6px;align-items:flex-start">
        <span class="log-key">domains_contacted</span>
        <div class="t-wrap">${us.domains_contacted.map(dom=>`<span class="t">${esc(dom)}</span>`).join('')}</div>
      </div>`;
    }
    html += block(6,'🔗','RED Y TECNOLOGÍAS', `${(us.domains_contacted||[]).length} DOMINIOS`, 'blue', netBody);
  }

  /* 07 — IPs contactadas (renumbered from 07) */
  if (cias.length) {
    const malCount  = cias.filter(x => x.abuse_score > 50).length;
    const suspCount = cias.filter(x => x.abuse_score > 20 && x.abuse_score <= 50).length;
    let ipBody = `<div style="overflow-x:auto"><table class="ip-tbl">
      <thead><tr>
        <th>IP ADDRESS</th><th>ABUSE</th><th>ORGANIZATION</th>
        <th>LOCATION</th><th>TYPE</th><th>REPORTS</th>
      </tr></thead><tbody>`;
    cias.forEach(row => {
      const col = row.abuse_score > 50 ? 'var(--red)' : row.abuse_score > 20 ? 'var(--orange)' : 'var(--neon)';
      const org = esc(row.org || row.isp || '—');
      const loc = esc([row.city, row.country].filter(Boolean).join(', ') || '—');
      const tip = row.is_tor ? '⚠️ TOR' : row.is_hosting ? 'HOSTING' : esc(row.usage_type || '—');
      ipBody += `<tr>
        <td><span class="ip-addr">${esc(row.ip)}</span></td>
        <td>
          <span style="color:${col};font-weight:700">${row.abuse_score}%</span>
          <div class="abuse-bar"><div class="abuse-fill" style="width:${row.abuse_score}%;background:${col}"></div></div>
        </td>
        <td style="color:var(--muted2)">${org}</td>
        <td>${loc}</td>
        <td style="color:var(--muted2)">${tip}</td>
        <td>${row.total_reports}</td>
      </tr>`;
    });
    ipBody += `</tbody></table></div>`;
    const ipBadge = malCount ? `${malCount} MALICIOSAS` : suspCount ? `${suspCount} SOSPECHOSAS` : 'ALL CLEAN';
    const ipCol   = malCount ? 'red' : suspCount ? 'orange' : 'neon';
    html += block(7,'🕵','REPUTACIÓN IPs CONTACTADAS', ipBadge, ipCol, ipBody);
  }

  /* 08 — Screenshot (solo si URLscan encontró una página web real) */
  const isWebPage = us.page_title || (us.mime_type && us.mime_type.includes('html'));
  if (us.screenshot && isWebPage) {
    html += block(8,'📸','SCREENSHOT', 'URLSCAN.IO', 'muted',
      `<img class="ss-img" id="screenshotImg" src="${esc(us.screenshot)}" alt="screenshot"/>`);
  }

  resultsEl.innerHTML = html;
  resultsEl.style.display = 'block';
  const ssImg = document.getElementById('screenshotImg');
  if (ssImg) ssImg.addEventListener('error', () => { ssImg.closest('.block').style.display = 'none'; });
  document.getElementById('rightPanel').scrollTo({ top: 0 });
}
