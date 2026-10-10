const $ = id => document.getElementById(id);
const fmt = n => { n = Number(n || 0); for (const u of ['B','KB','MB','GB','TB']) { if(n < 1024 || u === 'TB') return `${n.toFixed(1)} ${u}`; n /= 1024; } };
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path) {
  const r = await fetch(path, {cache:'no-store'});
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
}
function setMeter(id, pct) { $(id).style.width = `${Math.max(0,Math.min(100,pct||0))}%`; }
function setNotice(msg) { $('notice').textContent = msg; }
async function loadSystem() {
  const s = await api('/api/system');
  $('cpu').textContent = `${s.cpu_percent.toFixed(0)}%`;
  $('ram').textContent = `${s.ram_percent.toFixed(0)}%`;
  $('disk').textContent = `${s.disk_percent.toFixed(0)}%`;
  setMeter('cpuBar',s.cpu_percent); setMeter('ramBar',s.ram_percent); setMeter('diskBar',s.disk_percent);
  $('ramMeta').textContent = `${s.ram_used_label} of ${s.ram_total_label}`;
  $('diskMeta').textContent = `${s.disk_free_label} free · home filesystem`;
  $('cpuMeta').textContent = `${s.cpu_count ?? '?'} logical CPU threads`;
  const fields = [
    ['HOSTNAME',s.hostname],['OPERATING SYSTEM',s.platform],['KERNEL RELEASE',s.release],
    ['ARCHITECTURE',s.architecture],['CPU THREADS',s.cpu_count],['RAM AVAILABLE',fmt(s.ram_available)],
    ['DISK TOTAL',s.disk_total_label],['BOOT TIME (UTC)',s.boot_time || 'Unavailable']
  ];
  $('systemInfo').innerHTML = fields.map(([k,v])=>`<div class="info"><label>${esc(k)}</label><strong>${esc(v ?? 'Unavailable')}</strong></div>`).join('');
}
async function loadProcesses() {
  $('processRows').innerHTML='<tr><td colspan="4">Sampling processes…</td></tr>';
  const data = await api('/api/processes');
  $('procCount').textContent = data.processes.length;
  $('processRows').innerHTML = data.processes.slice(0,15).map(p=>`<tr><td title="${esc(p.exe)}">${esc(p.name)}</td><td>${p.pid}</td><td>${Number(p.cpu_percent).toFixed(1)}%</td><td>${esc(p.memory)}</td></tr>`).join('') || '<tr><td colspan="4">No visible processes.</td></tr>';
}
async function loadStorage() {
  $('storageSummary').textContent='Scanning a bounded set of files in your home directory…';
  $('storageRows').innerHTML='';
  const d = await api('/api/storage');
  $('storageSummary').textContent=`${d.files_scanned} files checked · ${d.candidates.length} review candidates${d.truncated?' · scan limit reached':''}`;
  $('storageRows').innerHTML = d.candidates.map(f=>`<div class="file-item"><strong>${esc(f.name)}</strong><p>${esc(f.path)}</p><div class="file-meta">${esc(f.size_label)} · ${f.age_days} days since modification</div><p>${esc(f.reason)}</p></div>`).join('') || '<p class="muted small">No candidates found in the scanned files.</p>';
}
async function loadNetwork() {
  const b=$('networkBtn'); b.disabled=true; b.textContent='Observing…';
  $('networkSummary').textContent='Sampling visible local sockets for up to 5 seconds…';
  $('networkRows').innerHTML='<tr><td colspan="5">Collecting observations…</td></tr>';
  try {
    const d=await api('/api/network?seconds=5');
    $('networkSummary').textContent=`${d.unique_socket_observations} unique socket observations · ${d.duration_seconds}s · ${d.permission_errors} permission-limited sample(s). ${d.limitations}`;
    $('networkRows').innerHTML=d.connections.map(c=>`<tr><td>${esc(c.type)} / ${esc(c.family)}</td><td>${esc(c.local)}</td><td>${esc(c.remote)}</td><td>${esc(c.status)}${c.review_notes.length?' · REVIEW':''}</td><td>${esc(c.pid ?? '—')}</td></tr>`).join('') || '<tr><td colspan="5">No sockets visible during this sample.</td></tr>';
  } catch(e) { $('networkSummary').textContent=`Network observation failed: ${e.message}`; }
  finally { b.disabled=false; b.textContent='Observe for 5 seconds'; }
}
async function refreshAll() {
  setNotice('Refreshing local system information…');
  try {
    await Promise.all([loadSystem(),loadProcesses(),loadStorage()]);
    setNotice('Overview updated locally. Findings are indicators for review, not confirmed security verdicts.');
  } catch(e) { setNotice(`Backend error: ${e.message}. Check the terminal running Sentinel Local.`); }
}
function tick(){ $('clock').textContent=new Date().toLocaleTimeString(); }
tick(); setInterval(tick,1000); refreshAll();
