const $=id=>document.getElementById(id);
let lastReport=null, hs='';
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=n=>{n=Number(n||0);for(const u of ['B','KB','MB','GB','TB']){if(n<1024||u==='TB')return `${n.toFixed(1)} ${u}`;n/=1024}};
async function api(url,opts={}){const r=await fetch(url,{cache:'no-store',...opts});if(!r.ok)throw Error(`${r.status} ${r.statusText}: ${(await r.text()).slice(0,250)}`);return r.json()}
function notice(s){$('notice').textContent=s}
function meter(id,v){$(id).style.width=`${Math.max(0,Math.min(100,v||0))}%`}
async function runScan(){
 const b=$('scanBtn');b.disabled=true;b.textContent='Scanning…';notice('Collecting a manual snapshot. This may take a little while.');
 $('findings').innerHTML='<p class="muted">Collecting evidence…</p>';
 try{
  const r=await api('/api/scan',{method:'POST'});lastReport=r;
  const s=r.system;
  $('cpu').textContent=`${s.cpu_percent.toFixed(0)}%`;$('ram').textContent=`${s.ram_percent.toFixed(0)}%`;$('disk').textContent=`${s.disk_percent.toFixed(0)}%`;
  meter('cpuBar',s.cpu_percent);meter('ramBar',s.ram_percent);meter('diskBar',s.disk_percent);
  $('ramMeta').textContent=`${fmt(s.ram_used)} / ${fmt(s.ram_total)}`;$('diskMeta').textContent=`${fmt(s.disk_free)} free`;
  $('findingCount').textContent=r.findings.length;
  $('systemInfo').innerHTML=[['HOST',s.hostname],['OS',s.platform],['ARCHITECTURE',s.architecture],['CPU THREADS',s.cpu_count],['RAM',fmt(s.ram_total)],['DISK',fmt(s.disk_total)],['BASELINE',r.baseline_existed?'Previous scan available':'First scan: baseline established'],['SCOPE',s.scope]].map(([k,v])=>`<div class="info"><label>${esc(k)}</label><strong>${esc(v)}</strong></div>`).join('');
  $('counts').innerHTML=Object.entries(r.counts).map(([k,v])=>`<span class="count ${k}">${esc(k)} <b>${v}</b></span>`).join('');
  renderFindings();
  $('networkNote').textContent=`${r.network.connections.length} visible connections. ${r.network.permission_errors} permission-limited sample(s). ${r.network.limitations.join(' ')}`;
  $('networkRows').innerHTML=r.network.connections.slice(0,100).map(c=>`<tr><td>${esc(c.protocol)}</td><td>${esc(c.local)}</td><td>${esc(c.remote)}</td><td>${esc(c.state)}</td><td>${esc(c.pid??'—')}</td></tr>`).join('')||'<tr><td colspan="5">No visible sockets</td></tr>';
  $('dns').textContent=r.network.dns_resolver_config||'Unavailable';
  $('arp').innerHTML=r.network.arp.map(a=>`<div class="file-item">${esc(a.ip)} · ${esc(a.mac)} · ${esc(a.interface)}</div>`).join('')||'No entries visible';
  $('wifi').textContent=r.network.wifi_entries.join('\n')||'Unavailable or not exposed to this Linux environment.';
   $('storageNote').textContent=`${r.storage.files_scanned} files checked; ${r.storage.total_candidate_count} review candidates. ${r.storage.truncated?'Scan limit reached. ':''}No files are deleted.`;
   const largest=(r.storage.largest_files||[]).map(f=>`<div class="file-item"><strong>${esc(f.name)} · ${esc(f.size_label)}</strong><p>${esc(f.path)}</p><p>${f.age_days} days since modification · ${esc(f.extension||'(none)')} · ${f.executable?'executable':'not executable'}</p><small>${esc(f.recommendation||'Review before removing; size alone is not suspicious.')}</small></div>`).join('')||'<p class="muted">No file metadata available.</p>';
   const candidates=(r.storage.candidates||[]).slice(0,40).map(f=>`<div class="file-item"><strong>${esc(f.name)} · ${esc(f.size_label)} · review score ${f.score}</strong><p>${esc(f.path)}</p><p>${esc((f.signals||[]).join(' · '))}</p><small>${esc(f.recommendation||'Review before removing.')}</small></div>`).join('')||'<p class="muted">No review candidates found in the scanned subset.</p>';
   $('files').innerHTML='<h3>Largest files (top 25)</h3>'+largest+'<h3>Files worth reviewing</h3>'+candidates;
  $('processRows').innerHTML=r.processes.slice(0,30).map(p=>`<tr><td>${esc(p.name)}</td><td>${p.pid}</td><td>${esc(p.parent_name||'—')}</td><td>${p.cpu}%</td><td>${esc(p.memory)}</td><td title="${esc(p.exe)}">${esc(p.exe||'Unavailable')}</td></tr>`).join('')||'<tr><td colspan="6">No visible processes</td></tr>';
  notice(`Assessment complete at ${new Date().toLocaleTimeString()}. Findings are leads for human review, not confirmed infections; they were also queued for Sentinel triage (panel 06).`);
 }catch(e){notice(`Scan failed: ${e.message}`)}
 finally{b.disabled=false;b.textContent='▶ Run security assessment'}
}
function renderFindings(){
 if(!lastReport)return;
 const filter=$('filter').value;
 const list=lastReport.findings.filter(f=>filter==='All'||f.category===filter);
 $('findings').innerHTML=list.map(f=>`<article class="finding ${esc(f.severity)}"><div class="finding-top"><span class="tag">${esc(f.category)}</span><span class="severity ${esc(f.severity)}">${esc(f.severity)}</span></div><h3>${esc(f.title)}</h3><p><b>Evidence</b> · ${esc(f.evidence)}</p><p><b>Recommended action</b> · ${esc(f.recommendation)}</p><small>Rule confidence: ${esc(f.confidence)} · ID ${esc(f.id)}</small></article>`).join('')||'<p class="muted">No findings in this category for this snapshot. This does not prove the system is clean.</p>';
}
const post=(u,b)=>api(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});
const sevCls=s=>['critical','high','medium'].includes(s)?s:'info';
const human=s=>String(s||'').replace(/_/g,' ');
async function poll(){
 try{const s=await api('/api/harness/state'),k=JSON.stringify(s);if(k!==hs){hs=k;renderHarness(s)}}
 catch(e){$('modelState').textContent='TRIAGE UNREACHABLE';$('modelDot').className='dot off'}
}
function renderHarness(s){
 const m=s.model,st=s.stats,ev=s.events[0];
 $('aaState').textContent=`ALWAYS-ACTIVE ${s.always_active?'ON':'OFF'}`;$('aaDot').className=`dot${s.always_active?'':' idle'}`;
 $('modelState').textContent=m.online?'MODEL ONLINE':m.state==='checking'?'MODEL …':'MODEL OFFLINE';$('modelDot').className=`dot${m.online?'':m.state==='checking'?' idle':' off'}`;
 $('modelLabel').textContent=`Model: ${m.name}${m.online?'':` · offline: ${m.message} Running on prefilter rules; findings stay queued.`}${s.escalation_model?` · Escalation: ${s.escalation_model}`:''}`;
 $('demoBtn').hidden=!s.demo_mode;$('undoIso').hidden=!s.isolated;
 $('harnessNote').textContent=`${s.demo_mode?'DEMO MODE: actions are dry runs. ':''}${s.judging?`Judging ${s.judging}. `:''}Queue ${s.queue} · cleared by model ${st.cleared||0} · skipped as normal ${st.skipped||0}${ev?` · ${ev.ts} ${ev.msg}`:''}`;
 $('aiResult').innerHTML=s.cards.map(card).join('')||'<p class="muted">Nothing needs your attention right now.</p>';
}
function card(c){
 const j=c.judgement,x=c.escalation,sev=c.severity||'none',id=esc(c.id);
 const title=j?(j.threat_type==='none'?'Looks normal':human(j.threat_type)):c.rule?c.rule.title:human(c.label||c.source);
 const evidence=j?j.evidence:c.rule?[c.rule.evidence]:[];
 const tag=`${c.source}${c.origin==='demo'?' · demo replay':''}${c.status==='provisional'?' · model offline':''}${x&&x.status==='pending'?' · escalating':''}`;
 const xs=!x?'':x.status==='pending'?`<p><b>Escalated</b> · ${esc(x.reason)}. Asking for a second opinion…</p>`:x.status==='done'?`<p><b>Second opinion (${esc(x.model)})</b> · ${esc(x.summary)} ${esc(x.guidance)}</p>${(x.steps||[]).map(t=>`<p><b>${esc(t.label)}</b> (read-only, ran automatically) · ${esc(t.result)}</p>`).join('')}`:`<p><b>Escalation</b> · ${esc(x.message)}</p>`;
 const acts=c.actions.map(a=>{const live=a.available&&['proposed','declined','failed'].includes(a.state);return `<button class="${live?'primary':'ghost'}" ${live?'':'disabled'} title="${esc(a.reason||a.detail)}" onclick="approve('${id}','${esc(a.name)}',${!!a.confirm})">${live?'Approve: ':''}${esc(a.label)}${a.admin?` · ${esc(a.admin)}`:''}${a.state==='running'?' …':''}</button>`}).join('');
 const results=c.actions.filter(a=>a.message||!a.available).map(a=>`<p><b>${esc(a.label)}</b> · ${esc(a.message||a.reason)}</p>`).join('');
 return `<article class="finding ${sevCls(sev)}"><div class="finding-top"><span class="tag">${esc(tag)}</span><span class="severity ${sevCls(sev)}">${esc(sev)}</span></div><h3>${esc(title)}</h3>${evidence.length?`<p><b>Evidence</b> · ${esc(evidence.join(' · '))}</p>`:''}${j?`<p><b>What it means</b> · ${esc(j.explanation)}</p>`:''}${!j&&c.flags.length?`<p><b>Rule flags</b> · ${esc(c.flags.join(' · '))}</p>`:''}${!j&&c.rule?`<p><b>Recommended action</b> · ${esc(c.rule.recommendation)}</p>`:''}${xs}${c.notes.map(n=>`<p class="muted">${esc(n)}</p>`).join('')}${results}<div class="card-actions">${acts}<button class="ghost" onclick="ignoreCard('${id}')">${c.status==='acted'?'Dismiss':'Ignore'}</button></div><small>${j?`Model confidence: ${esc(j.confidence)} · `:''}${c.label?`Labeled: ${esc(c.label)} · `:''}ID ${esc(c.finding_id)}</small></article>`;
}
async function approve(id,action,confirmFirst){
 if(confirmFirst&&!confirm('Restoring a backup overwrites the current files. Restore anyway?'))return;
 notice('Running the approved action. If an admin prompt appears, it comes from your operating system.');
 try{const r=await post(`/api/harness/cards/${id}/approve`,{action,confirm:confirmFirst});notice(r.message||r.status)}catch(e){notice(`Action failed: ${e.message}`)}
 poll();
}
async function ignoreCard(id){try{await post(`/api/harness/cards/${id}/ignore`)}catch(e){notice(e.message)}poll()}
async function toggleAA(){try{const r=await post('/api/harness/always_active',{on:!JSON.parse(hs||'{}').always_active});notice(`Always-Active ${r.always_active?'on':'off'}.`)}catch(e){notice(e.message)}poll()}
async function scanNow(){try{const r=await post('/api/harness/scan');notice(r.message)}catch(e){notice(`Scan failed: ${e.message}`)}poll()}
async function runDemo(){try{const r=await post('/api/harness/demo');notice(r.message)}catch(e){notice(`Demo failed: ${e.message}`)}poll()}
async function undoIsolation(){if(!confirm('Remove network isolation and reconnect this computer?'))return;try{const r=await post('/api/harness/undo_isolation');notice(r.message)}catch(e){notice(e.message)}poll()}
function tick(){$('clock').textContent=new Date().toLocaleTimeString()}
tick();setInterval(tick,1000);poll();setInterval(poll,3000);
async function refreshMetrics(){
 try{
  const s=await api('/api/system');
  $('cpu').textContent=`${Number(s.cpu_percent||0).toFixed(0)}%`;
  $('ram').textContent=`${Number(s.ram_percent||0).toFixed(0)}%`;
  $('disk').textContent=`${Number(s.disk_percent||0).toFixed(0)}%`;
  meter('cpuBar',s.cpu_percent);meter('ramBar',s.ram_percent);meter('diskBar',s.disk_percent);
  $('ramMeta').textContent=`${fmt(s.ram_used)} / ${fmt(s.ram_total)}`;
  $('diskMeta').textContent=`${fmt(s.disk_free)} free`;
 }catch(e){if(!lastReport)notice('Backend not reachable. Start the Flask server.');}
}
refreshMetrics();setInterval(refreshMetrics,3000);
