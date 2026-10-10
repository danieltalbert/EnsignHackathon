const $=id=>document.getElementById(id);
let lastReport=null, lastAI=null;
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=n=>{n=Number(n||0);for(const u of ['B','KB','MB','GB','TB']){if(n<1024||u==='TB')return `${n.toFixed(1)} ${u}`;n/=1024}};
async function api(url,opts={}){const r=await fetch(url,{cache:'no-store',...opts});if(!r.ok)throw Error(`${r.status} ${r.statusText}: ${(await r.text()).slice(0,250)}`);return r.json()}
function notice(s){$('notice').textContent=s}
function meter(id,v){$(id).style.width=`${Math.max(0,Math.min(100,v||0))}%`}
async function runScan(){
 const b=$('scanBtn');b.disabled=true;b.textContent='Scanning…';notice('Collecting a manual snapshot. This may take a little while.');
 $('findings').innerHTML='<p class="muted">Collecting evidence…</p>';
 try{
  const r=await api('/api/scan',{method:'POST'});lastReport=r;lastAI=null;
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
  $('storageNote').textContent=`${r.storage.files_scanned} files checked; ${r.storage.total_candidate_count} cleanup candidates.${r.storage.truncated?' Scan limit reached.':''} Nothing is deleted.`;
  $('files').innerHTML=r.storage.candidates.map(f=>`<div class="file-item"><strong>${esc(f.name)} · ${esc(f.size_label)}</strong><p>${esc(f.path)}</p><p>${f.age_days} days since modification · ${esc(f.reason)}</p></div>`).join('')||'<p class="muted">No candidates found in the scanned subset.</p>';
  $('processRows').innerHTML=r.processes.slice(0,30).map(p=>`<tr><td>${esc(p.name)}</td><td>${p.pid}</td><td>${esc(p.parent_name||'—')}</td><td>${p.cpu}%</td><td>${esc(p.memory)}</td><td title="${esc(p.exe)}">${esc(p.exe||'Unavailable')}</td></tr>`).join('')||'<tr><td colspan="6">No visible processes</td></tr>';
  $('aiBtn').disabled=false;$('aiResult').textContent='Ready to analyze this scan with Ollama.';
  notice(`Assessment complete at ${new Date().toLocaleTimeString()}. Findings are leads for human review, not confirmed infections.`);
 }catch(e){notice(`Scan failed: ${e.message}`)}
 finally{b.disabled=false;b.textContent='▶ Run security assessment'}
}
function renderFindings(){
 if(!lastReport)return;
 const filter=$('filter').value;
 const list=lastReport.findings.filter(f=>filter==='All'||f.category===filter);
 $('findings').innerHTML=list.map(f=>`<article class="finding ${esc(f.severity)}"><div class="finding-top"><span class="tag">${esc(f.category)}</span><span class="severity ${esc(f.severity)}">${esc(f.severity)}</span></div><h3>${esc(f.title)}</h3><p><b>Evidence</b> · ${esc(f.evidence)}</p><p><b>Recommended action</b> · ${esc(f.recommendation)}</p><small>Rule confidence: ${esc(f.confidence)} · ID ${esc(f.id)}</small></article>`).join('')||'<p class="muted">No findings in this category for this snapshot. This does not prove the system is clean.</p>';
}
async function analyze(){
 if(!lastReport)return;
 const b=$('aiBtn');b.disabled=true;b.textContent='Analyzing…';
 $('aiResult').textContent='Waiting for local Ollama. First model load can take a while.';
 try{
  const r=await api('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({report:lastReport})});
  lastAI=r;
  if(!r.available){$('aiResult').innerHTML=`<h3>AI unavailable</h3><p>${esc(r.message||r.error)}</p><p class="muted">${esc(r.error||'')}</p><p>Start Ollama and confirm the configured model with <code>ollama list</code>.</p>`;return}
  const a=r.analysis;
  $('aiResult').innerHTML=`<span class="pill">${esc(r.model)}</span><h3>${esc(a.summary||'Assessment summary')}</h3><p><b>Overall risk:</b> ${esc(a.overall_risk||'unknown')}</p>${(a.findings||[]).map(f=>`<div class="ai-finding"><b>${esc(f.finding_id)}</b><p>${esc(f.explanation)}</p><p><b>Recommendation:</b> ${esc(f.recommendation)}</p><small>AI confidence: ${esc(f.confidence||'unknown')}</small></div>`).join('')}${(a.limitations||[]).length?'<h3>Limitations</h3><ul>'+a.limitations.map(x=>`<li>${esc(x)}</li>`).join('')+'</ul>':''}`;
 }catch(e){$('aiResult').textContent=`AI request failed: ${e.message}`}
 finally{b.disabled=false;b.textContent='✳ Analyze with Gemma'}
}
function tick(){$('clock').textContent=new Date().toLocaleTimeString()}
tick();setInterval(tick,1000);
api('/api/system').then(s=>{$('cpu').textContent=`${s.cpu_percent.toFixed(0)}%`;$('ram').textContent=`${s.ram_percent.toFixed(0)}%`;$('disk').textContent=`${s.disk_percent.toFixed(0)}%`;meter('cpuBar',s.cpu_percent);meter('ramBar',s.ram_percent);meter('diskBar',s.disk_percent)}).catch(()=>notice('Backend not reachable. Start the Flask server.'));
