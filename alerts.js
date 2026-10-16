
(function(){
 const data=window.SAINSEC_ALERTS||[], results=document.getElementById('alert-results'), search=document.getElementById('alert-search'), cat=document.getElementById('category-filter'), sev=document.getElementById('severity-filter'), empty=document.getElementById('empty-state');
 const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 function contextualTools(a,st){
  const text=(a.name+' '+a.category+' '+st.title+' '+st.check).toLowerCase(), out=[];
  const add=(name,url,why)=>{if(!out.some(x=>x.name===name))out.push({name,url,why})};
  if(/ip address|source ip|destination ip|ip reputation|network connection|remote address|ip-based|ip indicator|source\/destination|src_ip/.test(text)||/network|firewall|dns|proxy|identity|authentication|exfiltration/i.test(a.category)){
   add('VirusTotal IP / indicator lookup','https://www.virustotal.com/gui/home/search','Review detections, related indicators and last analysis; reputation is not proof.');
   add('AbuseIPDB','https://www.abuseipdb.com/','Review report recency, confidence and reported behaviour.');
   add('Cisco Talos Reputation','https://talosintelligence.com/reputation_center','Check reputation/context and compare with internal telemetry.');
  }
  if(/domain|dns|url|phish|email|mail|click|web|proxy|sender|attachment/.test(text)){
   add('urlscan.io','https://urlscan.io/','Review URL/domain scan results and observed requests; consider public visibility before submitting.');
   add('URLhaus','https://urlhaus.abuse.ch/','Check whether a URL/host is associated with malware distribution.');
   add('Google Admin Toolbox – Messageheader','https://toolbox.googleapps.com/apps/messageheader/','For email alerts, inspect message hops, SPF/DKIM/DMARC results and routing.');
   add('MXToolbox','https://mxtoolbox.com/','Check DNS, MX and mail-domain configuration where relevant.');
  }
  if(/malware|ransomware|hash|file|payload|powershell|process|executable|dll|script|trojan|endpoint|edr|quarantine|command line/.test(text)){
   add('VirusTotal','https://www.virustotal.com/gui/home/search','Search file hash or indicator; avoid uploading confidential files.');
   add('MalwareBazaar','https://bazaar.abuse.ch/','Search known malware hashes/samples and metadata.');
   add('ANY.RUN','https://any.run/','Interactive sandbox for approved samples; follow company handling rules.');
   add('Triage Sandbox','https://tria.ge/','Sandbox behaviour and network/process observations.');
   add('Hybrid Analysis','https://www.hybrid-analysis.com/','Sandbox report and behavioural indicators.');
   add('CyberChef','https://gchq.github.io/CyberChef/','Decode/transform strings or safely inspect encoded text.');
  }
  if(/vulnerab|cve|exploit|patch|exposure|weak cipher|tls|certificate|configuration|misconfig/.test(text)){
   add('NVD CVE Search','https://nvd.nist.gov/vuln/search','Check CVE details, affected versions and references.');
   add('CISA Known Exploited Vulnerabilities','https://www.cisa.gov/known-exploited-vulnerabilities-catalog','Check whether the CVE is listed as exploited in the wild.');
   add('FIRST EPSS','https://www.first.org/epss/','Use EPSS as a probability signal alongside exposure and business impact.');
  }
  if(/mitre|tactic|technique|persistence|privilege escalation|lateral movement|living off the land|attack technique/.test(text)){
   add('MITRE ATT&CK','https://attack.mitre.org/','Map observed behaviour to techniques only when supported by evidence.');
  }
  if(/ot security|industrial|scada|plc|modbus|dnp3|opc ua|ethernet\/ip|hmi|safety instrumented|controller/.test(text)){
   add('MITRE ATT&CK for ICS','https://attack.mitre.org/matrices/ics/','Validate industrial technique context; use passive telemetry and OT owner input.');
   add('CISA ICS Recommended Practices','https://www.cisa.gov/resources-tools/resources/ics-recommended-practices','Reference OT-safe incident handling and controls.');
   add('NIST SP 800-82 OT Security','https://csrc.nist.gov/pubs/sp/800/82/r3/final','Reference OT security architecture and response guidance.');
  }
  if(/identity|sign.?in|login|authentication|mfa|conditional access|account|credential|oauth|consent|privilege|user/.test(text)){
   add('Have I Been Pwned','https://haveibeenpwned.com/','Use only approved public-domain/account checks; do not submit internal identifiers without policy approval.');
   add('MITRE ATT&CK','https://attack.mitre.org/','Map validated credential-access or account-abuse behaviour.');
  }
  if(/cloud|aws|azure|gcp|storage|s3|key vault|iam|role|service principal/.test(text)){
   add('Cloud Security Alliance Cloud Controls Matrix','https://cloudsecurityalliance.org/research/cloud-controls-matrix','Reference cloud control expectations; validate against provider audit logs.');
   add('MITRE ATT&CK Cloud','https://attack.mitre.org/matrices/enterprise/cloud/','Map cloud behaviours when supported by evidence.');
  }
  return out;
 }
 function quickLookupHtml(a,st){
  const text=(a.name+' '+a.category+' '+st.title+' '+st.check).toLowerCase();
  let types=[];
  if(/malware|ransomware|hash|file|payload|powershell|process|executable|dll|script|trojan|endpoint|edr|quarantine|command line/.test(text)) types=[['hash','Hash / file indicator'],['ip','IP address'],['domain','Domain / URL']];
  else if(/phish|email|mail|url|domain|sender|attachment|click/.test(text)) types=[['url','URL / domain'],['ip','IP address'],['hash','File hash']];
  else if(/vulnerab|cve|exploit|patch|exposure/.test(text)) types=[['cve','CVE ID (e.g. CVE-2025-0001)']];
  else if(/ot security|industrial|scada|plc|modbus|dnp3|opc ua|ethernet\/ip|hmi|controller/.test(text)) types=[['ip','OT asset IP'],['domain','Hostname / indicator']];
  else if(/ip|network|firewall|dns|proxy|exfiltration/.test(text)) types=[['ip','IP address'],['domain','Domain / URL']];
  else return '';
  return `<div class="quick-lookup"><label>Quick OSINT lookup <input type="text" class="ioc-input" placeholder="${esc(types[0][1])}" aria-label="Indicator to look up"></label><div class="lookup-buttons">${types.map(t=>`<button type="button" class="lookup-btn" data-lookup-type="${t[0]}">${esc(t[1])}</button>`).join('')}</div><small>Opens external public services. Do not submit confidential files or sensitive identifiers without approval; public results may be incomplete.</small></div>`;
 }
 [...new Set(data.map(a=>a.category))].forEach(c=>{let o=document.createElement('option');o.value=c;o.textContent=c;cat.appendChild(o)});
 document.getElementById('total-count').textContent=data.length;
 function render(){
  const q=search.value.trim().toLowerCase(), c=cat.value, s=sev.value;
  const filtered=data.filter(a=>(!q||(a.name+' '+a.category+' '+a.overview).toLowerCase().includes(q))&&(!c||a.category===c)&&(!s||a.severity.startsWith(s)));
  results.innerHTML=filtered.map(a=>card(a)).join('');empty.hidden=filtered.length>0;
  results.querySelectorAll('[data-query-tool]').forEach(btn=>btn.addEventListener('click',()=>{
   const card=btn.closest('.alert-card'), idx=Number(btn.dataset.queryTool), alert=data.find(a=>a.id===Number(card.dataset.id));
   card.querySelectorAll('[data-query-tool]').forEach(b=>b.setAttribute('aria-selected',String(b===btn)));
   const qdata=alert.queries[idx];
   renderPivots(card,qdata,0);
  }));
  results.querySelectorAll('.copy-btn').forEach(btn=>{if(btn.dataset.close) return;btn.onclick=()=>{const card=btn.closest('.alert-card');const activeTool=card.querySelector('[data-query-tool][aria-selected=true]');const alert=data.find(a=>a.id===Number(card.dataset.id));const qdata=alert.queries[Number(activeTool.dataset.queryTool)];const activePivot=Number(card.querySelector('[data-query-pivot][aria-selected=true]')?.dataset.queryPivot||0);const query=(qdata.pivots&&qdata.pivots[activePivot]?qdata.pivots[activePivot].query:qdata.query);navigator.clipboard?.writeText(query);btn.textContent='Copied (if clipboard permission granted)';setTimeout(()=>btn.textContent='Copy query',1800)}});
  results.querySelectorAll('[data-query-pivot]').forEach(btn=>btn.addEventListener('click',()=>{
   const card=btn.closest('.alert-card'), activeTool=card.querySelector('[data-query-tool][aria-selected=true]'), alert=data.find(a=>a.id===Number(card.dataset.id)), qdata=alert.queries[Number(activeTool.dataset.queryTool)];
   renderPivots(card,qdata,Number(btn.dataset.queryPivot));
  }));
 }
 function renderPivots(card,qdata,index){
  const pivots=qdata.pivots||[{source:qdata.purpose||'Investigation query',query:qdata.query,note:qdata.note}];
  const i=Math.max(0,Math.min(index,pivots.length-1)), p=pivots[i];
  const pivotTabs=card.querySelector('.query-pivot-tabs');
  pivotTabs.innerHTML=pivots.map((pv,n)=>`<button type="button" data-query-pivot="${n}" aria-selected="${n===i?'true':'false'}">${esc(pv.source)}</button>`).join('');
  pivotTabs.querySelectorAll('[data-query-pivot]').forEach(btn=>btn.addEventListener('click',()=>{
   renderPivots(card,qdata,Number(btn.dataset.queryPivot));
  }));
  card.querySelector('.query-code').textContent=p.query;
  card.querySelector('.query-language').textContent=qdata.language+' · '+p.source;
  card.querySelector('.query-note').textContent=p.note||qdata.note||'Validate schema and source coverage before use.';
  const copy=card.querySelector('.query-copy-btn');copy.onclick=()=>{navigator.clipboard?.writeText(p.query);copy.textContent='Copied (if clipboard permission granted)';setTimeout(()=>copy.textContent='Copy query',1800)};
 }
 function analysisGuide(a){
  const g=a.analysisGuide||{};
  const list=(v)=>Array.isArray(v)?v:(v?[v]:[]);
  const logs=g.logsTelemetry||'Use the alert source and connected telemetry relevant to this alert; verify availability and time coverage.';
  const pivots=g.investigationPivots||'Correlate the primary entity, timestamp, source/destination and related event IDs.';
  const redFlags=list(g.redFlags);
  const precautions=list(g.precautionPrevention);
  const response=g.ifCompromise||a.recommendation||'Follow the approved incident-response process, preserve evidence and scope related activity.';
  const evidence=g.evidenceToCollect||'Timestamp, affected entity, source alert/event ID, raw evidence, related indicators, analyst actions and telemetry gaps.';
  return `<div class="analysis-guide"><h3>Alert-specific analysis guide</h3><div class="analysis-guide-grid">
   <div class="guide-panel"><h4>Logs / Telemetry</h4><p>${esc(logs)} Confirm table/source availability, retention and time coverage.</p></div>
   <div class="guide-panel"><h4>Investigation pivots</h4><p>${esc(pivots)}</p></div>
   <div class="guide-panel"><h4>🚩 Red flags</h4><ul>${redFlags.map(x=>`<li>${esc(x)}</li>`).join('')}</ul></div>
   <div class="guide-panel"><h4>🛡️ Precaution / Prevention</h4><ul>${precautions.map(x=>`<li>${esc(x)}</li>`).join('')}</ul></div>
   <div class="guide-panel"><h4>🔴 If compromise is suspected / confirmed</h4><p>${esc(response)}</p></div>
   <div class="guide-panel"><h4>📋 Evidence to collect</h4><p>${esc(evidence)} Record UTC/local timezone and any telemetry gaps.</p></div>
  </div></div>`;
 }
 function card(a){
  const refs=a.references.map(r=>`<a href="${esc(r[1])}" target="_blank" rel="noopener noreferrer">${esc(r[0])} ↗</a>`).join('');
  const steps=a.steps.map(st=>`<details class="step-panel"><summary><span>${String(st.n).padStart(2,'0')}</span>${esc(st.title)}</summary><div class="step-content"><p><strong>WHAT TO CHECK</strong><br>${esc(st.check)}</p><p><strong>FIELDS TO CAPTURE</strong><br>${esc(st.fields)}</p><p><strong>SAMPLE ANALYSIS</strong><br>${esc(st.analysis)}</p>${st.nextPivot?`<p><strong>NEXT INVESTIGATION PIVOT</strong><br>${esc(st.nextPivot)}</p>`:""}<p class="muted">Replace bracketed values with actual evidence. Do not present an unverified value as a finding.</p>${(st.osint&&st.osint.length)||contextualTools(a,st).length?`<div class="osint-links"><strong>Useful tools for this investigation step</strong>${[...(st.osint||[]),...contextualTools(a,st)].filter((o,i,arr)=>arr.findIndex(x=>x.name===o.name)===i).map(o=>`<a href="${esc(o.url)}" target="_blank" rel="noopener noreferrer">${esc(o.name)} ↗</a>`).join('')}<small>Check the specific evidence relevant to this alert. Reputation and sandbox results are leads, not proof.</small></div>`:''}${quickLookupHtml(a,st)}</div></details>`).join('');
  const classes=Object.entries(a.classifications).map(([k,v])=>`<div class="classification-panel"><h4>${esc(k)}</h4><p><b>Recommendation</b><br>${esc(v.recommendation)}</p><p><b>Sample closure comment</b><br>${esc(v.closure)}</p><button class="copy-btn" data-close="${esc(k)}">Copy closure template</button></div>`).join('');
  const qs=a.queries.map((q,i)=>`<button type="button" data-query-tool="${i}" aria-selected="${i===0?'true':'false'}">${esc(q.tool)}</button>`).join('');
  const first=a.queries[0];
  return `<article class="alert-card" data-id="${a.id}"><details><summary class="alert-summary"><span class="alert-num">${String(a.id).padStart(3,'0')}</span><div class="alert-title-wrap"><div class="alert-title">${esc(a.name)}</div><div class="alert-meta">${esc(a.category)} · SOC L2 investigation reference</div></div><span class="alert-pill">Open SOP</span></summary><div class="alert-body"><section><h3>Alert overview</h3><p>${esc(a.overview)}</p><div class="overview-grid"><div class="mini-panel"><b>Severity guide</b>${esc(a.severity)}</div><div class="mini-panel"><b>Affected entities</b>${esc(a.entities)}</div><div class="mini-panel"><b>Investigation</b>${a.steps.length} structured steps</div></div><div class="definition-trigger-grid"><div class="guide-panel"><h4>Alert definition</h4><p>${esc(a.definition||a.overview)}</p></div><div class="guide-panel"><h4>When this alert triggers</h4><p>${esc(a.whenTriggers||"Validate the configured detection rule and raw telemetry; exact trigger logic depends on the source and deployment.")}</p><p><b>Trigger logic / prerequisites:</b> ${esc(a.triggerLogicNote||"Confirm source events, rule thresholds, correlation window and exclusions from the actual rule configuration.")}</p></div><div class="guide-panel"><h4>Why it matters</h4><p>${esc(a.whyItMatters||"Assess impact based on verified evidence, asset criticality and incident scope.")}</p></div></div><div class="alert-specific-recommendation"><h3>Alert-specific response guidance</h3><p>${esc(a.recommendation)}</p></div></section><section class="analysis-guide-section">${analysisGuide(a)}</section><section><h3>Investigation steps</h3><p class="muted">Open each step for the analyst action, evidence fields and sample analysis.</p><div class="investigation-steps">${steps}</div></section><section><h3>Detection & investigation query references</h3><p class="muted">These are starters, not guaranteed production detections. Adjust source, event filters, schema and time window for your deployment. Some vendor tabs provide pivot guidance rather than executable syntax.</p><div class="query-panel"><div class="query-tabs" role="tablist">${qs}</div><p class="muted">Select a tool first, then select the relevant table/data source below. Run one query at a time.</p><div class="query-pivot-tabs" role="tablist">${(first.pivots||[{source:first.purpose,query:first.query,note:first.note}]).map((p,i)=>`<button type="button" data-query-pivot="${i}" aria-selected="${i===0?'true':'false'}">${esc(p.source)}</button>`).join('')}</div><p class="query-language">${esc(first.language)} · ${esc((first.pivots&&first.pivots[0].source)||first.purpose)}</p><pre class="query-code">${esc((first.pivots&&first.pivots[0].query)||first.query)}</pre><p class="query-note">${esc((first.pivots&&first.pivots[0].note)||first.note)}</p><button class="copy-btn query-copy-btn">Copy query</button></div></section><section><h3>Classification & closure</h3><p class="muted">Choose the disposition supported by the available evidence. Recommendations and closure templates below are starting points—replace placeholders.</p><div class="classifications">${classes}</div></section><section><h3>Official documentation</h3><div class="reference-list">${refs}</div><p class="muted">Official docs are reference material; they do not prove the activity in your environment.</p></section></div></details></article>`;
 }
 search.addEventListener('input',render);cat.addEventListener('change',render);sev.addEventListener('change',render);
 results.addEventListener('click',e=>{
  const lookup=e.target.closest('[data-lookup-type]');
  if(lookup){
   const panel=lookup.closest('.quick-lookup'), input=panel.querySelector('.ioc-input'), value=input.value.trim();
   if(!value){input.focus();input.placeholder='Enter an indicator first';return}
   const type=lookup.dataset.lookupType;let url='';
   if(type==='ip') url='https://www.virustotal.com/gui/search/'+encodeURIComponent(value);
   else if(type==='domain') url='https://urlscan.io/search/#'+encodeURIComponent(value);
   else if(type==='url') url='https://urlscan.io/search/#'+encodeURIComponent(value);
   else if(type==='hash') url='https://www.virustotal.com/gui/search/'+encodeURIComponent(value);
   else if(type==='cve') url='https://nvd.nist.gov/vuln/search/results?query='+encodeURIComponent(value);
   if(url) window.open(url,'_blank','noopener,noreferrer');
   return;
  }
  const b=e.target.closest('[data-close]');if(!b)return;const article=b.closest('.alert-card'),a=data.find(x=>x.id===Number(article.dataset.id));const text=a.classifications[b.dataset.close].closure;navigator.clipboard?.writeText(text);b.textContent='Copied (if permitted)';setTimeout(()=>b.textContent='Copy closure template',1800)
 });
 render();
})();
