
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
  const name=a.name.toLowerCase(), cat=a.category.toLowerCase();
  const allSteps=a.steps||[];
  const sourceNames=[...new Set((a.queries||[]).flatMap(q=>(q.pivots||[]).map(p=>p.source)).concat((a.queries||[]).map(q=>q.purpose||'')).filter(Boolean))];
  const logs=sourceNames.length?sourceNames.join(', '):'Use the alert source and connected identity, endpoint, network, cloud or application telemetry relevant to this alert.';
  const pivots=allSteps.slice(0,4).map(s=>s.title).filter(Boolean).join(' → ') || 'Correlate the affected entity, time window and related events.';
  const redFlags=allSteps.map(s=>s.check||'').filter(Boolean).filter(t=>/unusual|unexpected|unauthor|malicious|failed|success|external|new|change|disabled|encoded|suspicious|rare|exfiltrat|privilege|bypass|unknown/i.test(t)).slice(0,3);
  const precautions=[];
  if(/identity|authentication|login|password|account|credential|sign-in|conditional access/.test(name+' '+cat)) precautions.push('Validate the user and approved sign-in context; review MFA, sessions, risky sign-ins and account changes. Revoke sessions or reset credentials only under the identity-response procedure.');
  if(/malware|endpoint|ransomware|process|powershell|file|edr/.test(name+' '+cat)) precautions.push('Check process tree, file/hash, endpoint scope and EDR action. Isolate an endpoint only when evidence and incident policy justify it.');
  if(/email|phish|mail|url/.test(name+' '+cat)) precautions.push('Validate sender, headers, URLs and attachments; search for other recipients and use approved message-removal/blocking workflows.');
  if(/network|firewall|dns|proxy|exfiltration/.test(name+' '+cat)) precautions.push('Validate source/destination, protocol, volume and asset ownership; apply network blocks only after checking business impact and change controls.');
  if(/cloud|azure|aws|gcp|storage|key vault|iam/.test(name+' '+cat)) precautions.push('Review cloud audit events, identity permissions and resource exposure; preserve audit evidence before changing roles, keys or access policies.');
  if(/ot security|industrial|scada|plc|modbus|dnp3|opc ua|controller/.test(name+' '+cat)) precautions.push('Use passive OT telemetry and confirm with the authorized OT owner. Do not actively scan, issue control commands or change PLC/safety logic without formal authorization.');
  if(!precautions.length) precautions.push('Preserve relevant telemetry, validate expected activity with the asset owner and follow the approved response/change process before containment or tuning.');
  const response=allSteps.find(s=>/contain|remediat|isolate|disable|revoke|block|escalat/i.test(s.check||''))?.check || a.recommendation || 'Follow the approved incident response process, preserve evidence and scope related activity before remediation.';
  const evidence=[...new Set(allSteps.slice(0,5).flatMap(s=>(s.fields||'').split(';').map(x=>x.trim())).filter(Boolean))].slice(0,9).join('; ');
  return `<div class="analysis-guide"><h3>Alert-specific analysis guide</h3><div class="analysis-guide-grid">
   <div class="guide-panel"><h4>Logs / Telemetry</h4><p>${esc(logs)}. Confirm table/source availability and time coverage.</p></div>
   <div class="guide-panel"><h4>Investigation pivots</h4><p>${esc(pivots)}. Correlate by entity, timestamp, source/destination and related event IDs.</p></div>
   <div class="guide-panel"><h4>🚩 Red flags</h4><ul>${(redFlags.length?redFlags:['Activity inconsistent with the established baseline, approved change records or expected user/device behaviour.']).map(x=>`<li>${esc(x)}</li>`).join('')}</ul></div>
   <div class="guide-panel"><h4>🛡️ Precaution / Prevention</h4><ul>${precautions.map(x=>`<li>${esc(x)}</li>`).join('')}</ul></div>
   <div class="guide-panel"><h4>🔴 If compromise is suspected / confirmed</h4><p>${esc(response)} Preserve evidence, scope related entities and escalate according to severity and policy. Coordinate disruptive actions with the service/asset owner.</p></div>
   <div class="guide-panel"><h4>📋 Evidence to collect</h4><p>${esc(evidence||'Timestamp, affected entity, source event/alert ID, raw event details, related indicators, analyst actions and owner validation.')}. Record UTC/local timezone and any telemetry gaps.</p></div>
  </div></div>`;
 }

 const TOOL_NAMES=['Microsoft Sentinel','Splunk','IBM QRadar','Microsoft Defender XDR','CrowdStrike Falcon','SentinelOne','Elastic Security'];
 function stepQueryMarkup(a,st){
  const first=(a.queries||[]).find(q=>q.tool===TOOL_NAMES[0])||(a.queries||[])[0]||{tool:'Manual investigation',language:'Manual pivot guidance',purpose:'Relevant telemetry',query:'Start from the alert entity and time window; pivot using the fields listed above.',note:'No executable query was provided for this tool.'};
  const options=TOOL_NAMES.map(t=>`<option value="${esc(t)}" ${t===first.tool?'selected':''}>${esc(t)}</option>`).join('');
  const initial=selectStepQuery(a,st,first.tool);
  return `<div class="step-query-panel" data-step-query-panel data-alert-id="${a.id}" data-step-n="${st.n}">
    <label class="step-tool-label">Select tool for this investigation step
      <select class="step-tool-select" aria-label="Select query tool">${options}</select>
    </label>
    <div class="step-query-result">
      <p class="query-language">${esc(initial.language)} · ${esc(initial.source)}</p>
      <pre class="query-code step-query-code">${esc(initial.query)}</pre>
      <p class="query-note">${esc(initial.note)}</p>
      <button type="button" class="copy-btn step-query-copy">Copy step query / pivot</button>
    </div>
    <p class="muted">Query/pivot is a starting point. Filter by the actual alert entity and time range; validate schema, permissions and telemetry coverage before interpreting results.</p>
  </div>`;
 }
 function selectStepQuery(a,st,tool){
  const q=(a.queries||[]).find(x=>x.tool===tool);
  if(!q)return {language:'Manual pivot guidance',source:'Relevant telemetry',query:`Alert: ${a.name}\nStep: ${st.title}\nStart from the alert entity and time window. Search the relevant source for: ${st.check}\nPivot using fields: ${st.fields}`,note:'No query definition is available for this tool; use the product UI and validate the relevant telemetry.'};
  const words=(st.title+' '+st.check+' '+st.fields).toLowerCase().split(/[^a-z0-9]+/).filter(w=>w.length>3);
  let pivots=q.pivots||[{source:q.purpose,query:q.query,note:q.note}];
  const score=p=>{const hay=(p.source+' '+p.query+' '+p.note).toLowerCase();return words.reduce((n,w)=>n+(hay.includes(w)?1:0),0)};
  const chosen=pivots.slice().sort((x,y)=>score(y)-score(x))[0]||{source:q.purpose,query:q.query,note:q.note};
  let query=chosen.query||q.query||'Use the product UI to search relevant telemetry.';
  let note=chosen.note||q.note||'Validate fields and time range.';
  if(/Product-specific|guidance/i.test(q.language)||/manual pivot/i.test(q.language)){
    query=`${a.name} — ${st.title}\n\nProduct UI pivot (not universal executable syntax):\n1. Open the alert/detection and set the time range around the alert.\n2. Filter on the affected host/user/entity and the indicator(s) listed in the alert.\n3. Review: ${st.check}\n4. Capture: ${st.fields}\n5. Pivot to related events before/after the timestamp and other hosts with the same indicator.`;
    note='Product-specific UI guidance, not executable query syntax. Use your tenant’s supported event search and field names.';
  }
  return {language:q.language||'Query starter',source:chosen.source||q.purpose||'Relevant telemetry',query,note};
 }
 function sampleTemplate(a){
  const steps=a.steps.map(st=>`${String(st.n).padStart(2,'0')}. ${st.title}\nFinding: [enter observed values; do not infer from the alert title]\nEvidence/event IDs: [IDs, fields and timestamps]\nStatus: [confirmed / ruled out / pending / not available]`).join('\n\n');
  return `SAMPLE ANALYSIS & CLOSURE — ${a.name}\n\nAlert definition / trigger: ${a.overview}\nAlert ID: [alert/incident ID]\nSeverity: [severity and rationale]\nAffected host/resource: [hostname/resource]\nAffected user/account: [user/account or N/A]\nFirst seen: [date/time + timezone]\nLast seen: [date/time + timezone]\nDetection source and status: [product/rule; detected/blocked/quarantined/remediation failed]\n\nINVESTIGATION FINDINGS\n${steps}\n\nSCOPE AND IMPACT\nAffected hosts/users/shares/resources: [values or “none identified in reviewed telemetry”]\nLateral movement: [evidence / not observed in available telemetry / undetermined]\nData access or exfiltration: [evidence / not observed in available telemetry / undetermined]\nBusiness impact: [impact and asset owner]\n\nCONTAINMENT / REMEDIATION\nActions taken: [action, operator/approver, timestamp]\nAction status: [success/failure/pending; verification evidence]\nRecovery / follow-up: [owner, action and due date]\n\nCLASSIFICATION: [True Positive / Benign Positive / False Positive / Undetermined]\nRationale: [evidence supporting the disposition]\nEvidence references: [query names, event IDs, raw logs, hashes, screenshots/case links]\nTelemetry gaps / limitations: [missing source, retention, field or validation]\nResidual risk and next owner/action: [details]\n\nClosure summary: Based on [specific evidence], ${a.name} was classified as [classification] for [host/resource] during [time range]. Findings: [concise factual summary]. Actions: [verified containment/remediation]. Remaining risk or evidence gaps: [details]. Follow-up owner: [owner].`;
 }
 function card(a){
  const refs=a.references.map(r=>`<a href="${esc(r[1])}" target="_blank" rel="noopener noreferrer">${esc(r[0])} ↗</a>`).join('');
  const steps=a.steps.map(st=>`<details class="step-panel"><summary><span>${String(st.n).padStart(2,'0')}</span>${esc(st.title)}</summary><div class="step-content"><p><strong>WHAT TO CHECK</strong><br>${esc(st.check)}</p><p><strong>FIELDS TO CAPTURE</strong><br>${esc(st.fields)}</p>${stepQueryMarkup(a,st)}${(st.osint&&st.osint.length)||contextualTools(a,st).length?`<div class="osint-links"><strong>Useful tools for this investigation step</strong>${[...(st.osint||[]),...contextualTools(a,st)].filter((o,i,arr)=>arr.findIndex(x=>x.name===o.name)===i).map(o=>`<a href="${esc(o.url)}" target="_blank" rel="noopener noreferrer">${esc(o.name)} ↗</a>`).join('')}<small>Check the specific evidence relevant to this alert. Reputation and sandbox results are leads, not proof.</small></div>`:''}${quickLookupHtml(a,st)}</div></details>`).join('');
  const classes=Object.entries(a.classifications).map(([k,v])=>`<div class="classification-panel"><h4>${esc(k)}</h4><p><b>Recommendation</b><br>${esc(v.recommendation)}</p><p><b>Sample closure comment</b><br>${esc(v.closure)}</p><button class="copy-btn" data-close="${esc(k)}">Copy closure template</button></div>`).join('');
  const qs=a.queries.map((q,i)=>`<button type="button" data-query-tool="${i}" aria-selected="${i===0?'true':'false'}">${esc(q.tool)}</button>`).join('');
  const first=a.queries[0];
  return `<article class="alert-card" data-id="${a.id}"><details><summary class="alert-summary"><span class="alert-num">${String(a.id).padStart(3,'0')}</span><div class="alert-title-wrap"><div class="alert-title">${esc(a.name)}</div><div class="alert-meta">${esc(a.category)} · SOC L2 investigation reference</div></div><span class="alert-pill">Open SOP</span></summary><div class="alert-body"><section><h3>Alert overview</h3><p>${esc(a.overview)}</p><div class="overview-grid"><div class="mini-panel"><b>Severity guide</b>${esc(a.severity)}</div><div class="mini-panel"><b>Affected entities</b>${esc(a.entities)}</div><div class="mini-panel"><b>Investigation</b>${a.steps.length} structured steps</div></div><div class="alert-specific-recommendation"><h3>Alert-specific response guidance</h3><p>${esc(a.recommendation)}</p></div></section><section class="analysis-guide-section">${analysisGuide(a)}</section><section><h3>Investigation steps</h3><p class="muted">Open each step for WHAT TO CHECK, FIELDS TO CAPTURE, relevant tools and a tool-specific query/pivot. Consolidated sample analysis appears after all steps.</p><div class="investigation-steps">${steps}</div><section class="sample-analysis-final"><h3>Sample analysis & closure template</h3><p class="muted">Complete after reviewing all steps. Replace every bracketed placeholder with evidence for this alert; record “not observed in available telemetry” or “undetermined” where appropriate.</p><pre class="query-code final-analysis-template">${esc(sampleTemplate(a))}</pre><button type="button" class="copy-btn final-analysis-copy">Copy sample analysis template</button></section></section><section><h3>Detection & investigation query references</h3><p class="muted">These are starters, not guaranteed production detections. Adjust source, event filters, schema and time window for your deployment. Some vendor tabs provide pivot guidance rather than executable syntax.</p><div class="query-panel"><div class="query-tabs" role="tablist">${qs}</div><p class="muted">Select a tool first, then select the relevant table/data source below. Run one query at a time.</p><div class="query-pivot-tabs" role="tablist">${(first.pivots||[{source:first.purpose,query:first.query,note:first.note}]).map((p,i)=>`<button type="button" data-query-pivot="${i}" aria-selected="${i===0?'true':'false'}">${esc(p.source)}</button>`).join('')}</div><p class="query-language">${esc(first.language)} · ${esc((first.pivots&&first.pivots[0].source)||first.purpose)}</p><pre class="query-code">${esc((first.pivots&&first.pivots[0].query)||first.query)}</pre><p class="query-note">${esc((first.pivots&&first.pivots[0].note)||first.note)}</p><button class="copy-btn query-copy-btn">Copy query</button></div></section><section><h3>Classification & closure</h3><p class="muted">Choose the disposition supported by the available evidence. Recommendations and closure templates below are starting points—replace placeholders.</p><div class="classifications">${classes}</div></section><section><h3>Official documentation</h3><div class="reference-list">${refs}</div><p class="muted">Official docs are reference material; they do not prove the activity in your environment.</p></section></div></details></article>`;
 }
 search.addEventListener('input',render);cat.addEventListener('change',render);sev.addEventListener('change',render);

 results.addEventListener('change',e=>{
  const sel=e.target.closest('.step-tool-select'); if(!sel)return;
  const panel=sel.closest('[data-step-query-panel]'); if(!panel)return;
  const a=data.find(x=>x.id===Number(panel.dataset.alertId)); if(!a)return;
  const st=a.steps.find(x=>x.n===Number(panel.dataset.stepN)); if(!st)return;
  const q=selectStepQuery(a,st,sel.value), box=panel.querySelector('.step-query-result');
  box.querySelector('.query-language').textContent=q.language+' · '+q.source;
  box.querySelector('.step-query-code').textContent=q.query;
  box.querySelector('.query-note').textContent=q.note;
 });
 results.addEventListener('click',e=>{
  const stepCopy=e.target.closest('.step-query-copy');
  if(stepCopy){const panel=stepCopy.closest('[data-step-query-panel]');const q=panel.querySelector('.step-query-code').textContent;navigator.clipboard?.writeText(q);stepCopy.textContent='Copied (if permitted)';setTimeout(()=>stepCopy.textContent='Copy step query / pivot',1800);return;}
  const finalCopy=e.target.closest('.final-analysis-copy');
  if(finalCopy){const tpl=finalCopy.closest('.sample-analysis-final').querySelector('.final-analysis-template').textContent;navigator.clipboard?.writeText(tpl);finalCopy.textContent='Copied (if permitted)';setTimeout(()=>finalCopy.textContent='Copy sample analysis template',1800);return;}
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
