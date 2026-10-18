
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

 function toolDefinition(name){
  const n=(name||'').toLowerCase();
  if(n.includes('virustotal')) return 'Multi-engine reputation and relationship lookup for URLs, domains, IPs and file hashes. Use it to compare vendor detections, timestamps and related indicators; a verdict alone is not proof.';
  if(n.includes('abuseipdb')) return 'IP-abuse reporting service. Use report confidence, report count, recency and categories to add context to an IP; account for VPNs, proxies, NAT and shared hosting.';
  if(n.includes('urlscan')) return 'Web-page and URL scan service. Use the final URL, redirect chain, contacted hosts, page behaviour and scan visibility to understand where a click led.';
  if(n.includes('urlhaus')) return 'Malware URL intelligence feed. Check whether the exact URL or host is associated with malware distribution, and capture status, first-seen/last-seen and related payload indicators.';
  if(n.includes('talos')) return 'Cisco network and IP/domain reputation lookup. Use reputation and ownership context as enrichment, then compare it with internal network and DNS telemetry.';
  if(n.includes('messageheader')) return 'Email-header analysis tool. Use Received hops, sender alignment and SPF/DKIM/DMARC results to assess routing and possible spoofing; preserve the original headers.';
  if(n.includes('mxtoolbox')) return 'DNS and email-domain diagnostics. Use relevant MX, SPF, DKIM, DMARC and blacklist results to validate mail/domain configuration.';
  if(n.includes('malwarebazaar')) return 'Malware sample/hash intelligence. Search hashes and inspect sample metadata, family tags and related indicators; do not download or execute samples outside approved procedures.';
  if(n.includes('any.run')||n.includes('triage sandbox')||n.includes('hybrid analysis')) return 'Sandbox analysis service. Review process tree, dropped files, persistence and network connections; treat sandbox heuristics as leads and submit only approved samples.';
  if(n.includes('cyberchef')) return 'Data transformation and decoding utility. Preserve the original input and recipe, validate decoded indicators independently, and never paste secrets into an unapproved service.';
  if(n.includes('have i been pwned')) return 'Public breach-exposure lookup. Use only approved identifiers and record breach/date/data categories; exposure context does not prove the current alert was caused by it.';
  if(n.includes('mitre')) return 'Adversary-technique knowledge base. Use technique IDs and descriptions to guide investigation pivots only when observed evidence supports the mapping.';
  if(n.includes('nvd')) return 'Vulnerability reference database. Verify CVE details and affected versions against the actual asset inventory and vendor advisory.';
  if(n.includes('known exploited')) return 'CISA catalog of vulnerabilities known to be exploited. Use it to prioritize validated affected assets and remediation, not as proof the asset was exploited.';
  if(n.includes('epss')) return 'Exploit prediction probability signal for a CVE. Combine it with exposure, asset criticality, exploit evidence and KEV status.';
  if(n.includes('cloud controls matrix')) return 'Cloud control framework reference. Use it to identify relevant control expectations, then validate against native cloud audit evidence.';
  if(n.includes('cisa ics')||n.includes('nist sp 800-82')) return 'OT/ICS security guidance. Use for safety-aware response and control references; coordinate actions with the authorized OT owner.';
  if(n.includes('greynoise')) return 'Internet scanner context service. Check whether an IP is associated with common scanning activity and compare the timing with your own logs.';
  return 'External enrichment/reference service. Use it to validate the indicator or behaviour relevant to this alert, capture the report URL and checked time, and corroborate with native telemetry.';
 }
 function toolEvidenceGuide(a,st,o){
  const t=(a.name+' '+a.category+' '+st.title+' '+st.check).toLowerCase();
  const n=(o.name||'').toLowerCase();
  const out=[];
  const add=(label,items)=>out.push({label,items});
  if(n.includes('virustotal')){
   if(/url|domain|phish|email|click|web/.test(t)) add('Capture from VirusTotal URL/domain results',[
    'Submitted indicator exactly as observed; record the URL/domain and any redirect/final URL separately.',
    'Detection/reputation summary and which security vendors flagged it; record the checked date/time.',
    'First submission/last analysis timestamps, categories/tags, and related communicating URLs, domains, IPs or files.',
    'For file indicators: SHA-256, file type/size, names, signature and behaviour/relations where available.',
    'Record the report URL and relevant screenshots/export references in the case.'
   ]);
   else if(/ip|network|firewall|dns|proxy|exfiltration/.test(t)) add('Capture from VirusTotal IP/domain results',[
    'Indicator type and exact IP/domain; distinguish public IP from internal/private address.',
    'Detection ratio and names of vendors that flagged it, checked timestamp, ASN/owner and reputation context.',
    'Related domains, URLs, communicating files and historical resolutions/relations where available.',
    'Compare indicator timing with proxy, DNS, firewall, endpoint and alert telemetry.',
    'Record the report URL and key evidence; reputation alone does not prove malicious activity.'
   ]);
   else add('Capture from VirusTotal file/indicator results',[
    'SHA-256 (preferred), SHA-1/MD5 if supplied, file name/type/size and signature/publisher.',
    'Detection ratio and exact vendor labels; distinguish generic/heuristic detections from named families.',
    'First submission/last analysis timestamps, tags, contacted URLs/IPs/domains and related samples.',
    'Behaviour or sandbox evidence relevant to this alert; correlate with the observed host/process/time.',
    'Record report URL and checked time. Do not upload confidential files without approval.'
   ]);
  } else if(n.includes('urlscan')){
   add('Capture from urlscan.io',[
    'Scan ID/report URL, scan timestamp, submitted URL, final URL and complete redirect chain.',
    'Page title, screenshot, contacted domains/IPs, DNS/TLS certificate details and HTTP requests.',
    'Suspicious downloads, forms, credential collection, brand impersonation, scripts and third-party hosts relevant to this alert.',
    'Compare observed URLs/domains and timestamps with proxy, DNS, Safe Links and endpoint/browser telemetry.',
    'Check scan visibility before submission; public scans can expose submitted indicators.'
   ]);
  } else if(n.includes('urlhaus')){
   add('Capture from URLhaus',[
    'Exact URL/host, URLhaus status (listed/not found), date added/last seen and reference/report URL.',
    'Threat tags, malware family or campaign labels, payload/download URLs and related hosts when available.',
    'Compare the URL and observation time with the message click, proxy/DNS and endpoint events.',
    'Record whether the exact URL or only the parent domain matched; avoid treating a domain-only match as conclusive.',
    'A missing listing does not mean safe; a listing is one lead to corroborate.'
   ]);
  } else if(n.includes('abuseipdb')){
   add('Capture from AbuseIPDB',[
    'Exact IP, confidence-of-abuse score, total reports and last-reported timestamp.',
    'Report categories, recency, source context and whether reports align with the observed behaviour.',
    'Check whether the IP is a VPN, proxy, hosting provider, NAT or shared egress address where known.',
    'Correlate with source/destination, authentication or network logs for the same time window.',
    'Record report URL and checked time; shared/reputation data is not proof by itself.'
   ]);
  } else if(n.includes('talos')){
   add('Capture from Cisco Talos',[
    'Exact IP/domain and Talos reputation/category with lookup timestamp.',
    'Network owner/ASN and any available email/web reputation context.',
    'Compare reputation with internal DNS, proxy, firewall, mail and authentication records.',
    'Record report URL and any conflicting results from other sources; reputation can be stale.'
   ]);
  } else if(n.includes('messageheader')){
   add('Capture from message-header analysis',[
    'Message-ID, sender/recipient, subject and original message timestamp/timezone.',
    'Received hops in order, originating IP where supported, and unexpected relays or routing changes.',
    'SPF, DKIM and DMARC results plus Return-Path vs From/Reply-To alignment.',
    'Preserve original headers; correlate Message-ID with mail trace, message delivery and URL-click events.',
    'Do not conclude legitimacy from passing SPF/DKIM/DMARC alone.'
   ]);
  } else if(n.includes('mxtoolbox')){
   add('Capture from MXToolbox',[
    'Domain queried, lookup type, result and timestamp.',
    'Relevant MX, SPF, DKIM selector, DMARC, DNS or blacklist findings for this alert.',
    'Record exact host/record and TTL or listed source when displayed.',
    'Compare with authoritative DNS and tenant mail configuration; results may be cached or incomplete.'
   ]);
  } else if(n.includes('malwarebazaar')){
   add('Capture from MalwareBazaar',[
    'Exact hash searched (prefer SHA-256), match/no-match, sample first-seen date and report reference.',
    'Malware family/tags, file type, signature and associated campaign indicators when available.',
    'Correlate hash and related indicators with endpoint file/process events and quarantine status.',
    'Do not download or execute samples unless approved lab procedures allow it.'
   ]);
  } else if(n.includes('any.run')||n.includes('triage sandbox')||n.includes('hybrid analysis')){
   add('Capture from sandbox report',[
    'Submission/report ID, sample hash, environment/OS and analysis timestamp.',
    'Process tree, command lines, dropped files, persistence changes and security-control evasion.',
    'DNS/HTTP/TLS connections, contacted IPs/domains/URLs, payload hashes and observed indicators.',
    'Separate observed behaviour from sandbox heuristics; correlate with actual endpoint evidence.',
    'Only submit approved samples; follow data-handling policy and do not execute on production systems.'
   ]);
  } else if(n.includes('cyberchef')){
   add('Capture from CyberChef analysis',[
    'Original input source and exact transformation/recipe used; preserve the original value.',
    'Decoded output, encoding type and any extracted URLs, domains, IPs, hashes or commands.',
    'Validate decoded values independently; decoding is analysis, not proof of maliciousness.',
    'Do not paste secrets, tokens or confidential data into unapproved environments.'
   ]);
  } else if(n.includes('have i been pwned')){
   add('Capture from breach lookup',[
    'Use only approved public account/domain lookup; avoid submitting internal identifiers without authorization.',
    'Record matching breach name/date and exposed data categories if returned; do not copy exposed secrets.',
    'Correlate exposure date with password/MFA changes and authentication telemetry.',
    'A breach match indicates exposure context, not proof that the current alert is caused by it.'
   ]);
  } else if(n.includes('mitre att&ck')){
   add('Capture from MITRE ATT&CK',[
    'Technique/sub-technique ID and name only when observed behaviours support the mapping.',
    'Record the exact behaviour/evidence that supports the mapping and the relevant platform.',
    'Use technique mapping to guide pivots and coverage review; it is not an indicator reputation verdict.'
   ]);
  } else if(n.includes('nvd cve')){
   add('Capture from NVD',[
    'CVE ID, affected product/version and vendor advisory references.',
    'CVSS vector/severity, known affected configurations and required conditions.',
    'Compare with verified asset inventory, version, exposure and compensating controls.',
    'Record publication/modified dates; do not assume vulnerable until asset/version is confirmed.'
   ]);
  } else if(n.includes('known exploited')){
   add('Capture from CISA KEV',[
    'Exact CVE match, catalog date added and remediation due date where listed.',
    'Required action and vendor patch/advisory reference.',
    'Correlate with asset exposure, installed version and available exploitation evidence.'
   ]);
  } else if(n.includes('epss')){
   add('Capture from EPSS',[
    'CVE ID, EPSS probability and score date.',
    'Use as a likelihood signal alongside asset exposure, exploit availability, business criticality and KEV status.',
    'EPSS is not proof of exploitation on the affected asset.'
   ]);
  } else if(n.includes('mitre')&&n.includes('ics')){
   add('Capture from MITRE ATT&CK for ICS',[
    'Technique ID/name and affected ICS platform/level where supported by evidence.',
    'Observed control-system action, asset, function/operation and timestamp.',
    'Validate against passive network capture, engineering workstation logs and OT owner context.'
   ]);
  } else if(n.includes('cisa ics')||n.includes('nist sp 800-82')){
   add('Capture from OT guidance',[
    'Relevant recommended control/response practice and the OT asset/process it applies to.',
    'Safety, availability and process impact checks required before any response action.',
    'Record OT owner approval and the approved change/incident procedure; avoid unapproved active scans or isolation.'
   ]);
  } else if(n.includes('cloud controls matrix')||n.includes('mitre att&ck cloud')){
   add('Capture from cloud control/technique reference',[
    'Control or technique ID/name and the observed cloud service/API action.',
    'Actor identity, target resource, operation, result/status, request/correlation ID and timestamp from native audit logs.',
    'Record the mapping rationale; external framework pages do not replace provider audit evidence.'
   ]);
  } else {
   add('Capture and assess for this alert',[
    `Record the exact indicator/entity related to "${a.name}" and the lookup/report URL.`,
    'Capture verdict/reputation, supporting details, timestamps and relevant related indicators available from this service.',
    'Correlate results with the alert time, affected user/host/resource and native telemetry.',
    'Record checked time, evidence reference and any conflicting or unavailable results.',
    'Treat external enrichment as supporting context, not proof; validate before classifying or taking action.'
   ]);
  }
  return `<details class="osint-tool-details"><summary aria-label="Show what to capture from ${esc(o.name)}" title="What to capture and assess"><span>▾</span></summary><div class="osint-tool-guide"><b>${esc(o.name)} — what it is / when to use it</b><p class="osint-tool-definition">${esc(toolDefinition(o.name))}</p><b>${esc(out[0].label)}</b><ul>${out[0].items.map(x=>`<li>${esc(x)}</li>`).join('')}</ul><small>Capture only what is relevant to this alert. Store evidence in the case, and follow your organization's data-handling policy.</small></div></details>`;
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
 let visibleCount=15;
 function render(){
  const q=search.value.trim().toLowerCase(), c=cat.value, s=sev.value;
  const filtered=data.filter(a=>(!q||(a.name+' '+a.category+' '+a.overview).toLowerCase().includes(q))&&(!c||a.category===c)&&(!s||a.severity.startsWith(s)));
  const shown=filtered.slice(0,visibleCount);
  results.innerHTML=shown.map(a=>card(a)).join('')+(filtered.length>shown.length?`<div class="load-more-wrap"><button type="button" class="load-more-alerts">Load more alerts (${filtered.length-shown.length} remaining)</button></div>`:'');
  // Initialize every rendered alert query panel and bind its source tabs.
  results.querySelectorAll('.alert-card').forEach(cardEl=>{
   const alertData=data.find(item=>item.id===Number(cardEl.dataset.id));
   const selectedTool=cardEl.querySelector('[data-query-tool][aria-selected=true]');
   const selectedQuery=alertData&&selectedTool&&alertData.queries[Number(selectedTool.dataset.queryTool)];
   if(selectedQuery) renderPivots(cardEl,selectedQuery,0);
  });
  empty.hidden=filtered.length>0;
  const loadMore=results.querySelector('.load-more-alerts');if(loadMore)loadMore.addEventListener('click',()=>{visibleCount+=15;render()});

 }
 function renderPivots(card,qdata,index){
  const pivots=qdata.pivots||[{source:qdata.purpose||'Investigation query',query:qdata.query,note:qdata.note}];
  const i=Math.max(0,Math.min(index,pivots.length-1)), p=pivots[i];
  const pivotTabs=card.querySelector('.query-pivot-tabs');
  pivotTabs.innerHTML=pivots.map((pv,n)=>`<button type="button" data-query-pivot="${n}" aria-selected="${n===i?'true':'false'}">${esc(pv.source)}</button>`).join('');
  // Source-tab clicks are handled once by the parent results click handler.
  // Do not attach per-render listeners here: these buttons are recreated on every
  // selection and duplicate handlers can leave the label and query out of sync.
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

 function eventReferences(a,st){
  const text=(a.name+' '+a.category+' '+st.title+' '+st.check).toLowerCase();
  const cat=a.category||'';
  const refs=[];
  const add=(source,items,note)=>refs.push({source,items,note});
  if(/Identity & Authentication/.test(cat)){
   if(/failed|success|login|sign.?in|authenticat|password|brute|spray|account lock|disabled account/.test(text)){
    add('Windows Security',[
     ['4625','An account failed to log on'],
     ['4624','An account successfully logged on'],
     ['4740','A user account was locked out'],
     ['4776','Credential validation using NTLM']
    ],'Windows Security Event IDs; exact availability depends on audit policy and log collection.');
   }
   if(/privilege|service account|explicit credential|credential/.test(text)) add('Windows Security',[['4648','A logon was attempted using explicit credentials'],['4672','Special privileges assigned to a new logon']], 'Use alongside the authentication sequence and account context.');
   add('Microsoft Entra ID',['SigninLogs — cloud sign-in records','ResultType — sign-in result/error code; 0 indicates success','ConditionalAccessStatus / AuthenticationDetails — policy and MFA context'],'These are native table/field references, not Windows Event IDs. Check tenant schema and licensing.');
   if(/linux|ssh|unix/.test(text)) add('Linux authentication',['sshd/PAM authentication messages in journald, /var/log/auth.log or /var/log/secure'],'Native messages vary by distribution, syslog pipeline and audit configuration.');
  } else if(/Endpoint, Malware & EDR/.test(cat)){
   if(/process|powershell|command|script|parent.child|injection|living.off|credential|lsass/.test(text)) add('Windows / Sysmon process telemetry',[
    ['4688','A new process was created (Windows process creation auditing)'],
    ['Sysmon 1','Process creation, including configured command-line/parent fields'],
    ['Sysmon 10','Process access; relevant to some LSASS access investigations']
   ],'Sysmon IDs require Sysmon deployment and appropriate configuration; Windows 4688 needs process-creation auditing.');
   if(/file|malware|ransomware|quarantin|hash|dll|usb|archive/.test(text)) add('Windows / Sysmon file telemetry',[
    ['4663','An attempt was made to access an object (when object auditing is configured)'],
    ['Sysmon 11','File creation (if configured)'],
    ['Sysmon 7','Image/DLL loaded (if configured)']
   ],'These events do not independently prove malicious activity; correlate with EDR process/file evidence.');
   if(/registry|persistence|scheduled task|service|tamper|agent|security tool/.test(text)) add('Windows persistence / system telemetry',[
    ['4657','A registry value was modified (when registry auditing is configured)'],
    ['4698','A scheduled task was created'],
    ['4697 / System 7045','A service was installed (audit source and OS logging vary)']
   ],'Verify the relevant audit policy and actual event source.');
   add('Microsoft Defender XDR','DeviceProcessEvents / DeviceFileEvents / DeviceRegistryEvents / DeviceLogonEvents — endpoint activity tables','Table availability and fields depend on onboarding, retention and licensing.');
  } else if(/Network, Firewall, DNS & Proxy/.test(cat)){
   if(/dns|domain/.test(text)) add('DNS telemetry',['Sysmon 22 — DNS query (if Sysmon DNS logging is configured)','DNS analytical/server logs — query, client, response and timestamp'],'No universal DNS Event ID across all DNS products; use the source-native query/event fields.');
   if(/connection|traffic|firewall|port|scan|rdp|smb|network|exfiltrat/.test(text)) add('Windows network telemetry',[['5156','Windows Filtering Platform permitted a connection'],['5157','Windows Filtering Platform blocked a connection'],['Sysmon 3','Network connection (if configured)']], 'Windows Filtering Platform auditing and Sysmon configuration are prerequisites; firewall/vendor logs may use other schemas.');
   add('Network/security devices','Firewall, IDS/IPS, proxy, DNS and NetFlow records — source-native action, protocol, source/destination IP/port, bytes and rule ID','Vendor-specific event IDs and field names vary; use the product-native event type and rule/action fields.');
  } else if(/Email, Phishing & Collaboration/.test(cat)){
   add('Microsoft 365 / Defender for Office 365','EmailEvents, EmailAttachmentInfo, EmailUrlInfo, UrlClickEvents; Unified Audit Log operations relevant to mailbox, inbox rules, forwarding or OAuth consent','These are native tables/operation names, not Windows Event IDs; availability depends on workload, license and ingestion.');
   if(/rule|forward|mailbox|delete|purge|oauth|consent/.test(text)) add('Microsoft 365 audit operations',['New-InboxRule / Set-InboxRule / UpdateInboxRules (operation names vary by audit source)','MailItemsAccessed / message trace or workload-specific audit operations where available'],'Validate exact operation names against the tenant audit schema and time range.');
  } else if(/Cloud Security/.test(cat)){
   if(/aws/.test(text)) add('AWS CloudTrail',['eventName — API action','eventSource — service','userIdentity — caller context','responseElements / errorCode — outcome where recorded'],'AWS CloudTrail records are native API audit events, not Windows Event IDs.');
   if(/azure|microsoft 365|key vault|entra/.test(text)) add('Azure / Entra audit telemetry',['Azure Activity Log: operationName, caller, resourceId, status','AuditLogs: activity / targetResources / initiatedBy','AzureDiagnostics or resource-specific tables for service logs'],'Exact table depends on diagnostic settings and connector configuration.');
   if(/google cloud|gcp/.test(text)) add('Google Cloud Audit Logs',['methodName — API operation','principalEmail — actor','resourceName — target','status — outcome'],'Native audit fields vary by log type and service.');
   if(!/aws|azure|microsoft 365|key vault|entra|google cloud|gcp/.test(text)) add('Cloud audit telemetry',['Cloud provider audit event / API operation','Actor, target resource, operation, result and request/correlation ID'],'Select the provider-native audit source configured for this alert.');
  } else if(/Privilege Escalation & Persistence/.test(cat)){
   if(/group|admin|privilege|account created|membership/.test(text)) add('Windows Security',[
    ['4720','A user account was created'],
    ['4728','A member was added to a security-enabled global group'],
    ['4732','A member was added to a security-enabled local group'],
    ['4756','A member was added to a security-enabled universal group'],
    ['4672','Special privileges assigned to a new logon']
   ],'Event IDs depend on domain/local audit policy and source coverage.');
   if(/service|scheduled task|registry|wmi|persistence/.test(text)) add('Windows persistence events',[
    ['4697 / System 7045','A service was installed'],
    ['4698','A scheduled task was created'],
    ['4657','A registry value was modified, if registry auditing is configured'],
    ['Sysmon 19–21','WMI event filter/consumer/binding activity, if configured']
   ],'Not every event is enabled by default; validate auditing and EDR telemetry.');
   if(/kerberoast|kerberos|ticket|pass.the.hash/.test(text)) add('Windows authentication / Kerberos',[
    ['4768','A Kerberos authentication ticket (TGT) was requested'],
    ['4769','A Kerberos service ticket was requested'],
    ['4776','NTLM credential validation']
   ],'Interpret ticket events with account, encryption, volume and baseline context; event presence alone is not proof of abuse.');
   if(/linux|sudo/.test(text)) add('Linux privilege / persistence',['sudo/authentication journal records','auditd EXECVE/USER_CMD or relevant syscall records when configured','systemd journal/service unit changes or cron logs'],'Linux event identifiers and fields depend on auditd, journald and distribution configuration.');
  } else if(/Data Exfiltration & Insider Threat/.test(cat)){
   add('Data access / transfer telemetry',['File/object access audit records','Cloud storage audit operations and download/export events','DLP events and policy/action fields','Proxy/firewall/flow records: bytes, destination and time'],'Native event IDs depend on storage, OS, cloud, database and DLP product; correlate actor, object, volume and destination.');
   if(/email/.test(text)) add('Microsoft 365 mail audit',['EmailEvents / message trace','Unified Audit Log mailbox activity and forwarding operations'],'These are source-native records rather than Windows Event IDs.');
   if(/usb|removable/.test(text)) add('Windows removable media / file access',['4663 — object access attempt when auditing is configured','DeviceEvents / DeviceFileEvents — endpoint device/file telemetry when available'],'Confirm device control and object-access auditing are enabled.');
  } else if(/Vulnerability, Exposure & Security Configuration/.test(cat)){
   add('Vulnerability / configuration telemetry',['Scanner-native finding/plugin/CVE ID and asset evidence','Cloud configuration change/audit operation','Windows System/Security or endpoint inventory records when relevant'],'Most vulnerability findings do not have one universal OS Event ID; retain scanner/plugin ID, CVE, asset and observed configuration.');
   if(/tls|certificate/.test(text)) add('Certificate / TLS telemetry',['Certificate thumbprint/serial, issuer, validity dates and TLS handshake/scan result'],'Use scanner, certificate inventory and service logs; do not infer an OS Event ID where none exists.');
  } else if(/Security Tools, Logs & Detection Health/.test(cat)){
   add('SIEM / connector / audit health telemetry',['Connector/agent health status and last successful ingestion timestamp','Data collection rule / diagnostic setting / audit policy change records','Detection rule audit/change history and execution errors'],'These are platform-native health/audit records; there is no universal Windows Event ID for SIEM connector failures.');
   if(/windows|service|agent|tamper/.test(text)) add('Windows system telemetry',[['System 7036','A service entered a running/stopped state (service-specific interpretation required)'],['System 7040','A service start type was changed'],['Security 1102','The audit log was cleared']], 'Availability depends on OS version, audit settings and source collection.');
  } else if(/OT Security/.test(cat)){
   add('OT / ICS native telemetry',['PLC/engineering workstation vendor audit events: login, logic download, program/firmware/config change','Modbus function codes: read functions (e.g. 03/04) versus write functions (e.g. 05/06/0F/10); validate device/protocol context','DNP3 control/select-operate events and function/object details','OPC UA session, authentication, method/write and audit events'],'OT event identifiers are vendor/protocol-specific; function codes are protocol operations, not universal security Event IDs. Validate with passive telemetry and OT owner.');
   if(/authentication|login|access|vendor/.test(text)) add('OT identity / remote access',['HMI/engineering workstation authentication audit records','VPN/jump host/remote access gateway session and approval logs'],'No universal OT Event ID; use the specific vendor, gateway and Windows/Linux source records.');
  }
  if(!refs.length) add('Source-native event references',['Use the alert source’s event type, operation/action, result/status and correlation/request ID'],'No universal Event ID applies to every product. Confirm source, auditing prerequisites and actual schema.');
  return refs;
 }
 function eventReferenceMarkup(a,st){
  const refs=eventReferences(a,st);
  return `<div class="event-reference-panel"><strong>RELEVANT EVENT IDs / NATIVE EVENT TYPES &amp; MEANING</strong>${refs.map(r=>{
   const items=Array.isArray(r.items)?r.items:(r.items==null?[]:[r.items]);
   return `<div class="event-reference-source"><b>${esc(r.source||'Source-native telemetry')}</b><ul>${items.map(it=>{
    if(Array.isArray(it)) return `<li><code>${esc(it[0]??'Event')}</code> — ${esc(it[1]??'Meaning not specified; validate against source documentation.')}</li>`;
    if(it && typeof it==='object') return `<li>${esc(it.id??it.eventId??it.name??'Event')} — ${esc(it.meaning??it.description??it.label??JSON.stringify(it))}</li>`;
    return `<li>${esc(String(it))}</li>`;
   }).join('')}</ul><small>${esc(r.note||'Validate event availability and fields against the configured telemetry source.')}</small></div>`;
  }).join('')}</div>`;
 }
 
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
  const steps=a.steps.map(st=>{
   const title=st.title.replace(/[.]+$/,'');
   const past=title.replace(/^Review\b/i,'Reviewed').replace(/^Validate\b/i,'Validated').replace(/^Inspect\b/i,'Inspected').replace(/^Correlate\b/i,'Correlated').replace(/^Compare\b/i,'Compared').replace(/^Assess\b/i,'Assessed').replace(/^Determine\b/i,'Determined').replace(/^Recommend\b/i,'Recommended').replace(/^Check\b/i,'Checked').replace(/^Confirm\b/i,'Confirmed').replace(/^Investigate\b/i,'Investigated').replace(/^Identify\b/i,'Identified').replace(/^Examine\b/i,'Examined').replace(/^Verify\b/i,'Verified').replace(/^Analyze\b/i,'Analyzed').replace(/^Trace\b/i,'Traced').replace(/^Hunt\b/i,'Hunted').replace(/^Scope\b/i,'Scoped').replace(/^Classify\b/i,'Classified').replace(/^Look\b/i,'Looked').replace(/^Pivot\b/i,'Pivoted').replace(/^Establish\b/i,'Established').replace(/^Enrich\b/i,'Enriched').replace(/^Analyse\b/i,'Analysed').replace(/^Search\b/i,'Searched').replace(/^Quantify\b/i,'Quantified').replace(/^Measure\b/i,'Measured').replace(/^Test\b/i,'Tested').replace(/^Escalate\b/i,'Escalated').replace(/^Preserve\b/i,'Preserved').replace(/^Open\b/i,'Opened')
   return `${String(st.n).padStart(2,'0')}. ${past}\nThe investigation reviewed the alert-specific condition: ${st.check} Findings: [observed alert-specific results, including relevant event IDs/native event types and their meaning where available]. Supporting evidence was [source/table, event/operation ID, timestamp and correlation/reference]. Assessment: [what the evidence supports; confirmed / not observed in available telemetry / undetermined].`;
  }).join('\n\n');
  return `SAMPLE ANALYSIS & CLOSURE — ${a.name}\n\nAlert Definition / Trigger: ${a.overview} The alert was treated as an investigative signal, not proof of compromise by itself.\nAlert ID: [actual incident/alert ID]\nSeverity: [actual severity and evidence-based rationale; source severity if available]\nAffected Host/Resource: [confirmed host/resource or undetermined]\nAffected User/Account: [confirmed user/account or N/A]\nFirst Seen: [YYYY-MM-DD HH:MM:SS UTC]\nLast Seen: [YYYY-MM-DD HH:MM:SS UTC]\nDetection Source and Status: [actual product/rule/source; detected/blocked/quarantined/remediation failed; investigation status]\n\nINVESTIGATION FINDINGS\n${steps}\n\nSCOPE AND IMPACT\nAffected hosts/users/resources: [confirmed entities or none identified in reviewed telemetry]\nLateral movement / related activity: [specific evidence / not observed in available telemetry / undetermined, as relevant to this alert]\nData or resource access / business impact: [observed activity, impact and asset owner / not observed in available telemetry / undetermined]\n\nCONTAINMENT / REMEDIATION\nRecommended or completed actions: [action, operator/approver and timestamp; distinguish recommendation from action actually taken]\nAction status and validation: [completed/failed/pending/not required, with verification evidence]\nRecovery / follow-up: [owner, action and due date]\n\nClassification: [True Positive / Benign Positive / False Positive / Undetermined]\nRationale: [specific evidence supporting the disposition; include legitimate explanation where validated]\nEvidence references: [query names, source/table, event IDs/native operation names, raw logs, hashes or case links]\nTelemetry gaps / limitations: [missing source, audit prerequisite, retention gap, unavailable field or pending validation]\nResidual risk and next owner/action: [remaining risk, owner, action and due date]\n\nClosure summary: Based on [specific verified evidence], the ${a.name} alert was classified as [classification] for [affected entity] during [investigation time range]. The investigation established [concise factual findings tied to the steps above]. Response actions were [actions actually taken and verified, or pending actions]. Remaining risks or telemetry gaps were [details]. Follow-up owner/action/due date: [details].`;
 }
 function card(a){
  const refs=a.references.map(r=>`<a href="${esc(r[1])}" target="_blank" rel="noopener noreferrer">${esc(r[0])} ↗</a>`).join('');
  const steps=a.steps.map(st=>`<details class="step-panel"><summary><span>${String(st.n).padStart(2,'0')}</span>${esc(st.title)}</summary><div class="step-content"><p><strong>WHAT TO CHECK</strong><br>${esc(st.check)}</p><p><strong>FIELDS TO CAPTURE</strong><br>${esc(st.fields)}</p>${eventReferenceMarkup(a,st)}${stepQueryMarkup(a,st)}${(st.osint&&st.osint.length)||contextualTools(a,st).length?`<div class="osint-links"><strong>Useful tools for this investigation step</strong>${[...(st.osint||[]),...contextualTools(a,st)].filter((o,i,arr)=>arr.findIndex(x=>x.name===o.name)===i).map(o=>`<div class="osint-tool"><a href="${esc(o.url)}" target="_blank" rel="noopener noreferrer">${esc(o.name)} ↗</a>${toolEvidenceGuide(a,st,o)}</div>`).join('')}<small>Check the specific evidence relevant to this alert. Reputation and sandbox results are leads, not proof.</small></div>`:''}${quickLookupHtml(a,st)}</div></details>`).join('');
  const classes=Object.entries(a.classifications).map(([k,v])=>`<div class="classification-panel"><h4>${esc(k)}</h4><p><b>Recommendation</b><br>${esc(v.recommendation)}</p><p><b>Sample closure comment</b><br>${esc(v.closure)}</p><button class="copy-btn" data-close="${esc(k)}">Copy closure template</button></div>`).join('');
  const qs=a.queries.map((q,i)=>`<button type="button" data-query-tool="${i}" aria-selected="${i===0?'true':'false'}">${esc(q.tool)}</button>`).join('');
  const first=a.queries[0];
  return `<article class="alert-card" data-id="${a.id}"><details><summary class="alert-summary"><span class="alert-num">${String(a.id).padStart(3,'0')}</span><div class="alert-title-wrap"><div class="alert-title">${esc(a.name)}</div><div class="alert-meta">${esc(a.category)} · SOC L2 investigation reference</div></div><span class="alert-pill">Open SOP</span></summary><div class="alert-body"><section><h3>Alert overview</h3><p>${esc(a.overview)}</p><div class="overview-grid"><div class="mini-panel"><b>Severity guide</b>${esc(a.severity)}</div><div class="mini-panel"><b>Affected entities</b>${esc(a.entities)}</div><div class="mini-panel"><b>Investigation</b>${a.steps.length} structured steps</div></div><div class="alert-specific-recommendation"><h3>Alert-specific response guidance</h3><p>${esc(a.recommendation)}</p></div></section><section class="analysis-guide-section">${analysisGuide(a)}</section><section><h3>Investigation steps</h3><p class="muted">Open each step for WHAT TO CHECK, FIELDS TO CAPTURE, relevant tools and a tool-specific query/pivot. Consolidated sample analysis appears after all steps.</p><div class="investigation-steps">${steps}</div><section class="sample-analysis-final"><h3>Sample analysis & closure template</h3><p class="muted">Complete after reviewing all steps. Replace every bracketed placeholder with evidence for this alert; record “not observed in available telemetry” or “undetermined” where appropriate.</p><pre class="query-code final-analysis-template">${esc(sampleTemplate(a))}</pre><button type="button" class="copy-btn final-analysis-copy">Copy sample analysis template</button></section></section><section><h3>Detection & investigation query references</h3><p class="muted">These are starters, not guaranteed production detections. Adjust source, event filters, schema and time window for your deployment. Some vendor tabs provide pivot guidance rather than executable syntax.</p><div class="query-panel"><div class="query-tabs" role="tablist">${qs}</div><p class="muted">Select a tool first, then select the relevant table/data source below. Run one query at a time.</p><div class="query-pivot-tabs" role="tablist">${(first.pivots||[{source:first.purpose,query:first.query,note:first.note}]).map((p,i)=>`<button type="button" data-query-pivot="${i}" aria-selected="${i===0?'true':'false'}">${esc(p.source)}</button>`).join('')}</div><p class="query-language">${esc(first.language)} · ${esc((first.pivots&&first.pivots[0].source)||first.purpose)}</p><pre class="query-code">${esc((first.pivots&&first.pivots[0].query)||first.query)}</pre><p class="query-note">${esc((first.pivots&&first.pivots[0].note)||first.note)}</p><button class="copy-btn query-copy-btn">Copy query</button></div></section><section><h3>Classification & closure</h3><p class="muted">Choose the disposition supported by the available evidence. Recommendations and closure templates below are starting points—replace placeholders.</p><div class="classifications">${classes}</div></section><section><h3>Official documentation</h3><div class="reference-list">${refs}</div><p class="muted">Official docs are reference material; they do not prove the activity in your environment.</p></section></div></details></article>`;
 }
 search.addEventListener('input',()=>{visibleCount=15;render()});cat.addEventListener('change',()=>{visibleCount=15;render()});sev.addEventListener('change',()=>{visibleCount=15;render()});

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
 // Handle source/table tabs in the capture phase so other delegated click
 // handlers cannot leave the visual selection and query panel out of sync.
 document.addEventListener('click',e=>{
  const queryPivot=e.target.closest && e.target.closest('[data-query-pivot]');
  if(!queryPivot || !results.contains(queryPivot)) return;
  e.preventDefault();
  e.stopImmediatePropagation();
  const card=queryPivot.closest('.alert-card');
  const activeTool=card&&card.querySelector('[data-query-tool][aria-selected="true"]');
  const alert=card&&data.find(a=>a.id===Number(card.dataset.id));
  const qdata=alert&&activeTool&&alert.queries[Number(activeTool.dataset.queryTool)];
  const pivotIndex=Number(queryPivot.dataset.queryPivot);
  if(qdata && Number.isInteger(pivotIndex)) renderPivots(card,qdata,pivotIndex);
 }, true);

 results.addEventListener('click',e=>{
  const queryTool=e.target.closest('[data-query-tool]');
  if(queryTool){
   const card=queryTool.closest('.alert-card');
   const alert=card&&data.find(a=>a.id===Number(card.dataset.id));
   if(alert){
    card.querySelectorAll('[data-query-tool]').forEach(b=>b.setAttribute('aria-selected',String(b===queryTool)));
    const qdata=alert.queries[Number(queryTool.dataset.queryTool)];
    if(qdata) renderPivots(card,qdata,0);
   }
   return;
  }
  const queryCopy=e.target.closest('.query-copy-btn');
  if(queryCopy){
   const card=queryCopy.closest('.alert-card');
   const query=card?.querySelector('.query-code')?.textContent||'';
   navigator.clipboard?.writeText(query);
   queryCopy.textContent='Copied (if permitted)';
   setTimeout(()=>queryCopy.textContent='Copy query',1800);
   return;
  }
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
 results.addEventListener('toggle',e=>{
  const details=e.target;
  if(!(details instanceof HTMLDetailsElement)||!details.matches('.osint-tool-details')||!details.open)return;
  const step=details.closest('.step-content')||results;
  step.querySelectorAll('.osint-tool-details[open]').forEach(other=>{if(other!==details)other.open=false;});
  const summary=details.querySelector('summary'), panel=details.querySelector('.osint-tool-guide');
  if(!summary||!panel)return;
  panel.style.position='fixed';
  panel.style.right='auto';
  panel.style.bottom='auto';
  panel.style.left='12px';
  panel.style.top='12px';
  const r=summary.getBoundingClientRect();
  const vw=document.documentElement.clientWidth, vh=document.documentElement.clientHeight;
  const width=Math.min(420,vw-24);
  panel.style.width=width+'px';
  const left=Math.max(12,Math.min(r.right-width,vw-width-12));
  panel.style.left=left+'px';
  const measured=panel.getBoundingClientRect();
  let top=r.bottom+6;
  if(top+measured.height>vh-12) top=Math.max(12,r.top-measured.height-6);
  panel.style.top=top+'px';
 });
 results.addEventListener('scroll',()=>{},true);
 render();
})();
