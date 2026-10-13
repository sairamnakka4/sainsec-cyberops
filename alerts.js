
(function(){
 const data=window.SAINSEC_ALERTS||[], results=document.getElementById('alert-results'), search=document.getElementById('alert-search'), cat=document.getElementById('category-filter'), sev=document.getElementById('severity-filter'), empty=document.getElementById('empty-state');
 const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 [...new Set(data.map(a=>a.category))].forEach(c=>{let o=document.createElement('option');o.value=c;o.textContent=c;cat.appendChild(o)});
 document.getElementById('total-count').textContent=data.length;
 function render(){
  const q=search.value.trim().toLowerCase(), c=cat.value, s=sev.value;
  const filtered=data.filter(a=>(!q||(a.name+' '+a.category+' '+a.overview).toLowerCase().includes(q))&&(!c||a.category===c)&&(!s||a.severity.startsWith(s)));
  results.innerHTML=filtered.map(a=>card(a)).join('');empty.hidden=filtered.length>0;
  results.querySelectorAll('[data-query-tool]').forEach(btn=>btn.addEventListener('click',()=>{
   const card=btn.closest('.alert-card'), idx=Number(btn.dataset.queryTool), alert=data.find(a=>a.id===Number(card.dataset.id));
   card.querySelectorAll('[data-query-tool]').forEach(b=>b.setAttribute('aria-selected',String(b===btn)));
   const qdata=alert.queries[idx];card.querySelector('.query-code').textContent=qdata.query;
   card.querySelector('.query-language').textContent=qdata.language+' · '+qdata.purpose;
   card.querySelector('.query-note').textContent=qdata.note;
   card.querySelector('.copy-btn').onclick=()=>navigator.clipboard?.writeText(qdata.query);
  }));
  results.querySelectorAll('.copy-btn').forEach(btn=>{const card=btn.closest('.alert-card');const alert=data.find(a=>a.id===Number(card.dataset.id));btn.onclick=()=>{const active=card.querySelector('[data-query-tool][aria-selected=true]');navigator.clipboard?.writeText(alert.queries[Number(active.dataset.queryTool)].query);btn.textContent='Copied (if clipboard permission granted)';setTimeout(()=>btn.textContent='Copy query',1800)}});
 }
 function card(a){
  const refs=a.references.map(r=>`<a href="${esc(r[1])}" target="_blank" rel="noopener noreferrer">${esc(r[0])} ↗</a>`).join('');
  const steps=a.steps.map(st=>`<details class="step-panel"><summary><span>${String(st.n).padStart(2,'0')}</span>${esc(st.title)}</summary><div class="step-content"><p><strong>WHAT TO CHECK</strong><br>${esc(st.check)}</p><p><strong>FIELDS TO CAPTURE</strong><br>${esc(st.fields)}</p><p><strong>SAMPLE ANALYSIS</strong><br>${esc(st.analysis)}</p><p class="muted">Replace bracketed values with actual evidence. Do not present an unverified value as a finding.</p></div></details>`).join('');
  const classes=Object.entries(a.classifications).map(([k,v])=>`<div class="classification-panel"><h4>${esc(k)}</h4><p><b>Recommendation</b><br>${esc(v.recommendation)}</p><p><b>Sample closure comment</b><br>${esc(v.closure)}</p><button class="copy-btn" data-close="${esc(k)}">Copy closure template</button></div>`).join('');
  const qs=a.queries.map((q,i)=>`<button type="button" data-query-tool="${i}" aria-selected="${i===0?'true':'false'}">${esc(q.tool)}</button>`).join('');
  const first=a.queries[0];
  return `<article class="alert-card" data-id="${a.id}"><details><summary class="alert-summary"><span class="alert-num">${String(a.id).padStart(3,'0')}</span><div class="alert-title-wrap"><div class="alert-title">${esc(a.name)}</div><div class="alert-meta">${esc(a.category)} · SOC L2 investigation reference</div></div><span class="alert-pill">Open SOP</span></summary><div class="alert-body"><section><h3>Alert overview</h3><p>${esc(a.overview)}</p><div class="overview-grid"><div class="mini-panel"><b>Severity guide</b>${esc(a.severity)}</div><div class="mini-panel"><b>Affected entities</b>${esc(a.entities)}</div><div class="mini-panel"><b>Investigation</b>${a.steps.length} structured steps</div></div></section><section><h3>Investigation steps</h3><p class="muted">Open each step for the analyst action, evidence fields and sample analysis.</p><div class="investigation-steps">${steps}</div></section><section><h3>Detection & investigation query references</h3><p class="muted">These are starters, not guaranteed production detections. Adjust source, event filters, schema and time window for your deployment. Some vendor tabs provide pivot guidance rather than executable syntax.</p><div class="query-panel"><div class="query-tabs" role="tablist">${qs}</div><p class="query-language">${esc(first.language)} · ${esc(first.purpose)}</p><pre class="query-code">${esc(first.query)}</pre><p class="query-note">${esc(first.note)}</p><button class="copy-btn">Copy query</button></div></section><section><h3>Official documentation</h3><div class="reference-list">${refs}</div><p class="muted">Official docs are reference material; they do not prove the activity in your environment.</p></section><section><h3>Classification & closure</h3><p class="muted">Choose the disposition supported by the available evidence. Recommendations and closure templates below are starting points—replace placeholders.</p><div class="classifications">${classes}</div></section></div></details></article>`;
 }
 search.addEventListener('input',render);cat.addEventListener('change',render);sev.addEventListener('change',render);
 results.addEventListener('click',e=>{const b=e.target.closest('[data-close]');if(!b)return;const article=b.closest('.alert-card'),a=data.find(x=>x.id===Number(article.dataset.id));const text=a.classifications[b.dataset.close].closure;navigator.clipboard?.writeText(text);b.textContent='Copied (if permitted)';setTimeout(()=>b.textContent='Copy closure template',1800)});
 render();
})();
