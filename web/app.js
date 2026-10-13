const $ = id => document.getElementById(id);
let selected = null, connected = false, polling = null, loginPolling = null;
const example = "\"\"\"Fixture didática. Nunca execute. Não contém credenciais reais.\"\"\"\nimport os\nfrom flask import request\n\npassword = \"demo-only-password\"\n\n\ndef search(cursor):\n    term = request.args.get(\"q\")\n    query = f\"SELECT * FROM users WHERE name = '{term}'\"\n    cursor.execute(query)\n    os.system(\"echo \" + term)\n    return eval(term)\n";
function notice(message) { $('notice').textContent = message; $('notice').hidden = !message; }
async function api(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { 'Content-Type': 'application/json', 'X-SAST-Client': 'dashboard', ...options.headers } });
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Verifique os campos e os limites dos arquivos.');
  return data;
}
function element(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
function badge(text) { return element('span', text, 'badge ' + text); }
const date = value => new Date(value).toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
async function refresh() {
  const [history, metrics] = await Promise.all([api('/api/scans'), api('/api/metrics')]);
  $('total').textContent = Object.values(metrics.severity).reduce((a,b) => a+b, 0);
  $('high').textContent = (metrics.severity.HIGH || 0) + (metrics.severity.CRITICAL || 0);
  $('medium').textContent = metrics.severity.MEDIUM || 0;
  $('scan-count').textContent = metrics.scans;
  $('history-body').replaceChildren(); $('history-empty').hidden = history.length > 0;
  for (const scan of history) {
    const row = element('tr'); row.append(element('td', scan.project), element('td', date(scan.created)));
    for (const status of [scan.status, scan.result.gate || 'PENDING']) { const cell = element('td'); cell.append(badge(status)); row.append(cell); }
    row.append(element('td', scan.result.findings?.length ?? '—'));
    const action = element('td'), button = element('button', 'Ver relatório →', 'text-button');
    button.addEventListener('click', () => openReport(scan.id).catch(e => notice(e.message))); action.append(button); row.append(action); $('history-body').append(row);
  }
  $('trend').replaceChildren();
  const trend = metrics.trend.slice(-8);
  if (!trend.length) $('trend').append(element('p','Execute uma análise para iniciar o histórico.','empty'));
  trend.reverse().forEach((item,index) => {
    const row = element('div',undefined,'activity-row'), indexNode = element('span',String(index + 1).padStart(2,'0'),'activity-index'), info = element('div',undefined,'activity-info');
    info.append(element('strong',item.project),element('small',(item.scan_type === 'website' ? 'WEB' : 'CODE') + '  /  ' + date(item.created)));
    const gate = badge(item.gate), count = element('span',item.count + (item.count === 1 ? ' achado' : ' achados'),'activity-count');
    row.append(indexNode,info,gate,count); $('trend').append(row);
  });
  $('critical').replaceChildren();
  if (!metrics.critical_files.length) $('critical').append(element('p','Nenhum arquivo crítico identificado.','empty'));
  for (const [file, count] of metrics.critical_files) { const row = element('div',undefined,'critical-row'); row.append(element('code',file),element('span',count + ' achados','badge HIGH')); $('critical').append(row); }
}
async function openReport(id, scroll = true) {
  selected = await api('/api/scans/' + id); $('results').hidden = false; renderReport();
  if (scroll) $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
async function trackScan(scan) {
  notice('Análise enviada. Aguardando processamento…'); await refresh();
  clearInterval(polling); let attempts = 0;
  polling = setInterval(async () => {
    try {
      const item = await api('/api/scans/' + scan.id);
      if (['COMPLETED','FAILED'].includes(item.status)) {
        clearInterval(polling); notice(item.status === 'COMPLETED' ? 'Análise concluída. Relatório disponível em JSON e SARIF.' : 'O processamento falhou. Veja o relatório.');
        await refresh(); await openReport(scan.id);
      } else if (++attempts >= 90) { clearInterval(polling); notice('A análise ainda está em fila. Atualize o histórico em alguns instantes.'); }
    } catch(e) { clearInterval(polling); notice(e.message); }
  },1500);
}
function showAi(container, ai) {
  const box = element('div',undefined,'ai-review');
  box.append(element('strong','Revisão Codex · severidade sugerida: ' + ai.severity), element('p',ai.explanation), element('p',ai.remediation));
  if (ai.possible_false_positive) box.append(element('p','Possível falso positivo: confirme manualmente. O Gate original foi preservado.'));
  box.append(element('pre',ai.corrected_code),element('p','Sugestão não executada nem aplicada. Revise e teste antes de usar.')); container.append(box);
}
function renderReport() {
  if (!selected) return;
  $('result-title').textContent = selected.project + ' · ' + (selected.result.gate || selected.status);
  $('findings').replaceChildren();
  for (const error of selected.result.errors || []) $('findings').append(element('p',(error.file || '') + ': ' + error.message,'muted'));
  const all = selected.result.findings || [], findings = all.filter(f => !$('severity-filter').value || f.severity === $('severity-filter').value);
  if (!findings.length) $('findings').append(element('p',selected.status === 'COMPLETED' ? 'Nenhum achado neste filtro. Ausência de achados não garante ausência de vulnerabilidades.' : 'A análise ainda não está concluída. Atualize em alguns instantes.','empty'));
  for (const finding of findings) {
    const card = element('article',undefined,'finding'), head = element('div',undefined,'finding-head');
    head.append(badge(finding.severity),element('h3',finding.title)); card.append(head);
    card.append(element('p',finding.file + ':' + finding.line + ' · ' + finding.rule + ' · ' + finding.cwe + ' · confiança ' + finding.confidence));
    card.append(element('p',finding.remediation));
    if (finding.trace.length) card.append(element('div',finding.trace.join('\n↓ '),'trace'));
    const button = element('button','Revisar com Codex ↗','text-button'); button.disabled = !connected; button.title = connected ? 'Envia ao Codex somente o achado e o contexto sanitizado.' : 'Conecte sua conta primeiro.';
    button.addEventListener('click', async () => { button.disabled = true; button.textContent = 'Codex está revisando…'; try { await api('/api/scans/' + selected.id + '/review/' + finding.fingerprint,{method:'POST',body:'{}'}); await openReport(selected.id,false); } catch(e) { notice(e.message); button.disabled = false; button.textContent = 'Tentar revisão novamente'; } });
    card.append(button); if (finding.ai) showAi(card,finding.ai); $('findings').append(card);
  }
}
async function account() {
  try {
    const state = await api('/api/codex/account'); connected = state.connected;
    $('account-status').textContent = connected ? '● Conta conectada' : state.loginPending ? '○ Aguardando login no navegador…' : state.lastLogin?.error || '○ Conta não conectada';
    $('connect').hidden = connected; $('connect').disabled = Boolean(state.loginPending); $('disconnect').hidden = !connected;
    if (connected || state.lastLogin?.success === false) { clearInterval(loginPolling); loginPolling = null; $('login-box').hidden = true; }
  } catch { connected = false; $('account-status').textContent = '○ Integração indisponível · inicie o serviço Codex'; $('connect').hidden = false; $('connect').disabled = false; $('disconnect').hidden = true; }
  if (selected) renderReport();
}
$('connect').addEventListener('click', async () => {
  $('connect').disabled = true; notice('');
  try {
    const login = await api('/api/codex/login',{method:'POST',body:'{}'});
    const url = new URL(login.verificationUrl); if (url.protocol !== 'https:' || url.hostname !== 'auth.openai.com') throw new Error('Link de login inválido.');
    $('user-code').textContent = login.userCode; $('login-link').href = url.href; $('login-box').hidden = false;
    $('account-status').textContent = '○ Aguardando login no navegador…';
    clearInterval(loginPolling); let attempts = 0; loginPolling = setInterval(() => { account(); if (++attempts >= 200) { clearInterval(loginPolling); loginPolling = null; notice('Tempo de acompanhamento encerrado. Atualize o status da conta.'); } },3000);
  } catch(e) { notice(e.message); $('connect').disabled = false; }
});
$('disconnect').addEventListener('click',async () => { try { await api('/api/codex/logout',{method:'POST',body:'{}'}); await account(); } catch(e) { notice(e.message); } });
$('mode-code').addEventListener('click',() => { $('mode-code').classList.add('active'); $('mode-site').classList.remove('active'); $('scan-form').hidden = false; $('site-form').hidden = true; });
$('mode-site').addEventListener('click',() => { $('mode-site').classList.add('active'); $('mode-code').classList.remove('active'); $('site-form').hidden = false; $('scan-form').hidden = true; });
$('example').addEventListener('click',() => { $('source').value = example; $('files').value = ''; $('file-summary').textContent = 'Exemplo didático vulnerável: nunca execute este código.'; });
$('files').addEventListener('change',() => { $('file-summary').textContent = $('files').files.length ? $('files').files.length + ' arquivo(s) selecionado(s). O texto colado será ignorado.' : 'Uploads podem misturar linguagens em uma única análise.'; });
$('scan-form').addEventListener('submit',async event => {
  event.preventDefault(); $('scan-button').disabled = true; notice('');
  try {
    let files = {}, total = 0;
    if ($('files').files.length > 100) throw new Error('Limite de 100 arquivos.');
    const allowed = ['.py','.js','.jsx','.ts','.tsx','.java','.php','.go','.cs','.rb'];
    for (const file of $('files').files) { if (!allowed.some(ext => file.name.toLowerCase().endsWith(ext)) || file.size > 100000) throw new Error('Use apenas linguagens suportadas e arquivos de até 100 KB.'); if (Object.hasOwn(files,file.name)) throw new Error('Há arquivos com nomes duplicados.'); total += file.size; if (total > 1000000) throw new Error('Limite total de 1 MB.'); files[file.name] = await file.text(); }
    if (!Object.keys(files).length) { if (!$('source').value.trim()) throw new Error('Cole código ou selecione arquivos do projeto.'); files = { ['main' + $('language').value]: $('source').value }; }
    const scan = await api('/api/scans',{method:'POST',body:JSON.stringify({project:$('project').value.trim(),files})});
    await trackScan(scan);
  } catch(e) { notice(e.message); } finally { $('scan-button').disabled = false; }
});
$('site-form').addEventListener('submit',async event => {
  event.preventDefault(); $('site-button').disabled = true; notice('');
  try {
    const scan = await api('/api/site-scans',{method:'POST',body:JSON.stringify({project:$('site-project').value.trim(),url:$('site-url').value.trim()})});
    await trackScan(scan);
  } catch(e) { notice(e.message); } finally { $('site-button').disabled = false; }
});
$('severity-filter').addEventListener('change',renderReport);
$('refresh').addEventListener('click',() => Promise.all([refresh(),account()]).catch(e => notice(e.message)));
$('download').addEventListener('click',() => { if (!selected) return; const url = URL.createObjectURL(new Blob([JSON.stringify(selected,null,2)],{type:'application/json'})); const a = element('a'); a.href = url; a.download = 'sentinela-' + selected.id + '.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url),1000); });
$('download-sarif').addEventListener('click',() => {
  if (!selected) return;
  const findings = selected.result.findings || [], rules = [...new Map(findings.map(f => [f.rule,{id:f.rule,name:f.title,shortDescription:{text:f.title},help:{text:f.remediation}}])).values()];
  const sarif = {version:'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json',runs:[{tool:{driver:{name:'NULL//SENTRY',informationUri:location.origin,rules}},results:findings.map(f => ({ruleId:f.rule,level:['CRITICAL','HIGH'].includes(f.severity)?'error':f.severity==='MEDIUM'?'warning':'note',message:{text:f.title + '. ' + f.remediation},locations:[{physicalLocation:{artifactLocation:{uri:f.file},region:{startLine:f.line||1,startColumn:f.column||1}}}],fingerprints:{'null-sentry/v1':f.fingerprint}}))}]};
  const url = URL.createObjectURL(new Blob([JSON.stringify(sarif,null,2)],{type:'application/sarif+json'})); const a = element('a'); a.href = url; a.download = 'sentinela-' + selected.id + '.sarif'; a.click(); setTimeout(() => URL.revokeObjectURL(url),1000);
});
$('download-pdf').addEventListener('click',async () => {
  if (!selected) return; const button = $('download-pdf'); button.disabled = true; button.textContent = 'CODEX GERANDO…'; notice('Gerando resumo executivo e PDF…');
  try { await api('/api/scans/' + selected.id + '/ai-report',{method:'POST',body:'{}'}); const a=element('a'); a.href='/api/scans/' + selected.id + '/report.pdf'; a.download='null-sentry-' + selected.id + '.pdf'; a.click(); notice('Relatório executivo PDF gerado.'); await openReport(selected.id,false); }
  catch(e){ notice(e.message); } finally { button.disabled=false; button.textContent='PDF + CODEX ↓'; }
});
refresh().catch(e => notice(e.message)); account();
