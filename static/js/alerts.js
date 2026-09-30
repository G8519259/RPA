// P12 —— 告警中心前端（渠道 / 规则 / 事件历史 三个标签页）
let ALERT_EVENT_TYPES = []; // [{event_type, name, default_params}]
let ALERT_CHANNELS = [];    // [{id, name, kind}]
let evPage = 1;

function initAlerts(){
  switchTab('channels');
  loadEventTypes();
}

function switchTab(t){
  document.querySelectorAll('#tab-channels,#tab-rules,#tab-events').forEach(d => d.style.display = 'none');
  document.getElementById('tab-'+t).style.display = '';
  document.querySelectorAll('.tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === t));
  if (t === 'channels') loadChannels();
  if (t === 'rules') loadRules();
  if (t === 'events') loadEvents();
}

async function loadEventTypes(){
  try {
    const r = await api('GET', '/api/alerts/rules');
    ALERT_EVENT_TYPES = r.data.event_types || [];
    const sel = document.getElementById('ev-type');
    sel.innerHTML = '<option value="">全部类型</option>' + ALERT_EVENT_TYPES.map(e =>
      `<option value="${e.event_type}">${esc(e.name)} (${e.event_type})</option>`).join('');
  } catch(e){}
}

// ============ 渠道 ============

function channelFormHtml(kind, cfg){
  cfg = cfg || {};
  if (kind === 'telegram') return `
    <div class="form-row"><label>Bot Token</label><input id="f-bot_token" value="${esc(cfg.bot_token||'')}" placeholder="123456:ABC..."></div>
    <div class="form-row"><label>Chat ID</label><input id="f-chat_id" value="${esc(cfg.chat_id||'')}" placeholder="-1001234567890"></div>
    <div class="form-row"><label>代理（可选）</label><input id="f-proxy" value="${esc(cfg.proxy||'')}" placeholder="socks5://127.0.0.1:1080"></div>`;
  if (kind === 'webhook') return `
    <div class="form-row"><label>URL</label><input id="f-url" value="${esc(cfg.url||'')}" placeholder="https://example.com/hook"></div>
    <div class="form-row"><label>签名密钥（可选，用于 X-RPA-Signature 验签）</label><input id="f-secret" value="${esc(cfg.secret||'')}" placeholder="留空不签名"></div>
    <div class="form-row"><label>自定义请求头（可选，JSON）</label><input id="f-headers" value="${esc(cfg.headers ? JSON.stringify(cfg.headers) : '')}" placeholder='{"X-Token":"abc"}'></div>`;
  if (kind === 'email') return `
    <div class="form-row"><label>SMTP 服务器</label><input id="f-host" value="${esc(cfg.host||'')}" placeholder="smtp.example.com"></div>
    <div class="form-row"><label>端口 / 加密</label><div style="display:flex;gap:8px"><input id="f-port" type="number" value="${esc(cfg.port||587)}"><select id="f-tls"><option value="starttls">STARTTLS</option><option value="plain">明文</option></select></div></div>
    <div class="form-row"><label>用户名（可选）</label><input id="f-username" value="${esc(cfg.username||'')}" placeholder="user"></div>
    <div class="form-row"><label>密码（可选）</label><input id="f-password" type="password" value="${esc(cfg.password||'')}" placeholder="留空则回传 ****** 表示不改"></div>
    <div class="form-row"><label>发件人</label><input id="f-from" value="${esc(cfg.from||'')}" placeholder="rpa@example.com"></div>
    <div class="form-row"><label>收件人（每行一个）</label><textarea id="f-to" rows="3">${esc((cfg.to||[]).join('\n'))}</textarea></div>`;
  return '';
}

function collectChannelCfg(kind){
  const v = id => document.getElementById(id).value.trim();
  if (kind === 'telegram') return { bot_token: v('f-bot_token'), chat_id: v('f-chat_id'), proxy: v('f-proxy') };
  if (kind === 'webhook') {
    let headers = {};
    try { if (v('f-headers')) headers = JSON.parse(v('f-headers')); } catch(e){ toast('请求头 JSON 格式错误', true); return null; }
    return { url: v('f-url'), secret: v('f-secret'), headers };
  }
  if (kind === 'email') return {
    host: v('f-host'), port: parseInt(v('f-port'))||587, tls: document.getElementById('f-tls').value,
    username: v('f-username'), password: v('f-password'), from: v('f-from'),
    to: v('f-to').split('\n').map(s=>s.trim()).filter(Boolean),
  };
  return null;
}

async function loadChannels(){
  try {
    const r = await api('GET', '/api/alerts/channels');
    const items = r.data || [];
    ALERT_CHANNELS = items;
    document.getElementById('ch-rows').innerHTML = items.map(c => {
      let cfg = '';
      const cf = c.config || {};
      if (c.kind === 'telegram') cfg = `chat_id=${esc(cf.chat_id||'-')}`;
      else if (c.kind === 'webhook') cfg = esc(cf.url||'-');
      else if (c.kind === 'email') cfg = `${esc(cf.host||'-')}:${esc(cf.port||'')} → ${esc((cf.to||[]).join(', '))}`;
      return `<tr><td>${esc(c.name)}</td><td>${esc(c.kind)}</td><td class="muted" style="max-width:320px;overflow:hidden;text-overflow:ellipsis">${cfg}</td>
        <td>${c.enabled ? '<span class="badge ok">启用</span>' : '<span class="badge">停用</span>'}</td>
        <td>
          ${IS_VIEWER ? '' : `
          <button class="btn btn-sm" onclick="testChannel(${c.id})">发送测试</button>
          <button class="btn btn-sm" onclick='editChannel(${c.id})'>编辑</button>
          <button class="btn btn-sm btn-danger" onclick="delChannel(${c.id})">删除</button>`}
        </td></tr>`;
    }).join('') || '<tr><td colspan="5" class="muted">暂无渠道，点击"新建渠道"添加</td></tr>';
  } catch(e){ toast('加载渠道失败：'+e.message, true); }
}

async function editChannel(id){
  const ch = id ? ALERT_CHANNELS.find(c => c.id === id) : null;
  const kind = ch ? ch.kind : 'telegram';
  const kinds = ['telegram','webhook','email'];
  openModal(id ? '编辑渠道' : '新建渠道', `
    <div class="form-row"><label>名称</label><input id="f-name" value="${esc(ch?ch.name:'')}"></div>
    <div class="form-row"><label>类型</label><select id="f-kind" ${id?'disabled':''}>${kinds.map(k=>`<option value="${k}" ${k===kind?'selected':''}>${k}</option>`).join('')}</select></div>
    <div id="ch-form">${channelFormHtml(kind, ch ? ch.config : {})}</div>
    <div class="form-row"><label>状态</label><select id="f-enabled"><option value="1" ${(ch?ch.enabled:1)?'selected':''}>启用</option><option value="0" ${ch&&!ch.enabled?'selected':''}>停用</option></select></div>
  `, async () => {
    const name = document.getElementById('f-name').value.trim();
    if (!name) { toast('名称不能为空', true); return false; }
    const cfg = collectChannelCfg(document.getElementById('f-kind').value);
    if (!cfg) return false;
    try {
      if (id) await api('PUT', '/api/alerts/channels/'+id, { name, kind: ch.kind, config: cfg, enabled: parseInt(document.getElementById('f-enabled').value) });
      else await api('POST', '/api/alerts/channels', { name, kind: document.getElementById('f-kind').value, config: cfg, enabled: parseInt(document.getElementById('f-enabled').value) });
      toast(id ? '已更新' : '已创建'); loadChannels();
    } catch(e){ toast('保存失败：'+e.message, true); return false; }
  });
  document.getElementById('f-kind').onchange = e => {
    document.getElementById('ch-form').innerHTML = channelFormHtml(e.target.value, {});
  };
}

async function testChannel(id){
  try {
    await api('POST', `/api/alerts/channels/${id}/test`);
    toast('测试消息已发送');
  } catch(e){ toast('测试发送失败：'+e.message, true); }
}

function delChannel(id){
  confirmDo('删除该渠道？已绑定到规则的会被自动移除。', async () => {
    try { await api('DELETE', '/api/alerts/channels/'+id); toast('已删除'); loadChannels(); }
    catch(e){ toast('删除失败：'+e.message, true); }
  }, '删除');
}

// ============ 规则 ============

async function loadRules(){
  try {
    const r = await api('GET', '/api/alerts/rules');
    const items = r.data.items || [];
    const nameOf = id => { const c = ALERT_CHANNELS.find(x => x.id === id); return c ? esc(c.name) : '#'+id; };
    document.getElementById('ru-rows').innerHTML = items.map(ru => {
      const et = ALERT_EVENT_TYPES.find(e => e.event_type === ru.event_type);
      const params = JSON.stringify(ru.params);
      const chs = (ru.channel_ids||[]).map(nameOf).join('、') || '<span class="muted">未绑定渠道</span>';
      return `<tr><td>${esc(ru.name)}</td>
        <td>${esc(et?et.name:ru.event_type)} <span class="muted">${esc(ru.event_type)}</span></td>
        <td class="muted" style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc(params)}</td>
        <td>${chs}</td>
        <td>${ru.cooldown_secs}s</td>
        <td>${ru.enabled ? '<span class="badge ok">启用</span>' : '<span class="badge">停用</span>'}</td>
        <td>
          ${IS_VIEWER ? '' : `
          <button class="btn btn-sm" onclick="toggleRule(${ru.id})">${ru.enabled?'停用':'启用'}</button>
          <button class="btn btn-sm" onclick='editRule(${ru.id})'>编辑</button>
          <button class="btn btn-sm btn-danger" onclick="delRule(${ru.id})">删除</button>`}
        </td></tr>`;
    }).join('') || '<tr><td colspan="7" class="muted">暂无规则</td></tr>';
  } catch(e){ toast('加载规则失败：'+e.message, true); }
}

let RULE_CACHE = [];
async function editRule(id){
  const r = id ? (await api('GET', '/api/alerts/rules')).data.items.find(x => x.id === id) : null;
  if (id && !r) return;
  const et = ALERT_EVENT_TYPES.find(e => e.event_type === (r ? r.event_type : 'node_offline'));
  openModal(id ? '编辑规则' : '新建规则', `
    <div class="form-row"><label>名称</label><input id="f-name" value="${esc(r?r.name:'')}"></div>
    <div class="form-row"><label>事件类型</label><select id="f-event_type">${ALERT_EVENT_TYPES.map(e=>`<option value="${e.event_type}" ${e.event_type===(r?r.event_type:'node_offline')?'selected':''}>${esc(e.name)} (${e.event_type})</option>`).join('')}</select></div>
    <div class="form-row"><label>阈值参数（JSON）</label><input id="f-params" value='${esc(r ? JSON.stringify(r.params) : et.default_params)}'></div>
    <div class="form-row"><label>绑定渠道（多选）</label><div>${ALERT_CHANNELS.map(c=>`<label style="margin-right:12px"><input type="checkbox" class="f-ch" value="${c.id}" ${r&&r.channel_ids.includes(c.id)?'checked':''} style="width:auto"> ${esc(c.name)}</label>`).join('') || '<span class="muted">暂无渠道</span>'}</div></div>
    <div class="form-row"><label>冷却（秒，同一规则同一事件窗口内去重）</label><input id="f-cooldown" type="number" value="${r?r.cooldown_secs:3600}"></div>
    <div class="form-row"><label>状态</label><select id="f-enabled"><option value="1" ${(r?r.enabled:1)?'selected':''}>启用</option><option value="0" ${r&&!r.enabled?'selected':''}>停用</option></select></div>
  `, async () => {
    const name = document.getElementById('f-name').value.trim();
    if (!name) { toast('名称不能为空', true); return false; }
    let params = {};
    try { params = JSON.parse(document.getElementById('f-params').value || '{}'); }
    catch(e){ toast('参数 JSON 格式错误', true); return false; }
    const channel_ids = [...document.querySelectorAll('.f-ch:checked')].map(el => parseInt(el.value));
    const payload = { name, event_type: document.getElementById('f-event_type').value, params, channel_ids,
      cooldown_secs: parseInt(document.getElementById('f-cooldown').value)||0, enabled: parseInt(document.getElementById('f-enabled').value) };
    try {
      if (id) await api('PUT', '/api/alerts/rules/'+id, payload);
      else await api('POST', '/api/alerts/rules', payload);
      toast(id ? '已更新' : '已创建'); loadRules();
    } catch(e){ toast('保存失败：'+e.message, true); return false; }
  });
  document.getElementById('f-event_type').onchange = e => {
    const t = ALERT_EVENT_TYPES.find(x => x.event_type === e.target.value);
    if (t) document.getElementById('f-params').value = t.default_params;
  };
}

async function toggleRule(id){
  try { await api('POST', `/api/alerts/rules/${id}/toggle`); loadRules(); }
  catch(e){ toast('操作失败：'+e.message, true); }
}

function delRule(id){
  confirmDo('删除该规则？', async () => {
    try { await api('DELETE', '/api/alerts/rules/'+id); toast('已删除'); loadRules(); }
    catch(e){ toast('删除失败：'+e.message, true); }
  }, '删除');
}

// ============ 事件历史 ============

const SEV = { info: '<span class="badge">ℹ info</span>', warning: '<span class="badge warn">⚠ warning</span>', critical: '<span class="badge danger">🔴 critical</span>' };
const EST = { pending: '<span class="badge warn">待发送</span>', sent: '<span class="badge ok">已发送</span>', failed: '<span class="badge danger">失败</span>' };

async function loadEvents(){
  try {
    const qs = `page=${evPage}&page_size=20&status=${document.getElementById('ev-status').value}&event_type=${document.getElementById('ev-type').value}`;
    const r = await api('GET', '/api/alerts/events?'+qs);
    const d = r.data;
    document.getElementById('ev-rows').innerHTML = d.items.map(e =>
      `<tr><td class="muted">${esc(e.created_at)}</td><td>${esc(e.event_type)}</td>
       <td style="max-width:280px"><b>${esc(e.title)}</b><div class="muted">${esc(e.body).slice(0,120)}</div></td>
       <td>${SEV[e.severity]||esc(e.severity)}</td><td>${EST[e.status]||esc(e.status)}</td>
       <td>${e.attempts}</td><td class="muted" style="max-width:200px">${esc(e.last_error||'-')}</td>
       <td>${(e.status==='failed' && !IS_VIEWER) ? `<button class="btn btn-sm" onclick="retryEvent(${e.id})">重试</button>` : ''}</td></tr>`
    ).join('') || '<tr><td colspan="8" class="muted">暂无事件</td></tr>';
    const pages = Math.max(1, Math.ceil(d.total / d.page_size));
    document.getElementById('ev-pager').innerHTML =
      `共 ${d.total} 条 <button class="btn btn-sm" ${evPage<=1?'disabled':''} onclick="evPage--;loadEvents()">上一页</button> ${evPage}/${pages} <button class="btn btn-sm" ${evPage>=pages?'disabled':''} onclick="evPage++;loadEvents()">下一页</button>`;
  } catch(e){ toast('加载事件失败：'+e.message, true); }
}

async function retryEvent(id){
  try { await api('POST', `/api/alerts/events/${id}/retry`); toast('已重新投递'); loadEvents(); }
  catch(e){ toast('重试失败：'+e.message, true); }
}

function cleanupEvents(){
  openModal('清理历史事件', `<div class="form-row"><label>删除多少天前的事件</label><input id="f-days" type="number" value="30"></div>`, async () => {
    try {
      const r = await api('POST', '/api/alerts/events/cleanup', { days: parseInt(document.getElementById('f-days').value)||30 });
      toast(`已清理 ${r.data.deleted} 条`); loadEvents();
    } catch(e){ toast('清理失败：'+e.message, true); return false; }
  }, '清理');
}
