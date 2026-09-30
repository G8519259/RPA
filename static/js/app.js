// 全局 JS 工具：API 调用（自动带 CSRF）、toast、弹窗、表格分页
function csrf() {
  return sessionStorage.getItem('csrf') || document.querySelector('meta[name=csrf]')?.content || '';
}

async function api(method, url, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  if (method !== 'GET' && method !== 'HEAD') {
    opt.headers['X-CSRF-Token'] = csrf();
  }
  const r = await fetch(url, opt);
  if (r.status === 401) { location.href = '/admin/login'; throw new Error('未登录'); }
  const j = await r.json().catch(() => ({ ok: false, error: 'HTTP ' + r.status }));
  if (!j.ok) throw new Error(j.error || ('HTTP ' + r.status));
  return j.data;
}

function toast(msg, isErr) {
  const box = document.getElementById('toast');
  const d = document.createElement('div');
  d.className = 'toast-msg' + (isErr ? ' err' : '');
  d.textContent = msg;
  box.appendChild(d);
  setTimeout(() => d.remove(), 3500);
}

async function logout() {
  try { await api('POST', '/api/auth/logout'); } catch (e) {}
  sessionStorage.removeItem('csrf');
  location.href = '/admin/login';
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function fmtBytes(b) {
  b = Number(b) || 0;
  const u = ['B','KB','MB','GB','TB','PB'];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i === 0 ? b : b.toFixed(1)) + ' ' + u[i];
}

// UTC "YYYY-MM-DD HH:MM:SS" → 本地显示（默认 +8）
const TZ = 8;
function fmtTime(s) {
  if (!s) return '-';
  const d = new Date(s.replace(' ', 'T') + 'Z');
  if (isNaN(d)) return s;
  const l = new Date(d.getTime() + TZ * 3600 * 1000);
  return l.toISOString().slice(0, 19).replace('T', ' ');
}

function openModal(title, bodyHtml, onOk, okText) {
  const root = document.getElementById('modal-root');
  root.innerHTML = `<div class="modal-mask" onclick="if(event.target===this)closeModal()">
    <div class="modal"><h3>${esc(title)}</h3><div id="modal-body">${bodyHtml}</div>
    <div class="actions"><button class="btn" onclick="closeModal()">取消</button>
    <button class="btn btn-primary" id="modal-ok">${esc(okText || '确定')}</button></div></div></div>`;
  document.getElementById('modal-ok').onclick = async () => {
    try { await onOk(); closeModal(); } catch (e) { toast(e.message, true); }
  };
}
function closeModal() { document.getElementById('modal-root').innerHTML = ''; }

async function confirmDo(msg, fn, okText) {
  openModal('确认', `<p>${esc(msg)}</p>`, fn, okText || '确定');
}

function pagerHtml(total, page, pageSize, fnName) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return `<div class="pager">共 ${total} 条 · 第 ${page}/${pages} 页
    <button class="btn btn-sm" ${page <= 1 ? 'disabled' : ''} onclick="${fnName}(${page - 1})">上一页</button>
    <button class="btn btn-sm" ${page >= pages ? 'disabled' : ''} onclick="${fnName}(${page + 1})">下一页</button></div>`;
}

function qs(obj) {
  return Object.entries(obj).filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&');
}

function badgeFor(enabled, reason) {
  if (enabled) return '<span class="badge ok">启用</span>';
  const m = { manual: '手动停用', expired: '已过期', quota: '流量用尽' };
  return `<span class="badge danger">${m[reason] || '停用'}</span>`;
}

// ---- P11 配额 / 到期单元格 ----
function quotaCell(r) {
  const q = r.quota;
  if (!q || !q.quota_bytes) return '<span class="muted">-</span>';
  const pct = Math.min(100, Math.round(q.used_bytes * 100 / q.quota_bytes));
  const cls = q.status === 'exceeded' ? 'danger' : (pct >= 80 ? 'warn' : '');
  const st = q.status === 'exceeded' ? ' <span class="badge danger">超限</span>' : '';
  const period = q.period === 'monthly' ? ' <span class="muted">月</span>' : '';
  return `<div class="pbar"><div class="pfill ${cls}" style="width:${pct}%"></div></div>`
    + `<span class="muted">${pct}%</span>${period}${st}`;
}

function expireCell(r) {
  if (!r.expires_at) return '<span class="muted">永久</span>';
  const past = r.expires_at <= __nowStr();
  return `<span class="${past ? 'badge danger' : ''}">${esc(r.expires_at)}</span>`;
}

function __nowStr() {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function copyText(t) {
  navigator.clipboard.writeText(t).then(() => toast('已复制'), () => toast('复制失败', true));
}

// ---- P8 运行时状态徽章 ----
let __rtCache = null, __rtCacheAt = 0;
async function loadRuntimeStatus(force) {
  const now = Date.now();
  if (!force && __rtCache && now - __rtCacheAt < 5000) return __rtCache;
  try {
    const d = await api('GET', '/api/runtime/status');
    __rtCache = {};
    for (const it of d.items) __rtCache[it.entry_type + ':' + it.entry_id] = it;
    __rtCacheAt = now;
  } catch (e) { __rtCache = __rtCache || {}; }
  return __rtCache;
}
function runtimeBadge(etype, id) {
  const m = (__rtCache || {})[etype + ':' + id] || (__rtCache || {})[etype + '_udp:' + id];
  if (!m) return '<span class="muted">-</span>';
  const st = m.status || '';
  if (st === 'running') return `<span class="badge ok" title="连接数 ${m.conns} / 上行 ${fmtBytes(m.bytes_up)} / 下行 ${fmtBytes(m.bytes_down)}">运行中</span>`;
  if (st.startsWith('idle')) return '<span class="badge">待机</span>';
  if (st.startsWith('error:')) return `<span class="badge danger" title="${esc(st.slice(6))}">异常</span>`;
  return `<span class="badge">${esc(st)}</span>`;
}
async function refreshRuntimeColumn(etype) {
  await loadRuntimeStatus(true);
  document.querySelectorAll('[data-rt]').forEach(td => {
    const [t, id] = td.dataset.rt.split(':');
    td.innerHTML = runtimeBadge(t, +id);
  });
}

function fmtBps(bps) {
  if (bps == null) return '—';
  const b = bps / 8;
  if (b < 1024) return b.toFixed(0) + ' B/s';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB/s';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB/s';
  return (b / 1073741824).toFixed(2) + ' GB/s';
}
