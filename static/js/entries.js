// 通用条目列表页逻辑（三类条目共用）
let GT = { groups: [], tags: [], nodes: [] };

async function loadGT() {
  try { GT.groups = await api('GET', '/api/groups'); } catch (e) {}
  try { GT.tags = await api('GET', '/api/tags'); } catch (e) {}
  try { const n = await api('GET', '/api/nodes'); GT.nodes = n.items || n; } catch (e) { GT.nodes = [{ id: 1, name: '本地节点' }]; }
}

function groupChip(g) {
  if (!g) return '<span class="muted">未分组</span>';
  return `<span class="groupchip" style="background:${esc(g.color)}">${esc(g.name)}</span>`;
}
function tagChips(tags) {
  return (tags || []).map(t => `<span class="tagchip" style="background:${esc(t.color)}">${esc(t.name)}</span>`).join('');
}
function expireCell(row) {
  if (!row.expires_at) return '<span class="badge muted">永久</span>';
  const exp = new Date(row.expires_at.replace(' ', 'T') + 'Z').getTime();
  const days = (exp - Date.now()) / 86400000;
  const cls = days < 0 ? 'danger' : days <= 7 ? 'warn' : 'ok';
  return `<span class="badge ${cls}">${fmtTime(row.expires_at)}</span>`;
}
function quotaCell(row) {
  const q = row.quota;
  if (!q || q.quota_bytes === 0) return '<span class="muted">-</span>';
  const pct = Math.min(100, (q.used_bytes / q.quota_bytes) * 100);
  const cls = q.status === 'exceeded' ? 'danger' : pct >= 80 ? 'warn' : '';
  return `<div style="display:flex;align-items:center;gap:6px"><div class="progress"><div class="${cls}" style="width:${pct}%"></div></div><span class="muted">${pct.toFixed(0)}%</span></div>`;
}

function initEntryPage(o) {
  const L = {
    api: o.api, etype: o.etype, page: 1, pageSize: 20,
    selected: new Set(),
    async reload() {
      const f = this.readFilters();
      const d = await api('GET', this.api + '?' + qs({ page: this.page, page_size: this.pageSize, ...f }));
      this.render(d);
      if (o.runtimeBadge) refreshRuntimeColumn().catch(() => {});
    },
    readFilters() {
      const g = id => document.getElementById(id)?.value;
      const f = {
        q: g('f-q') || undefined,
        node_id: g('f-node') || undefined,
        enabled: g('f-enabled') || undefined,
        group_id: g('f-group') || undefined,
        tag_id: g('f-tag') || undefined,
        disabled_reason: g('f-reason') || undefined,
        expiring_days: g('f-expiring') || undefined,
      };
      if (o.readExtraFilters) Object.assign(f, o.readExtraFilters());
      return f;
    },
    render(d) {
      this.rows = (d && d.data && d.data.items) || d.items || [];
      const thead = document.getElementById('thead');
      thead.innerHTML = '<th><input type="checkbox" id="sel-all"></th>'
        + o.columns.map(c => `<th>${esc(c.label)}</th>`).join('') + '<th>操作</th>';
      document.getElementById('sel-all').onchange = e => {
        document.querySelectorAll('.row-sel').forEach(cb => { cb.checked = e.target.checked; });
        this.syncSel();
      };
      const tb = document.getElementById('tbody');
      tb.innerHTML = d.items.map(r => {
        const tds = o.columns.map(c => `<td>${c.cell(r)}</td>`).join('');
        return `<tr><td><input type="checkbox" class="row-sel" data-id="${r.id}"></td>${tds}
          <td style="white-space:nowrap">
            <button class="btn btn-sm" onclick="L.openForm(${r.id})">编辑</button>
            <button class="btn btn-sm" onclick="L.toggleOne(${r.id}, ${r.enabled ? 0 : 1})">${r.enabled ? '停用' : '启用'}</button>
            <button class="btn btn-sm" onclick="L.quotaForm(${r.id})">配额</button>
            <button class="btn btn-sm" onclick="L.quickSub(${r.id})">订阅</button>
            <button class="btn btn-sm btn-danger" onclick="L.delOne(${r.id})">删除</button>
          </td></tr>`;
      }).join('') || `<tr><td colspan="${o.columns.length + 2}" class="muted" style="text-align:center">暂无数据</td></tr>`;
      tb.querySelectorAll('.row-sel').forEach(cb => cb.onchange = () => this.syncSel());
      document.getElementById('pager').innerHTML = pagerHtml(d.total, d.page, d.page_size, 'L.goto');
      this.selected.clear();
      this.syncBar();
    },
    goto(p) { this.page = p; this.reload().catch(e => toast(e.message, true)); },
    syncSel() {
      this.selected = new Set([...document.querySelectorAll('.row-sel:checked')].map(cb => +cb.dataset.id));
      this.syncBar();
    },
    syncBar() {
      const bar = document.getElementById('batchbar');
      bar.style.display = this.selected.size ? 'flex' : 'none';
      document.getElementById('sel-count').textContent = this.selected.size;
    },
    items() { return [...this.selected].map(id => ({ entry_type: this.etype, entry_id: id })); },
    async toggleOne(id, enabled) {
      if (enabled) {
        // P11：手动恢复因配额停用的条目时提示确认（配额未重置前流量会计入，立刻超限）
        const row = (this.rows || []).find(r => r.id === id);
        if (row && row.disabled_reason === 'quota') {
          const q = row.quota || {};
          const pct = q.quota_bytes ? Math.round(q.used_bytes * 100 / q.quota_bytes) : 100;
          confirmDo(
            `该条目因流量配额用尽被自动停用（已用 ${pct}%）。手动启用后若配额未重置或调大，会立即再次超限停用。建议先在"流量配额"页重置用量或调大配额。仍要手动启用吗？`,
            async () => {
              await api('POST', `${this.api}/${id}/toggle`, { enabled: true });
              toast('已启用');
              this.reload();
            }, '仍要启用');
          return;
        }
      }
      await api('POST', `${this.api}/${id}/toggle`, { enabled: !!enabled });
      toast(enabled ? '已启用' : '已停用');
      this.reload();
    },
    // P11：配额设置弹窗
    async quotaForm(id) {
      let q = null;
      try { q = (await api('GET', `/api/entries/${this.etype}/${id}/quota`)).quota; } catch (e) { toast('加载配额失败：' + e.message, true); return; }
      const cur = q && q.quota_bytes ? `${fmtBytes(q.used_bytes)} / ${fmtBytes(q.quota_bytes)}（${Math.round(q.used_bytes * 100 / q.quota_bytes)}%）` : '未设置';
      const row = (this.rows || []).find(r => r.id === id);
      const name = row ? row.name : ('#' + id);
      openModal(`配额 - ${esc(name)}`, `
        <div class="form-row"><label>当前用量</label><div style="padding:6px 0">${cur}</div></div>
        <div class="form-row"><label>配额（字节，0=取消）</label><input id="qf-quota" type="number" value="${q ? q.quota_bytes : 0}"></div>
        <div class="form-row"><label>周期</label><select id="qf-period">
          <option value="total" ${!q || q.period === 'total' ? 'selected' : ''}>累计</option>
          <option value="monthly" ${q && q.period === 'monthly' ? 'selected' : ''}>每月</option></select></div>
        <div class="form-row"><label>每月重置日（1-28）</label><input id="qf-day" type="number" min="1" max="28" value="${q ? q.reset_day : 1}"></div>
        <div class="muted">常用：1GB=${1073741824}，10GB=${10737418240}；仅落地代理（有监听地址）/端口转发/中转隧道的流量可计量。</div>
        ${q && q.quota_bytes ? '<button class="btn btn-sm" id="qf-reset" style="margin-top:8px">重置本周期用量</button>' : ''}`,
        async () => {
          const body = {
            quota_bytes: parseInt(document.getElementById('qf-quota').value || '0'),
            period: document.getElementById('qf-period').value,
            reset_day: parseInt(document.getElementById('qf-day').value || '1'),
          };
          try {
            const r = await api('PUT', `/api/entries/${this.etype}/${id}/quota`, body);
            toast(r.recovered ? '配额已更新，条目已恢复' : '配额已更新');
            this.reload();
          } catch (e) { toast('更新失败：' + e.message, true); }
        }, '保存');
      const rb = document.getElementById('qf-reset');
      if (rb) rb.onclick = async () => {
        try {
          const r = await api('POST', `/api/entries/${this.etype}/${id}/quota/reset`);
          toast(r.recovered ? '用量已重置，条目已恢复' : '用量已重置');
          closeModal(); this.reload();
        } catch (e) { toast('重置失败：' + e.message, true); }
      };
    },
    async delOne(id) {
      const d = await api('GET', `${this.api}/${id}`);
      const refs = d.sub_refs || 0;
      confirmDo(`确定删除「${d.name}」？${refs ? `该条目被 ${refs} 个订阅引用，删除后将从这些订阅中移除。` : ''}`, async () => {
        await api('DELETE', `${this.api}/${id}`);
        toast('已删除');
        this.reload();
      }, '删除');
    },
    openForm(id) {
      const isNew = !id;
      const load = isNew ? Promise.resolve(null) : api('GET', `${this.api}/${id}`);
      load.then(item => {
        openModal(isNew ? '新建' : '编辑', o.formHtml(item, isNew), async () => {
          const payload = o.formData(isNew);
          if (isNew) await api('POST', this.api, payload);
          else await api('PUT', `${this.api}/${id}`, payload);
          toast('已保存');
          this.reload();
        }, '保存');
        if (o.afterFormOpen) o.afterFormOpen(item, isNew);
      }).catch(e => toast(e.message, true));
    },
    async quickSub(id) {
      openModal('一键生成订阅', `
        <div class="form-row"><label>订阅名称</label><input id="qs-name" value="单条目订阅-${id}"></div>
        <div class="form-row"><label>有效期</label>
          <select id="qs-preset">
            <option value="permanent">永久</option><option value="7d">7 天</option>
            <option value="30d">30 天</option><option value="90d">90 天</option><option value="1y">1 年</option>
          </select></div>`, async () => {
        const d = await api('POST', `/api/entries/${this.etype}/${id}/quick_subscription`, {
          name: document.getElementById('qs-name').value,
          expire_preset: document.getElementById('qs-preset').value,
        });
        openModal('订阅已生成', `<div class="form-row"><label>订阅地址</label>
          <div class="codebox">${esc(d.url)}</div></div>
          <button class="btn" onclick="copyText('${esc(d.url)}')">复制地址</button>`, () => {}, '关闭');
      }, '生成');
    },
    // ---- 批量 ----
    async bToggle(enabled) {
      await api('POST', `${this.api}/batch_toggle`, { ids: [...this.selected], enabled });
      toast('已更新'); this.reload();
    },
    async bDelete() {
      confirmDo(`确定删除选中的 ${this.selected.size} 个条目？关联的标签、配额、订阅引用将一并清理。`, async () => {
        await api('POST', `${this.api}/batch_delete`, { ids: [...this.selected] });
        toast('已删除'); this.reload();
      }, '删除');
    },
    async bMove() {
      const nid = document.getElementById('b-node').value;
      if (!nid) return toast('请选择节点', true);
      await api('POST', `${this.api}/batch_move`, { ids: [...this.selected], node_id: +nid });
      toast('已迁移'); this.reload();
    },
    async bSetGroup() {
      const gid = document.getElementById('b-group').value;
      await api('POST', '/api/entries/batch_set_group', { items: this.items(), group_id: gid ? +gid : null });
      toast('已设置'); this.reload();
    },
    async bAddTag() {
      const tid = document.getElementById('b-tag').value;
      if (!tid) return toast('请选择标签', true);
      await api('POST', '/api/entries/batch_add_tags', { items: this.items(), tag_ids: [+tid] });
      toast('已添加'); this.reload();
    },
    async bRemoveTag() {
      const tid = document.getElementById('b-tag').value;
      if (!tid) return toast('请选择标签', true);
      await api('POST', '/api/entries/batch_remove_tags', { items: this.items(), tag_ids: [+tid] });
      toast('已移除'); this.reload();
    },
    async bSetExpiry() {
      const preset = document.getElementById('b-expiry').value;
      await api('POST', '/api/entries/batch_set_expiry', { items: this.items(), expire_preset: preset });
      toast('已设置'); this.reload();
    },
    async bSetQuota() {
      openModal('批量设置配额', `
        <div class="form-row"><label>配额（GB，填 0 取消配额）</label><input id="bq-gb" type="number" min="0" value="100"></div>
        <div class="form-row"><label>周期</label><select id="bq-period">
          <option value="total">累计</option><option value="monthly">每月（1 日重置）</option></select></div>
        <p class="muted">不经过本系统的条目（如无监听地址的代理）会被跳过并提示。</p>`, async () => {
        const gb = parseFloat(document.getElementById('bq-gb').value) || 0;
        const d = await api('POST', '/api/entries/batch_set_quota', {
          items: this.items(), quota_bytes: Math.round(gb * 1073741824),
          period: document.getElementById('bq-period').value,
        });
        toast(`已设置 ${d.ok} 个${d.skipped.length ? `，跳过 ${d.skipped.length} 个` : ''}`);
        this.reload();
      }, '设置');
    },
  };
  window.L = L;
  window.__entryPage = L;
  return L;
}

function commonFiltersHtml() {
  const gopts = GT.groups.map(g => `<option value="${g.id}">${esc(g.name)}</option>`).join('');
  const topts = GT.tags.map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
  const nopts = GT.nodes.map(n => `<option value="${n.id}">${esc(n.name)}</option>`).join('');
  return `
    <select id="f-node"><option value="">全部节点</option>${nopts}</select>
    <select id="f-enabled"><option value="">全部状态</option><option value="1">启用</option><option value="0">停用</option></select>
    <select id="f-group"><option value="">全部分组</option>${gopts}</select>
    <select id="f-tag"><option value="">全部标签</option>${topts}</select>
    <select id="f-reason"><option value="">停用原因不限</option>
      <option value="manual">手动停用</option><option value="expired">已过期</option><option value="quota">流量用尽</option></select>
    <select id="f-expiring"><option value="">到期不限</option>
      <option value="7">7 天内到期</option><option value="30">30 天内到期</option></select>`;
}

function batchBarHtml() {
  const nopts = GT.nodes.map(n => `<option value="${n.id}">${esc(n.name)}</option>`).join('');
  const gopts = GT.groups.map(g => `<option value="${g.id}">${esc(g.name)}</option>`).join('');
  const topts = GT.tags.map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
  return `已选 <b id="sel-count">0</b> 项
    <button class="btn btn-sm btn-ok" onclick="L.bToggle(true)">启用</button>
    <button class="btn btn-sm" onclick="L.bToggle(false)">停用</button>
    <button class="btn btn-sm btn-danger" onclick="L.bDelete()">删除</button>
    <select id="b-node" style="width:auto"><option value="">迁移到节点…</option>${nopts}</select>
    <button class="btn btn-sm" onclick="L.bMove()">迁移</button>
    <select id="b-group" style="width:auto"><option value="">设置分组…</option><option value="">— 未分组 —</option>${gopts}</select>
    <button class="btn btn-sm" onclick="L.bSetGroup()">分组</button>
    <select id="b-tag" style="width:auto"><option value="">选择标签…</option>${topts}</select>
    <button class="btn btn-sm" onclick="L.bAddTag()">加标签</button>
    <button class="btn btn-sm" onclick="L.bRemoveTag()">去标签</button>
    <select id="b-expiry" style="width:auto">
      <option value="permanent">永久有效</option><option value="7d">7 天</option>
      <option value="30d">30 天</option><option value="90d">90 天</option><option value="1y">1 年</option>
    </select>
    <button class="btn btn-sm" onclick="L.bSetExpiry()">有效期</button>
    <button class="btn btn-sm" onclick="L.bSetQuota()">配额</button>`;
}

function expirePresetHtml(sel) {
  const opts = [['permanent', '永久'], ['7d', '7 天'], ['30d', '30 天'], ['90d', '90 天'], ['1y', '1 年']];
  return `<select id="fm-preset">${opts.map(([v, t]) => `<option value="${v}" ${sel === v ? 'selected' : ''}>${t}</option>`).join('')}</select>`;
}
function nodeSelectHtml(selId, sel) {
  return `<select id="${selId}">${GT.nodes.map(n => `<option value="${n.id}" ${n.id === sel ? 'selected' : ''}>${esc(n.name)}</option>`).join('')}</select>`;
}
function groupSelectHtml(selId, sel) {
  return `<select id="${selId}"><option value="">— 未分组 —</option>${GT.groups.map(g => `<option value="${g.id}" ${g.id === sel ? 'selected' : ''}>${esc(g.name)}</option>`).join('')}</select>`;
}
function tagCheckHtml(selIds) {
  const sel = new Set(selIds || []);
  return GT.tags.map(t => `<label style="display:inline-block;margin:2px 8px 2px 0;font-size:13px">
    <input type="checkbox" class="fm-tag" value="${t.id}" ${sel.has(t.id) ? 'checked' : ''}> ${esc(t.name)}</label>`).join('') || '<span class="muted">暂无标签</span>';
}
function readTagIds() {
  return [...document.querySelectorAll('.fm-tag:checked')].map(c => +c.value);
}
