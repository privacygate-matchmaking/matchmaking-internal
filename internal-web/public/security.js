/* 보안 사건 대응 화면 (총관리자).
 * 사건 목록 → 상세(사유 코드·추적번호·자동 잠금) → 조치(잠금 해제·계정 정지/복구·받은 자료 회수)와 검토 상태·메모.
 * 회원 이름·연락처는 받지도 보여 주지도 않는다 (계정 코드·사유 코드만). 권한은 서버가 요청마다 다시 확인한다.
 * api(path, options): app.js 의 CSRF 포함 fetch, describe(res): 공통 오류 문구, ask(): 확인 대화상자. */
'use strict';
window.SecurityUI = (() => {
  const STATUS = { new: ['신규', 'red'], reviewing: ['검토 중', 'amber'], resolved: ['조치 완료', 'green'], false_positive: ['오탐', 'off'] };
  const ROLE = { counselor: '상담 직원', approver: '승인 담당자', data_admin: '총관리자', member: '회원' };
  const SOURCE = { 'internal-api': '내부 업무 API', 'transfer-api': '중계 서버' };
  const ACTION = { status: '검토 상태 변경', suspend_account: '계정 정지', restore_account: '계정 복구',
                   unlock: '임시 잠금 해제', revoke_deliveries: '받은 자료 회수' };
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  };
  const kst = (iso) => (iso ? new Date(iso).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' }) : '-');
  const hm = (iso) => (iso ? new Date(iso).toLocaleTimeString('ko-KR', { timeZone: 'Asia/Seoul', hour: '2-digit', minute: '2-digit' }) : '');
  const pill = (text, color) => el('span', `pill ${color || ''}`.trim(), text);
  const statusPill = (s) => pill(...(STATUS[s] || [s, '']));
  const future = (iso) => !!iso && new Date(iso) > new Date();

  /** 계정 상태 한 줄: 정지 / 임시 잠금(~HH:MM) / 활성 / 계정 없음 */
  function accountState(subject) {
    if (!subject || !subject.exists) return pill('계정 없음', 'off');
    if (subject.active === false) return pill('정지됨', 'red');
    if (future(subject.locked_until)) return pill(`임시 잠금 ~${hm(subject.locked_until)}`, 'amber');
    return pill('활성', 'green');
  }

  /** 상세 화면에서 보여 줄 조치 버튼 목록 (서버도 같은 조건을 다시 확인) */
  function availableActions(item) {
    const s = item.subject || {};
    const out = [];
    if (!s.exists) return out;
    if (future(s.locked_until)) out.push('unlock');
    if (item.subject_role !== 'data_admin') out.push(s.active === false ? 'restore_account' : 'suspend_account');
    if (item.subject_role === 'member') out.push('revoke_deliveries');
    return out;
  }

  function confirmText(action, item) {
    const who = `${item.subject_code || '-'}(${ROLE[item.subject_role] || item.subject_role || '-'})`;
    return {
      unlock: `${who} 계정의 자동 임시 잠금을 지금 풀까요?`,
      suspend_account: `${who} 계정을 정지할까요?\n\n업무 DB 에서 비활성으로 바꾸고 로그인 세션을 모두 끊습니다(Keycloak 계정도 비활성). 복구 전까지 로그인할 수 없습니다.`,
      restore_account: `${who} 계정을 복구할까요? 임시 잠금도 함께 풀립니다.`,
      revoke_deliveries: `${who} 회원이 받은 소개 자료 승인을 모두 회수할까요?\n\n회수한 자료는 다시 내려받을 수 없으며 되돌릴 수 없습니다.`,
    }[action];
  }

  async function render(ctx) {
    const { root } = ctx;
    const scope = ctx.scope || 'open';
    root.replaceChildren(el('p', 'muted', '보안 사건을 불러오는 중입니다.'));
    const res = await ctx.api(`/api/admin/security-incidents?status=${scope}`);
    if (!res.ok) { root.replaceChildren(el('p', 'result err', await ctx.describe(res))); return; }
    const { items, counts } = await res.json();
    root.replaceChildren();

    const head = el('div', 'row-between');
    head.append(el('p', 'muted', `신규 ${counts.new || 0}건 · 검토 중 ${counts.reviewing || 0}건 · 조치 완료 ${counts.resolved || 0}건 · 오탐 ${counts.false_positive || 0}건`));
    const toggle = el('div', 'actions');
    for (const [value, label] of [['open', '열린 사건'], ['all', '전체']]) {
      const b = el('button', `btn sm${value === scope ? ' primary' : ''}`, label); b.type = 'button';
      b.onclick = () => render({ ...ctx, scope: value });
      toggle.append(b);
    }
    const refresh = el('button', 'btn sm', '새로 고침'); refresh.type = 'button'; refresh.onclick = () => render({ ...ctx, scope });
    toggle.append(refresh);
    head.append(toggle);
    root.append(head);

    const detail = el('div', 'card mt16 security-detail'); detail.hidden = true;
    if (!items.length) {
      root.append(el('div', 'empty mt16', scope === 'open' ? '열린 보안 사건이 없습니다.' : '보안 사건이 없습니다.'));
      return;
    }
    const wrap = el('div', 'tablewrap mt16'); const table = el('table');
    const thead = el('thead'); const hr = el('tr');
    for (const h of ['최근 발생', '사건', '대상 계정', '횟수', '계정 상태', '검토 상태', '']) hr.append(el('th', '', h));
    thead.append(hr);
    const body = el('tbody');
    for (const item of items) {
      const tr = el('tr');
      const what = el('td');
      what.append(el('strong', '', item.title), el('br'),
        item.blocked ? pill('차단됨', 'green') : pill('차단 안 됨 (baseline)', 'red'), document.createTextNode(' '),
        pill(item.severity === 'high' ? '높음' : '보통', item.severity === 'high' ? 'red' : 'amber'));
      const whoCell = el('td'); whoCell.append(el('strong', '', item.subject_code || '-'), el('br'), el('span', 'muted', ROLE[item.subject_role] || item.subject_role || '-'));
      const stateCell = el('td'); stateCell.append(accountState(item.subject));
      const statusCell = el('td'); statusCell.append(statusPill(item.status));
      const open = el('button', 'btn sm', '상세'); open.type = 'button';
      open.onclick = () => showDetail({ ...ctx, scope }, item.incident_id, detail);
      const act = el('td'); act.append(open);
      tr.append(el('td', '', kst(item.last_seen_at)), what, whoCell, el('td', '', `${item.occurrences}회`), stateCell, statusCell, act);
      body.append(tr);
    }
    table.append(thead, body); wrap.append(table); root.append(wrap, detail);
    if (window.ListPager) ListPager.apply(body, [...body.children], { size: 10, search: true, placeholder: '사건·대상 코드·상태로 검색', label: '보안 사건 페이지' });
    if (ctx.focus) await showDetail({ ...ctx, scope }, ctx.focus, detail);
  }

  async function showDetail(ctx, incidentId, box) {
    box.hidden = false;
    box.replaceChildren(el('p', 'muted', '불러오는 중입니다.'));
    const res = await ctx.api(`/api/admin/security-incidents/${encodeURIComponent(incidentId)}`);
    if (!res.ok) { box.replaceChildren(el('p', 'result err', await ctx.describe(res))); return; }
    const item = await res.json();
    box.replaceChildren();
    box.append(el('span', 'eyebrow', 'SECURITY INCIDENT'), el('h3', '', item.title));
    const facts = el('dl', 'facts');
    const fact = (k, v) => { const dd = el('dd'); if (v instanceof Node) dd.append(v); else dd.textContent = v ?? '-'; facts.append(el('dt', '', k), dd); };
    fact('대상 계정', `${item.subject_code || '-'} · ${ROLE[item.subject_role] || item.subject_role || '-'}`);
    fact('계정 상태', accountState(item.subject));
    fact('차단 여부', item.blocked ? '서버가 막음 (enforce)' : '막지 못함 — 비교 시연 모드(baseline)에서 통과');
    fact('탐지 위치', SOURCE[item.source] || item.source);
    fact('사유', item.detail);
    fact('발생', `${kst(item.first_seen_at)} ~ ${kst(item.last_seen_at)} · ${item.occurrences}회`);
    fact('자동 임시 잠금', item.auto_locked_until ? `${kst(item.auto_locked_until)}까지` : '없음');
    fact('추적번호', item.trace_id ? el('span', 'mono', item.trace_id) : '-');
    fact('검토 상태', statusPill(item.status));
    if (item.note) fact('메모', item.note);
    box.append(facts);

    const result = el('p', 'result'); result.hidden = true;
    const say = (text, ok) => { result.textContent = text; result.className = `result ${ok ? 'ok' : 'err'}`; result.hidden = false; };

    const acts = availableActions(item);
    if (acts.length) {
      box.append(el('h4', '', '조치'));
      const row = el('div', 'actions');
      for (const action of acts) {
        const b = el('button', `btn sm${action === 'unlock' || action === 'restore_account' ? '' : ' danger'}`, ACTION[action]); b.type = 'button';
        b.onclick = async () => {
          const ok = await ctx.ask(ACTION[action], confirmText(action, item),
            [{ label: '취소', value: null }, { label: '확인', value: 'yes', cls: action === 'unlock' || action === 'restore_account' ? 'primary' : 'danger' }],
            'SECURITY RESPONSE', '조치 메모 (선택)');
          if (ok !== 'yes') return;
          b.disabled = true;
          const r = await ctx.api(`/api/admin/security-incidents/${encodeURIComponent(item.incident_id)}/actions`,
            { method: 'POST', json: { action, note: ctx.lastNote ? ctx.lastNote() : null } });
          if (!r.ok) { say(await ctx.describe(r), false); b.disabled = false; return; }
          const data = await r.json();
          const extra = data.keycloak === 'keycloak_failed' ? ' (Keycloak 반영 실패 — 업무 API 는 막혀 있습니다. Keycloak 관리 콘솔에서 확인하세요)'
            : data.revoked !== undefined ? ` (${data.revoked}건 회수)` : '';
          ctx.toast(`${ACTION[action]} 완료${extra}`);
          await render({ ...ctx, focus: item.incident_id });
        };
        row.append(b);
      }
      box.append(row);
    }

    box.append(el('h4', '', '검토 상태·메모'));
    const form = el('form', 'form one');
    const select = el('select');
    for (const [value, [label]] of Object.entries(STATUS)) { const o = el('option', '', label); o.value = value; if (value === item.status) o.selected = true; select.append(o); }
    const note = el('textarea'); note.maxLength = 500; note.rows = 3; note.placeholder = '확인 내용·조치 사유 (회원 이름·연락처는 적지 마세요)';
    const save = el('button', 'btn primary sm', '저장'); save.type = 'submit';
    form.append(select, note, save);
    form.onsubmit = async (event) => {
      event.preventDefault();
      save.disabled = true;
      const r = await ctx.api(`/api/admin/security-incidents/${encodeURIComponent(item.incident_id)}/status`,
        { method: 'POST', json: { status: select.value, note: note.value.trim() || null } });
      save.disabled = false;
      if (!r.ok) { say(await ctx.describe(r), false); return; }
      ctx.toast('검토 상태를 저장했습니다.');
      await render({ ...ctx, focus: item.incident_id });
    };
    box.append(form, result);

    box.append(el('h4', '', '조치 기록'));
    if (!item.actions.length) box.append(el('p', 'muted', '아직 조치 기록이 없습니다.'));
    else {
      const ul = el('ul', 'timeline');
      for (const a of item.actions) {
        ul.append(el('li', '', `${kst(a.created_at)} · ${a.actor} · ${ACTION[a.action] || a.action} · ${a.result}${a.detail ? ` — ${a.detail}` : ''}`));
      }
      box.append(ul);
    }
    box.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  return { render, availableActions, accountState, STATUS };
})();
