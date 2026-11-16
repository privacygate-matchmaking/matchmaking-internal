/* 직원 가입 신청 폼 (로그인 전) + 총관리자 가입 승인 목록.
 * 가입 신청: 세션·CSRF 토큰이 없으므로 internal-api 가 Origin 과 요청 횟수를 확인한다.
 * 비밀번호는 요청 본문으로만 보내고 화면·저장소에 남기지 않는다. 최종 검사는 internal-api 가 한다. */
'use strict';
window.StaffSignupUI = (() => {
  const ROLES = { counselor: '상담 직원', approver: '승인 담당자' };
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  };

  /** 입력값 → {body} 또는 {field, error}. 서버와 같은 규칙 (서버가 최종 판단). */
  function validate(v) {
    const fail = (field, error) => ({ field, error });
    const username = (v.username || '').trim();
    if (!/^[a-z][a-z0-9_]{3,19}$/.test(username)) return fail('username', '아이디는 영문 소문자로 시작하는 4~20자(영문 소문자·숫자·_)로 입력하세요.');
    const password = v.password || '';
    if (password.length < 12 || password.length > 64) return fail('password', '비밀번호는 12~64자로 입력하세요.');
    if (password !== password.trim()) return fail('password', '비밀번호 앞뒤에 공백을 넣을 수 없습니다.');
    if (password.toLowerCase().includes(username)) return fail('password', '비밀번호에 아이디를 넣을 수 없습니다.');
    if (password !== v.password_confirm) return fail('password_confirm', '비밀번호 확인이 일치하지 않습니다.');
    const name = (v.name || '').trim();
    if (!name || name.length > 30 || /[<>]/.test(name)) return fail('name', '이름을 입력하세요 (30자 이내).');
    const email = (v.email || '').trim();
    if (!/^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,120}\.[A-Za-z]{2,24}$/.test(email)) return fail('email', '이메일 형식을 확인하세요.');
    if (!ROLES[v.requested_role]) return fail('requested_role', '신청할 역할을 선택하세요.');
    return { body: { username, password, name, email, requested_role: v.requested_role } };
  }

  function field(form, key, label, input, hint) {
    input.id = 'staff-signup-' + key.replace(/_/g, '-');
    const l = el('label', '', label); l.htmlFor = input.id;
    form.append(l, input);
    if (hint) form.append(el('p', 'muted hint', hint));
    return input;
  }
  function input(type, attrs = {}) {
    const n = el('input'); n.type = type;
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    return n;
  }

  function render(root, { fetch: send = (...a) => fetch(...a), onBack = () => {} } = {}) {
    root.replaceChildren();
    const card = el('div', 'login-card signup-card');
    const form = el('form', 'form one'); form.noValidate = true;
    card.append(el('span', 'eyebrow', 'STAFF SIGN-UP'), el('h2', '', '직원 가입 신청'),
      el('p', 'muted', '총관리자가 승인하면 로그인할 수 있습니다. 승인 전에는 계정이 비활성 상태입니다. 시험 서비스이므로 실제 개인정보를 입력하지 마세요.'));
    const inputs = {};
    inputs.username = field(form, 'username', '아이디', input('text', { autocomplete: 'username', maxlength: '20', autocapitalize: 'none', spellcheck: 'false' }), '영문 소문자로 시작, 4~20자 (영문 소문자·숫자·_)');
    inputs.password = field(form, 'password', '비밀번호', input('password', { autocomplete: 'new-password', maxlength: '64' }), '12자 이상, 아이디를 포함할 수 없음');
    inputs.password_confirm = field(form, 'password_confirm', '비밀번호 확인', input('password', { autocomplete: 'new-password', maxlength: '64' }));
    inputs.name = field(form, 'name', '이름', input('text', { autocomplete: 'name', maxlength: '30' }));
    inputs.email = field(form, 'email', '이메일', input('email', { autocomplete: 'email', maxlength: '200' }));
    const role = el('select');
    for (const [value, label] of [['', '선택하세요'], ...Object.entries(ROLES)]) { const o = el('option', '', label); o.value = value; role.append(o); }
    inputs.requested_role = field(form, 'requested_role', '신청 역할', role, '총관리자 계정은 가입 신청으로 만들 수 없습니다.');
    const error = el('p', 'error'); error.setAttribute('role', 'alert');
    const submit = el('button', 'primary wide', '가입 신청'); submit.type = 'submit';
    const back = el('button', 'text-button', '← 로그인 화면으로'); back.type = 'button'; back.onclick = onBack;
    form.append(error, submit, back);
    card.append(form);
    root.append(card);

    form.onsubmit = async (event) => {
      event.preventDefault();
      error.textContent = '';
      const values = {};
      for (const [k, n] of Object.entries(inputs)) values[k] = n.value;
      const result = validate(values);
      if (result.error) {
        error.textContent = result.error;
        if (inputs[result.field] && inputs[result.field].focus) inputs[result.field].focus();
        return;
      }
      submit.disabled = true;
      try {
        const res = await send('/api/staff-signups', { method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(result.body) });
        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          error.textContent = data.error?.message || (res.status === 422 ? '입력 내용을 다시 확인하세요.' : '가입 신청을 완료하지 못했습니다. 잠시 후 다시 시도하세요.');
          return;
        }
        inputs.password.value = ''; inputs.password_confirm.value = '';
        const done = el('div', 'login-card signup-card');
        done.append(el('span', 'eyebrow', 'REQUEST SENT'), el('h2', '', '가입 신청이 접수되었습니다'),
          el('p', '', `${ROLES[result.body.requested_role]} 아이디 ${result.body.username} 로 신청했습니다.`),
          el('p', 'muted', '총관리자가 승인하면 로그인할 수 있습니다. 승인 전에 로그인하면 "사용할 수 없는 계정"으로 안내됩니다.'));
        const again = el('button', 'text-button', '← 로그인 화면으로'); again.type = 'button'; again.onclick = onBack;
        done.append(again);
        root.replaceChildren(done);
      } catch {
        error.textContent = '가입 신청을 완료하지 못했습니다. 잠시 후 다시 시도하세요.';
      } finally {
        if (submit.isConnected) submit.disabled = false;
      }
    };
    return { form, inputs, error, submit };
  }

  /** 총관리자: 대기 중 신청 목록. api(path, options)는 app.js 의 CSRF 포함 fetch. */
  async function renderAdmin({ root, api, describe, toast = () => {}, confirmAsk = (m) => window.confirm(m) }) {
    root.replaceChildren(el('p', 'muted', '가입 신청을 불러오는 중입니다.'));
    const res = await api('/api/staff-signups');
    if (!res.ok) { root.replaceChildren(el('p', 'result err', await describe(res))); return; }
    const { items } = await res.json();
    root.replaceChildren();
    if (!items.length) { root.append(el('div', 'empty', '대기 중인 가입 신청이 없습니다.')); return; }
    const wrap = el('div', 'tablewrap'); const table = el('table');
    const head = el('thead'); const hr = el('tr');
    for (const h of ['이름', '아이디', '이메일', '신청 역할', '신청 시각', '처리']) hr.append(el('th', '', h));
    head.append(hr); const body = el('tbody');
    for (const item of items) {
      const tr = el('tr');
      const roleCell = el('td'); roleCell.append(el('span', 'pill' + (item.requested_role === 'approver' ? ' amber' : ''), ROLES[item.requested_role] || item.requested_role));
      tr.append(el('td', '', item.name), el('td', 'mono', item.username), el('td', '', item.email), roleCell,
        el('td', '', item.created_at ? new Date(item.created_at).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' }) : '-'));
      const act = el('td'); const box = el('div', 'actions');
      const decide = (action) => async () => {
        const warn = item.requested_role === 'approver' && action === 'approve'
          ? '\n\n승인 담당자는 소개 자료 반출을 승인할 수 있습니다. 실제 승인 업무 담당자인지 확인하세요. (기존 승인 담당자에게도 알림이 갑니다)' : '';
        const text = action === 'approve'
          ? `${item.name}(${item.username}) 님을 ${ROLES[item.requested_role]}로 승인할까요?${warn}`
          : `${item.name}(${item.username}) 님의 가입 신청을 거절할까요? 계정과 신청 기록이 삭제됩니다.`;
        if (!(await confirmAsk(text))) return;
        for (const b of box.querySelectorAll('button')) b.disabled = true;
        const r = await api(`/api/staff-signups/${encodeURIComponent(item.signup_id)}/${action}`, { method: 'POST', json: {} });
        if (!r.ok) { toast(await describe(r)); for (const b of box.querySelectorAll('button')) b.disabled = false; return; }
        const data = await r.json();
        toast(action === 'approve' ? `승인했습니다. 직원 코드 ${data.pseudo_id}` : '가입 신청을 거절했습니다.');
        await renderAdmin({ root, api, describe, toast, confirmAsk });
      };
      const ok = el('button', 'btn sm primary', '승인'); ok.type = 'button'; ok.onclick = decide('approve');
      const no = el('button', 'btn sm danger', '거절'); no.type = 'button'; no.onclick = decide('reject');
      box.append(ok, no); act.append(box); tr.append(act); body.append(tr);
    }
    table.append(head, body); wrap.append(table); root.append(wrap);
    if (window.ListPager) ListPager.apply(body, [...body.children], { size: 10, search: true, placeholder: '이름·아이디·이메일·역할로 검색', label: '가입 신청 페이지' });
  }

  function bind(doc = document) {
    const open = doc.getElementById('staff-signup-open'), view = doc.getElementById('staff-signup-view'), login = doc.getElementById('login-view');
    if (!open || !view || !login) return;
    const back = () => { view.hidden = true; view.replaceChildren(); login.hidden = false; };
    open.onclick = () => { login.hidden = true; view.hidden = false; render(view, { onBack: back }); };
  }
  if (typeof document !== 'undefined' && document.addEventListener) document.addEventListener('DOMContentLoaded', () => bind());
  return { validate, render, renderAdmin, bind, ROLES };
})();
