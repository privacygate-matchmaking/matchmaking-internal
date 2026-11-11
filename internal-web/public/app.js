// PrivacyGate 내부 화면
// 메뉴 숨김은 사용 편의일 뿐 보안 통제가 아니다. 권한은 internal-api 가 매 요청 확인한다.
// 서버 문자열은 모두 textContent 로만 넣는다 (innerHTML 금지, CSP 로 인라인 스크립트·스타일 차단).
const state = { me: null, members: [], consents: {}, requests: [], filter: "" };
const $ = (id) => document.getElementById(id);

const ROLE_NAMES = { counselor: "상담", data_admin: "총관리자", approver: "승인" };
const STATUS = {
  pending: ["대기", "amber"], approved: ["승인", "green"], rejected: ["거절", "red"], revoked: ["회수", "red"],
  active: ["활동", "green"], withdraw_pending: ["탈퇴 예정", "amber"],
  submitted: ["접수", ""], in_review: ["심사 중", "amber"], reviewed: ["심사 완료", "green"], deleted: ["삭제됨", ""],
  passed: ["통과", "green"], blocked: ["차단", "red"], failed: ["실패", "red"],
};

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const method = (options.method || "GET").toUpperCase();
  if (method !== "GET" && state.me) headers["X-CSRF-Token"] = state.me.csrf_token;
  if (options.json !== undefined) {
    headers["Content-Type"] = "application/json";
    options = { ...options, body: JSON.stringify(options.json) };
  }
  const res = await fetch(path, { ...options, method, headers, credentials: "same-origin" });
  if (res.status === 401 && path !== "/api/me") showLogin();   // internal-api 자체 세션 만료만 401 (중계 401 은 서버가 500 으로 바꿈)
  return res;
}

// 오류 응답 {"error": {code, message, trace_id}} 를 한 줄로
async function describe(res) {
  try {
    const body = await res.json();
    if (body.error) return `${body.error.message} (${body.error.code}, 추적번호 ${body.error.trace_id})`;
  } catch (_) { /* 본문 없음 */ }
  return `응답 ${res.status}`;
}

async function getJson(path) {
  const res = await api(path);
  if (!res.ok) throw new Error(await describe(res));
  return res.json();
}

// 서버는 UTC 로 주고, 화면은 한국 시간으로 표시
function toKst(iso) {
  return iso ? new Date(iso).toLocaleString("ko-KR", { timeZone: "Asia/Seoul" }) : "-";
}
const short = (id) => (id ? String(id).slice(0, 8) : "-");

function showResult(el, text, ok) {
  el.textContent = text;
  el.className = `result ${ok ? "ok" : "err"}`;
  el.hidden = false;
}

// ---- 표 그리기 도우미 (DOM API 만 사용) ----
function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (cls) node.className = cls;
  return node;
}
function pill(status) {
  const [label, color] = STATUS[status] || [status, ""];
  return el("span", label, `pill ${color}`.trim());
}
function button(label, onClick, cls = "btn sm") {
  const b = el("button", label, cls);
  b.type = "button";
  b.onclick = async () => { b.disabled = true; try { await onClick(); } finally { b.disabled = false; } };
  return b;
}
function row(cells) {
  const tr = document.createElement("tr");
  for (const c of cells) {
    const td = document.createElement("td");
    if (c instanceof Node) td.appendChild(c); else td.textContent = c ?? "-";
    tr.appendChild(td);
  }
  return tr;
}
function actions(...nodes) {
  const d = el("div", null, "actions");
  nodes.filter(Boolean).forEach((n) => d.appendChild(n));
  return d;
}
function fill(bodyId, emptyId, rows) {
  const body = $(bodyId);
  body.replaceChildren(...rows);
  $(emptyId).hidden = rows.length > 0;
}
function mono(text) { const s = el("span", text, "mono"); s.title = text || ""; return s; }
// 가명 ID 가 있으면 가명으로, 없으면 UUID 앞 8자리. 마우스를 올리면 전체 UUID
function who(pseudo, id) { const s = el("span", pseudo || short(id), pseudo ? "" : "mono"); s.title = id || ""; return s; }

// ---- 화면 전환 ----
function showLogin() {
  $("login-view").hidden = false;
  $("app-view").hidden = true;
  $("account").hidden = true;
  if (new URLSearchParams(location.search).get("login") === "failed") {
    $("login-msg").textContent = "로그인하지 못했습니다. 직원 계정인지 확인하세요.";
    $("login-msg").hidden = false;
  }
}

function showApp() {
  const { pseudo_id, role } = state.me;
  const roleName = ROLE_NAMES[role] || role;
  $("login-view").hidden = true;
  $("app-view").hidden = false;
  $("account").hidden = false;
  $("user-label").textContent = `${pseudo_id} · ${roleName}`;
  $("avatar").textContent = roleName.charAt(0);
  $("side-user").textContent = pseudo_id;
  $("side-role").textContent = roleName;
  $("baseline-banner").hidden = state.me.gate_mode !== "baseline";

  let first = null;
  for (const btn of $("nav").querySelectorAll("button")) {
    const visible = btn.dataset.roles.split(",").includes(role);
    btn.hidden = !visible;
    if (visible && !first) first = btn.dataset.view;
    btn.onclick = () => selectView(btn.dataset.view);
  }
  // 본문의 역할별 영역도 같은 규칙 (표시 편의일 뿐, 권한은 서버가 확인)
  for (const node of document.querySelectorAll("main [data-roles]")) {
    if (node.closest("#nav")) continue;
    node.hidden = !node.dataset.roles.split(",").includes(role);
  }
  if (first) selectView(first);
  initNotifications();
}

const isCounselor = () => state.me.role === "counselor";

const LOADERS = {
  members: async () => { await loadMembers(); if (isCounselor()) await loadRequests(); },
  manage: loadManage,
  evidence: loadReviews,
  approvals: loadApprovals,
};

function selectView(name) {
  for (const btn of $("nav").querySelectorAll("button")) btn.classList.toggle("active", btn.dataset.view === name);
  for (const view of document.querySelectorAll(".view")) {
    const on = view.dataset.view === name;
    view.hidden = !on;
    if (on) $("crumb").textContent = `이음 내부 업무 · ${view.dataset.title}`;
  }
  if (LOADERS[name]) LOADERS[name]().catch((e) => console.warn(e.message));
}

// ---- ① 담당 회원 조회 ----
function memberStatus(m) {
  const p = pill(m.status || "active");
  if (m.status !== "withdraw_pending" || !m.withdraw_at) return p;
  const days = Math.max(0, Math.ceil((new Date(m.withdraw_at) - Date.now()) / 86400000));
  const d = el("div");
  d.append(p, el("span", `D-${days} · ${new Date(m.withdraw_at).toLocaleDateString("ko-KR", { timeZone: "Asia/Seoul" })} 삭제`, "sub-code"));
  if (m.withdraw_reason) { const r = el("span", `사유: ${m.withdraw_reason}`, "sub-code"); r.title = m.withdraw_reason; d.append(r); }
  return d;
}

// 확인 팝업: choices = [{label, value, cls}] → 고른 value (취소·Esc 는 null)
// input = "입력칸 이름" 을 주면 선택 입력칸을 보여 주고, 입력값은 state.askText 에 담는다
function ask(title, message, choices, eyebrow = "CONFIRM", input = null) {
  const dlg = $("confirm-dialog");
  $("confirm-input-wrap").hidden = !input;
  $("confirm-input").value = "";
  if (input) $("confirm-input-label").textContent = input;
  $("confirm-eyebrow").textContent = eyebrow;
  $("confirm-title").textContent = title;
  $("confirm-message").textContent = message;
  const box = $("confirm-actions");
  box.replaceChildren(...choices.map((c) => {
    const b = el("button", c.label, `btn ${c.cls || ""}`.trim());
    b.value = c.value == null ? "" : c.value;
    return b;
  }));
  return new Promise((resolve) => {
    dlg.onclose = () => { state.askText = $("confirm-input").value.trim(); resolve(dlg.returnValue || null); };
    dlg.returnValue = "";
    dlg.showModal();
  });
}
function memberCell(m) { return el("strong", m.pseudo_id); }
function withMark(text, ok) {
  const d = el("span", text ?? "-");
  if (ok) d.append(el("span", "✓ 증빙", "ok-mark"));
  return d;
}
// 직원 화면용: A-003(박도윤)
const withName = (code, name) => (name ? `${code}(${name})` : code);
const ageText = (m) => (m.age != null ? `만 ${m.age}세` : "-");

// ---- 표 정렬·검색 (화면에서만, 서버가 준 목록 안에서) ----
const EDU_RANK = { "고졸": 1, "전문대졸": 2, "4년제 대졸": 3, "대학원졸": 4 };
const SORT_VALUE = {
  education_level: (m) => EDU_RANK[m.education_level] ?? null,
  verified: (m) => (m.education_verified ? 2 : 0) + (m.employment_verified ? 1 : 0),
};
const tableState = { members: { key: "pseudo_id", dir: 1, q: "" }, manage: { key: "pseudo_id", dir: 1, q: "" } };

function sortAndFilter(items, st, fields) {
  const q = st.q.trim().toLowerCase();
  const list = q ? items.filter((m) => fields.some((f) => String(m[f] ?? "").toLowerCase().includes(q))) : items.slice();
  const get = SORT_VALUE[st.key] || ((m) => m[st.key]);
  return list.sort((a, b) => {
    const x = get(a), y = get(b);
    if (x == null && y == null) return 0;
    if (x == null) return 1;                 // 빈 값은 항상 뒤로
    if (y == null) return -1;
    const c = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), "ko");
    return c * st.dir;
  });
}

function bindSort(headId, name, render) {
  for (const th of $(headId).querySelectorAll("th[data-sort]")) {
    th.classList.add("sortable");
    th.tabIndex = 0;
    const go = () => {
      const st = tableState[name];
      if (st.key === th.dataset.sort) st.dir = -st.dir; else { st.key = th.dataset.sort; st.dir = 1; }
      render();
    };
    th.onclick = go;
    th.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } };
  }
}

function markSort(headId, name) {
  const st = tableState[name];
  for (const th of $(headId).querySelectorAll("th[data-sort]")) {
    const on = th.dataset.sort === st.key;
    th.classList.toggle("asc", on && st.dir === 1);
    th.classList.toggle("desc", on && st.dir === -1);
    th.setAttribute("aria-sort", on ? (st.dir === 1 ? "ascending" : "descending") : "none");
  }
}

async function loadMembers() {
  const { items } = await getJson("/api/members");
  state.members = items;
  renderMembers();
}

function renderMembers() {
  const items = sortAndFilter(state.members, tableState.members,
    ["pseudo_id", "name", "gender", "education_level", "job_group", "counselors"]);
  $("members-count").textContent = items.length === state.members.length
    ? `${items.length}명` : `${items.length}명 / 전체 ${state.members.length}명`;
  markSort("members-head", "members");
  fill("members-body", "members-empty", items.map((m) =>
    row([memberCell(m), m.name ?? "-", m.gender ?? "-", ageText(m), m.height_cm ? `${m.height_cm}cm` : "-",
         withMark(m.education_level, m.education_verified), m.job_group ?? "-", m.counselors || "미배정",
         memberStatus(m), actions(button("상세", () => showMember(m.member_id)))])));
}

async function showMember(memberId) {
  const box = $("member-detail");
  const res = await api(`/api/members/${memberId}`);
  if (!res.ok) { box.hidden = true; return alertInline($("members-empty"), await describe(res)); }
  const m = await res.json();
  state.consents[m.member_id] = m.consents;
  $("member-detail-title").textContent = m.pseudo_id;
  $("member-detail-status").replaceChildren(pill(m.status));
  const f = $("member-facts");
  f.replaceChildren();
  fact(f, "이름", m.name ?? "-");
  fact(f, "성별", m.gender ?? "-");
  fact(f, "나이", m.birth_date ? `${ageText(m)} (${m.birth_date})` : "-");
  fact(f, "키 · 몸무게", m.height_cm ? `${m.height_cm}cm · ${m.weight_kg ?? "-"}kg (본인 신고)` : "-");
  fact(f, "학력", `${m.education_level ?? "-"}${m.school ? ` · ${m.school}` : ""}${m.major ? ` ${m.major}` : ""}  [학력 증빙 ${m.education_verified ? "통과" : "미확인 — 매칭 불가"}]`);
  fact(f, "직군 · 직장", `${m.job_group ?? "-"}${m.company ? ` · ${m.company}` : ""}  [재직 증빙 ${m.employment_verified ? "통과 — 직장 공개" : "미확인 — 직장 비공개"}]`);
  fact(f, "소개", m.introduction ?? "-", "long");
  if (m.status === "withdraw_pending") {
    fact(f, "탈퇴 요청", `${m.withdraw_by ?? "-"}${m.withdraw_by_role === "data_admin" ? " (총관리자)" : ""} · ${toKst(m.withdraw_requested_at)} → ${toKst(m.withdraw_at)} 삭제 예정`);
    fact(f, "탈퇴 사유", m.withdraw_reason || "(입력 안 함)", "long");
  }
  const yes = (v) => el("span", v ? "매칭함" : "-", v ? "pill" : "muted");
  fill("matches-body", "matches-empty", m.matches.map((x) =>
    row([withName(x.counterpart_pseudo_id, x.counterpart_name), yes(x.i_matched), yes(x.they_matched),
         x.matched ? el("span", "매칭 성사", "pill green") : el("span", "대기", "muted")])));
  const counselor = isCounselor();
  fill("consents-body", "consents-empty", m.consents.map((c) => {
    const cells = [withName(c.counterpart_pseudo_id, c.counterpart_name), c.item, c.purpose, toKst(c.expires_at),
                   pill(c.revoked_at ? "revoked" : c.valid ? "approved" : "rejected")];
    if (counselor) cells.push(c.valid && m.status === "active"
      ? actions(button("발송 요청", () => requestIntroduction(m, c), "btn sm primary")) : "-");
    return row(cells);
  }));
  box.hidden = false;
  box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function alertInline(node, text) { node.textContent = text; node.hidden = false; }

// ---- 반출 신청 (counselor) ----
async function loadRequests() {
  const { items } = await getJson("/api/export-requests");
  fill("requests-body", "requests-empty", items.map((r) =>
    row([r.label || mono(short(r.request_id)), r.recipient_pseudo_id ? withName(r.recipient_pseudo_id, r.recipient_name) : mono(short(r.recipient_id)), r.purpose,
         pill(r.request_status), toKst(r.expires_at), toKst(r.created_at)])));
}

// 매칭 동의로 소개 자료 발송 요청: 자료는 서버가 회원 DB 로 만든다
async function requestIntroduction(m, c) {
  const out = $("request-result");
  const res = await api(`/api/members/${m.member_id}/introductions`, { method: "POST", json: { consent_id: c.consent_id } });
  if (!res.ok) { showResult(out, await describe(res), false); out.scrollIntoView({ block: "nearest" }); return; }
  const r = await res.json();
  showResult(out, `${m.pseudo_id} → ${c.counterpart_pseudo_id} 발송 요청 완료 (승인 대기) · ${r.label}`, true);
  out.scrollIntoView({ block: "nearest" });
  loadRequests();
}

// ---- ② 회원 관리 (정보 수정·탈퇴) ----
async function loadManage() {
  const { items } = await getJson("/api/members");
  state.members = items;
  $("stat-members").textContent = items.length;
  $("stat-active").textContent = items.filter((m) => m.status === "active").length;
  $("stat-withdrawn").textContent = items.filter((m) => m.status === "withdraw_pending").length;
  $("stat-evidence").textContent = items.reduce((n, m) => n + (m.open_evidence || 0), 0);
  renderManage();
  if (state.me.role === "data_admin") await loadExports();
}

function renderManage() {
  const items = sortAndFilter(state.members, tableState.manage,
    ["pseudo_id", "name", "gender", "education_level", "job_group", "company", "counselors"]);
  $("manage-count").textContent = items.length === state.members.length
    ? `${items.length}명` : `${items.length}명 / 전체 ${state.members.length}명`;
  markSort("manage-head", "manage");
  fill("manage-body", "manage-empty", items.map((m) => {
    const active = m.status === "active";
    const ev = el("div");
    ev.append(el("span", "학력", m.education_verified ? "pill green" : "pill off"), document.createTextNode(" "),
              el("span", "재직", m.employment_verified ? "pill green" : "pill off"));
    return row([memberCell(m), m.name ?? "-", m.gender ?? "-", ageText(m), m.education_level ?? "-",
                `${m.job_group ?? "-"}${m.company ? ` · ${m.company}` : ""}`, ev, m.counselors || "미배정", memberStatus(m),
                active ? actions(button("수정", () => openEdit(m)),
                                 button("탈퇴", () => withdraw(m), "btn sm danger"))
                       : pendingActions(m)]);
  }));
}

function openEdit(m) {
  const f = $("edit-form").elements;
  f.member_id.value = m.member_id;
  for (const k of ["name", "gender", "birth_date", "height_cm", "weight_kg", "education_level", "school", "major",
                   "job_group", "company", "introduction"]) f[k].value = m[k] ?? "";
  $("edit-title").textContent = `회원 정보 수정 · ${m.pseudo_id} ${m.name ?? ""}`;
  $("edit-card").hidden = false;
  $("edit-card").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function saveEdit(ev) {
  ev.preventDefault();
  const f = ev.target.elements;
  const body = {};
  for (const k of ["name", "gender", "birth_date", "education_level", "school", "major", "job_group", "company", "introduction"]) {
    const v = f[k].value.trim();
    body[k] = v === "" ? null : v;
  }
  for (const k of ["height_cm", "weight_kg"]) body[k] = f[k].value === "" ? null : Number(f[k].value);
  const res = await api(`/api/members/${encodeURIComponent(f.member_id.value)}`, { method: "PATCH", json: body });
  let msg = "회원 정보를 수정했습니다.";
  if (res.ok) {
    const r = await res.json();
    if (!r.education_verified || !r.employment_verified) msg += ` (증빙 상태: 학력 ${r.education_verified ? "통과" : "미확인"}, 재직 ${r.employment_verified ? "통과" : "미확인"})`;
  }
  showResult($("manage-result"), res.ok ? msg : await describe(res), res.ok);
  if (res.ok) { $("edit-card").hidden = true; loadManage(); }
}

// 탈퇴 예정 회원의 버튼: 총관리자 → 철회·즉시 탈퇴 / 상담 직원 → 본인 쪽 요청만 철회 (총관리자 요청은 안내만)
function pendingActions(m) {
  if (state.me.role === "data_admin")
    return actions(button("탈퇴 철회", () => cancelWithdraw(m)), button("즉시 탈퇴", () => withdrawNow(m), "btn sm danger"));
  if (m.withdraw_by_role === "data_admin") return el("span", "총관리자가 탈퇴 요청함", "pill amber");
  return actions(button("탈퇴 철회", () => cancelWithdraw(m)));
}

const who2 = (m) => `${m.pseudo_id} ${m.name ?? ""}`.trim();

// 탈퇴: 1) 확인 팝업 → 2) 한 번 더 확인 → 탈퇴 예정(7일 유예). 즉시 탈퇴·철회는 탈퇴 예정 줄의 버튼으로
async function withdraw(m) {
  const first = await ask("회원 탈퇴", `${who2(m)} 회원을 탈퇴시키겠습니까?`, [
    { label: "확인", value: "yes", cls: "primary" }, { label: "취소", value: null }], "WITHDRAW", "탈퇴 사유 (선택, 200자 이내)");
  if (first !== "yes") return;
  const reason = state.askText;
  const ok = await ask("다시 확인", `${who2(m)} 회원은 탈퇴 예정 상태가 됩니다. 7일 동안 매칭·자료 제공이 멈추고, 그 사이 탈퇴를 철회하거나 즉시 탈퇴할 수 있습니다. 7일이 지나면 회원 정보가 DB에서 삭제됩니다.`, [
    { label: "확인", value: "yes", cls: "danger" }, { label: "취소", value: null }], "CONFIRM");
  if (ok !== "yes") return;
  await doWithdraw(m, "scheduled", reason);
}

// 탈퇴 예정 회원을 기한 전에 바로 삭제
async function withdrawNow(m) {
  const first = await ask("즉시 탈퇴", `탈퇴 예정인 ${who2(m)} 회원을 기다리지 않고 지금 탈퇴시키겠습니까?`, [
    { label: "확인", value: "yes", cls: "primary" }, { label: "취소", value: null }], "WITHDRAW");
  if (first !== "yes") return;
  const ok = await ask("다시 확인", `${who2(m)} 회원의 정보·동의·매칭·증빙 서류가 지금 DB에서 삭제되며 되돌릴 수 없습니다. 정말 진행할까요?`, [
    { label: "확인", value: "yes", cls: "danger" }, { label: "취소", value: null }], "CONFIRM");
  if (ok !== "yes") return;
  await doWithdraw(m, "immediate");
}

async function doWithdraw(m, mode, reason = "") {
  const res = await api(`/api/members/${m.member_id}/withdraw`, { method: "POST", json: { mode, reason: reason || null } });
  if (!res.ok) return showResult($("manage-result"), await describe(res), false);
  const r = await res.json();
  showResult($("manage-result"), mode === "scheduled"
    ? `${who2(m)} 탈퇴 예정 · ${toKst(r.withdraw_at)}에 삭제됩니다 (그 전에 철회 가능)`
    : `${who2(m)} 탈퇴 완료 · 회원 정보를 DB에서 삭제했습니다`, true);
  loadManage();
}

async function cancelWithdraw(m) {
  const ok = await ask("탈퇴 철회", `${who2(m)} 회원의 탈퇴 예정을 취소하고 활동 상태로 되돌릴까요?`, [
    { label: "확인", value: "yes", cls: "primary" }, { label: "취소", value: null }], "RESTORE");
  if (ok !== "yes") return;
  const res = await api(`/api/members/${m.member_id}/withdraw/cancel`, { method: "POST", json: {} });
  showResult($("manage-result"), res.ok ? `${who2(m)} 탈퇴를 철회했습니다` : await describe(res), res.ok);
  loadManage();
}

async function loadExports() {
  const { items } = await getJson("/api/admin/member-exports");
  fill("exports-body", "exports-empty", items.map((x) =>
    row([mono(short(x.export_id)),
         x.created_by_role === "data_admin" ? x.created_by : el("span", `${x.created_by} (${ROLE_NAMES[x.created_by_role] || x.created_by_role})`, "pill red"),
         x.row_count, x.transfer_file_id ? mono(short(x.transfer_file_id)) : "-", toKst(x.created_at)])));
}

async function runExport() {
  const res = await api("/api/admin/member-exports", { method: "POST" });
  if (!res.ok) return showResult($("export-result"), await describe(res), false);
  const x = await res.json();
  showResult($("export-result"), `내보내기 완료 · export_id ${x.export_id} · ${x.row_count}건 · ${toKst(x.created_at)}`, true);
  loadExports().catch(() => {});
}

// ---- ③ 회원·서류 조회·심사·승인 ----
async function loadReviews() {
  state.evidence = (await getJson("/api/evidence-files")).items;
  renderReviews();
}

function renderReviews() {
  const want = state.evFilter ? state.evFilter.split(",") : null;
  const items = state.evidence.filter((e) => !want || want.includes(e.status));
  fill("reviews-body", "reviews-empty", items.map((e) => {
    const open = ["submitted", "in_review"].includes(e.status);
    const status = e.status === "reviewed" && e.review_result
      ? el("span", e.review_result === "passed" ? "통과" : "반려", `pill ${e.review_result === "passed" ? "green" : "red"}`)
      : pill(e.status);
    return row([mono(short(e.file_id)), memberCell({ pseudo_id: e.member_pseudo_id }),
      e.member_name ?? "-", e.kind === "employment" ? "재직" : "학력", toKst(e.created_at), status, e.reviewer || "-",
      toKst(e.delete_after) + (e.legal_hold ? " (보존)" : ""),
      open ? actions(button("열람", () => openEvidence(e.file_id)),
                     button("통과", () => review(e.file_id, "passed")),
                     button("반려", () => review(e.file_id, "rejected"), "btn sm danger")) : "-"]);
  }));
}

async function openEvidence(id) {
  const win = window.open("", "_blank");       // 팝업 차단 회피: 클릭 시점에 창을 먼저 연다
  const res = await api(`/api/evidence-files/${id}/content`);
  if (!res.ok) {
    if (win) win.close();
    return showResult($("reviews-result"), await describe(res), false);
  }
  const url = URL.createObjectURL(await res.blob());
  if (win) { win.opener = null; win.location = url; } else { location.assign(url); }
  setTimeout(() => URL.revokeObjectURL(url), 60000);
  loadReviews();
}

async function review(id, result) {
  const res = await api(`/api/evidence-files/${id}/review`, { method: "POST", json: { result } });
  showResult($("reviews-result"), res.ok ? `심사 완료 (${result === "passed" ? "통과" : "반려"})` : await describe(res), res.ok);
  loadReviews();
}

// ---- 조회·심사·승인 (approver) ----
async function loadApprovals() {
  state.requests = (await getJson("/api/export-requests")).items;
  renderApprovals();
}

function renderApprovals() {
  const want = state.filter ? state.filter.split(",") : null;
  const items = state.requests.filter((r) => !want || want.includes(r.request_status));
  fill("approvals-body", "approvals-empty", items.map((r) => {
    const mine = r.requester_id === state.me.user_id;
    const btns = [button(r.request_status === "pending" && !mine ? "심사" : "상세", () => showRequest(r.request_id))];
    if (r.request_status === "approved" && (r.label || r.approval_id))
      btns.push(button("회수", () => revoke(r.label, r.approval_id), "btn sm danger"));
    const tr = row([r.label || mono(short(r.request_id)), who(r.requester_pseudo_id, r.requester_id),
                    who(r.recipient_pseudo_id && withName(r.recipient_pseudo_id, r.recipient_name), r.recipient_id), r.purpose,
                    pill(r.request_status), toKst(r.expires_at), actions(...btns)]);
    tr.dataset.id = r.request_id;
    return tr;
  }));
}

function fact(dl, label, value, cls) {
  dl.append(el("dt", label));
  const dd = el("dd", value ?? "-", cls);
  dl.append(dd);
}

async function showRequest(id) {
  const res = await api(`/api/export-requests/${id}`);
  if (!res.ok) return showResult($("approvals-result"), await describe(res), false);
  const r = await res.json();
  for (const tr of $("approvals-body").children) tr.classList.toggle("selected", tr.dataset.id === id);
  const mine = r.requester_id === state.me.user_id;
  $("detail-title").textContent = r.label ? `소개 자료 ${r.label}` : `신청 ${short(r.request_id)}`;
  $("detail-status").replaceChildren(pill(r.request_status));
  const facts = $("detail-facts");
  facts.replaceChildren();
  fact(facts, "자료 이름", r.label || short(r.request_id));
  fact(facts, "신청 직원", (r.requester_pseudo_id || r.requester_id) + (mine ? " (본인)" : ""));
  fact(facts, "자료 주인 회원", r.member_pseudo_id ? withName(r.member_pseudo_id, r.member_name) : r.member_id);
  fact(facts, "받는 회원", r.recipient_pseudo_id ? withName(r.recipient_pseudo_id, r.recipient_name) : r.recipient_id);
  fact(facts, "동의", r.consent_label || short(r.consent_id));
  fact(facts, "목적", r.purpose);
  fact(facts, "파일", r.label ? `${r.label}.json (v${r.file_version})` : `${short(r.file_id)} (v${r.file_version})`);
  fact(facts, "파일 해시", r.file_hash, "mono");
  fact(facts, "파일 검사", STATUS[r.scan_status]?.[0] || r.scan_status);
  fact(facts, "제공 기한", toKst(r.expires_at));
  fact(facts, "신청 시각", toKst(r.created_at));
  const prev = $("detail-preview");
  prev.replaceChildren();
  if (r.preview && typeof r.preview === "object") {
    const names = { member_pseudo_id: "이름", age_band: "나이", job_group: "직군 · 직장", introduction: "상세" };
    for (const [k, v] of Object.entries(r.preview)) fact(prev, names[k] || k, typeof v === "string" ? v : JSON.stringify(v), k === "introduction" ? "long" : "");
  } else {
    fact(prev, "미리보기", "표시할 수 없습니다 (검사 미통과 또는 반출 금지 파일)");
  }
  const act = $("detail-actions");
  act.replaceChildren();
  if (r.request_status === "pending" && !mine) {
    act.append(button("승인", () => decide(r.request_id, "approve"), "btn primary"),
               button("거절", () => decide(r.request_id, "reject"), "btn danger"));
  } else if (mine) {
    act.append(el("span", "본인이 신청한 건은 승인·거절할 수 없습니다.", "muted"));
  }
  $("request-detail").hidden = false;
}

async function decide(id, action) {
  const res = await api(`/api/export-requests/${id}/${action}`, { method: "POST", json: {} });
  if (!res.ok) return showResult($("approvals-result"), await describe(res), false);
  const r = await res.json();
  if (r.approval_id) $("revoke-id").value = state.requests.find((x) => x.request_id === id)?.label || "";
  $("request-detail").hidden = true;
  showResult($("approvals-result"),
    action === "approve" ? "승인 완료 · 받는 회원이 외부 화면에서 내려받을 수 있습니다" : "거절 완료", true);
  loadApprovals();
}

async function revoke(label, approvalId) {
  // 소개 자료 이름(A-001_file1)으로 회수. 이름이 없는 예전 건만 approval_id 로
  const res = label
    ? await api("/api/approvals/revoke-by-label", { method: "POST", json: { label } })
    : await api(`/api/approvals/${encodeURIComponent(approvalId)}/revoke`, { method: "POST", json: {} });
  showResult($("approvals-result"), res.ok ? `회수 완료 (${label || short(approvalId)}) · 받는 회원은 더 이상 내려받을 수 없습니다` : await describe(res), res.ok);
  loadApprovals();
}

// ---- 알림 (오른쪽 위 종) ----
const notif = { items: [], selected: new Set(), timer: null };
const KIND_ICON = { evidence_submitted: "📄", match_made: "💞", intro_requested: "📨", intro_decided: "✅",
  withdraw_requested: "⏳", withdraw_cancelled: "↩", member_deleted: "🗑", member_export: "⚠", member_assigned: "👤" };

function timeAgo(iso) {
  const sec = Math.max(0, (Date.now() - new Date(iso)) / 1000);
  if (sec < 60) return "방금";
  if (sec < 3600) return `${Math.floor(sec / 60)}분 전`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}시간 전`;
  return toKst(iso);
}

function setBadge(n) {
  const b = $("bell-badge");
  b.textContent = n > 99 ? "99+" : String(n);
  b.hidden = n <= 0;
  $("bell").setAttribute("aria-label", n > 0 ? `알림 ${n}개 읽지 않음` : "알림");
}

async function loadNotifications() {
  const res = await api("/api/notifications");
  if (!res.ok) return;
  const data = await res.json();
  notif.items = data.items;
  for (const id of [...notif.selected]) if (!data.items.some((x) => x.notification_id === id)) notif.selected.delete(id);
  setBadge(data.unread);
  renderNotifications();
}

function renderNotifications() {
  const list = $("notif-list");
  $("notif-empty").hidden = notif.items.length > 0;
  const unread = notif.items.filter((x) => !x.read).length;
  $("notif-summary").textContent = notif.items.length ? `읽지 않음 ${unread} · 전체 ${notif.items.length}` : "";
  list.replaceChildren(...notif.items.map((x) => {
    const li = el("li", null, `notif-item${x.read ? "" : " unread"}`);
    const cb = el("input"); cb.type = "checkbox"; cb.checked = notif.selected.has(x.notification_id);
    cb.setAttribute("aria-label", "선택");
    cb.onchange = () => { cb.checked ? notif.selected.add(x.notification_id) : notif.selected.delete(x.notification_id); syncNotifTools(); };
    const main = el("button", null, "notif-main"); main.type = "button";
    main.append(el("span", KIND_ICON[x.kind] || "🔔", "notif-icon"));
    const txt = el("span", null, "notif-text");
    txt.append(el("strong", x.title), el("span", x.body || "", "notif-body"), el("span", timeAgo(x.created_at), "notif-time"));
    main.append(txt);
    main.onclick = async () => {                       // 누르면 읽음 + 해당 화면으로
      if (!x.read) await markNotifications([x.notification_id]);
      if (x.link_view && document.querySelector(`#nav button[data-view="${x.link_view}"]:not([hidden])`)) {
        toggleNotifPanel(false);
        selectView(x.link_view);
      }
    };
    const ops = el("span", null, "notif-ops");
    if (!x.read) ops.append(button("읽음", () => markNotifications([x.notification_id]), "text-button"));
    ops.append(button("삭제", () => deleteNotifications([x.notification_id]), "text-button danger-text"));
    li.append(cb, main, ops);
    return li;
  }));
  syncNotifTools();
}

function syncNotifTools() {
  const n = notif.selected.size;
  $("notif-read-sel").disabled = n === 0;
  $("notif-delete-sel").disabled = n === 0;
  $("notif-read-sel").textContent = n ? `선택 읽음 (${n})` : "선택 읽음";
  $("notif-delete-sel").textContent = n ? `선택 삭제 (${n})` : "선택 삭제";
  const all = $("notif-select-all");
  all.checked = notif.items.length > 0 && n === notif.items.length;
  all.indeterminate = n > 0 && n < notif.items.length;
}

async function markNotifications(ids, all = false) {
  const res = await api("/api/notifications/read", { method: "POST", json: { ids, all } });
  if (res.ok) await loadNotifications();
}

async function deleteNotifications(ids, all = false) {
  const res = await api("/api/notifications/delete", { method: "POST", json: { ids, all } });
  if (res.ok) { ids.forEach((i) => notif.selected.delete(i)); if (all) notif.selected.clear(); await loadNotifications(); }
}

function toggleNotifPanel(open) {
  const p = $("notif-panel");
  const show = open ?? p.hidden;
  p.hidden = !show;
  $("bell").setAttribute("aria-expanded", String(show));
  if (show) loadNotifications();
}

function initNotifications() {
  $("bell").onclick = (e) => { e.stopPropagation(); toggleNotifPanel(); };
  $("notif-panel").onclick = (e) => e.stopPropagation();
  document.addEventListener("click", () => { if (!$("notif-panel").hidden && !$("confirm-dialog").open) toggleNotifPanel(false); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("notif-panel").hidden) toggleNotifPanel(false); });
  $("notif-read-all").onclick = () => markNotifications([], true);
  $("notif-delete-all").onclick = async () => {
    if (!notif.items.length) return;
    const ok = await ask("알림 모두 삭제", `알림 ${notif.items.length}개를 모두 삭제할까요?`, [
      { label: "확인", value: "yes", cls: "danger" }, { label: "취소", value: null }], "NOTIFICATIONS");
    if (ok === "yes") deleteNotifications([], true);
  };
  $("notif-read-sel").onclick = () => markNotifications([...notif.selected]);
  $("notif-delete-sel").onclick = () => deleteNotifications([...notif.selected]);
  $("notif-select-all").onchange = (e) => {
    notif.selected = new Set(e.target.checked ? notif.items.map((x) => x.notification_id) : []);
    renderNotifications();
  };
  loadNotifications();
  clearInterval(notif.timer);
  notif.timer = setInterval(() => { if (!document.hidden) loadNotifications(); }, 30000);   // 30초마다 확인
}

async function logout() {
  const res = await api("/auth/logout", { method: "POST" });
  location.assign(res.ok ? (await res.json()).logout_url : "/");
}

async function init() {
  $("logout-btn").onclick = logout;
  $("export-btn").onclick = async () => { $("export-btn").disabled = true; try { await runExport(); } finally { $("export-btn").disabled = false; } };
  $("revoke-form").onsubmit = (ev) => { ev.preventDefault(); revoke($("revoke-id").value.trim()); };
  $("edit-form").onsubmit = saveEdit;
  bindSort("members-head", "members", renderMembers);
  bindSort("manage-head", "manage", renderManage);
  $("members-search").oninput = (e) => { tableState.members.q = e.target.value; renderMembers(); };
  $("manage-search").oninput = (e) => { tableState.manage.q = e.target.value; renderManage(); };
  $("edit-cancel").onclick = () => { $("edit-card").hidden = true; };
  for (const chip of $("evidence-filters").querySelectorAll(".chip")) {
    chip.onclick = () => {
      state.evFilter = chip.dataset.status;
      for (const c of $("evidence-filters").querySelectorAll(".chip")) c.classList.toggle("active", c === chip);
      renderReviews();
    };
  }
  for (const chip of $("approval-filters").querySelectorAll(".chip")) {
    chip.onclick = () => {
      state.filter = chip.dataset.status;
      for (const c of $("approval-filters").querySelectorAll(".chip")) c.classList.toggle("active", c === chip);
      renderApprovals();
    };
  }
  const res = await api("/api/me");
  if (res.status === 200) { state.me = await res.json(); showApp(); } else { showLogin(); }
}

init();
