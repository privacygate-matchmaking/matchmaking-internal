


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
  if (res.status === 401 && path !== "/api/me") showLogin();
  return res;
}


async function describe(res) {
  try {
    const body = await res.json();
    if (body.error) return `${body.error.message} (${body.error.code}, 추적번호 ${body.error.trace_id})`;
  } catch (_) {             }
  return `응답 ${res.status}`;
}

async function getJson(path) {
  const res = await api(path);
  if (!res.ok) throw new Error(await describe(res));
  return res.json();
}


function toKst(iso) {
  return iso ? new Date(iso).toLocaleString("ko-KR", { timeZone: "Asia/Seoul" }) : "-";
}
const short = (id) => (id ? String(id).slice(0, 8) : "-");

function showResult(el, text, ok) {
  el.textContent = text;
  el.className = `result ${ok ? "ok" : "err"}`;
  el.hidden = false;
}


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
// 목록은 10개씩 페이지로 나눈다 (pager.js). 검색은 전체 행에서 하고 결과도 10개씩 나눈다.
const LIST_SEARCH = {
  "requests-body": "소개 자료·받는 회원·목적·상태로 검색",
  "exports-body": "내보내기 번호·실행 직원으로 검색",
  "reviews-body": "파일 이름·회원·이름·종류·상태·심사자로 검색",
  "approvals-body": "자료·신청 직원·받는 회원·목적·상태로 검색",
};
function fill(bodyId, emptyId, rows, opts = {}) {
  const body = $(bodyId);
  if (!window.ListPager) { body.replaceChildren(...rows); $(emptyId).hidden = rows.length > 0; return; }
  ListPager.apply(body, rows, { size: 10, empty: $(emptyId), search: !!LIST_SEARCH[bodyId],
                               placeholder: LIST_SEARCH[bodyId], ...opts });
}
const listKey = (st) => `${st.q || ""}|${st.key || ""}|${st.dir || ""}`;
function mono(text) { const s = el("span", text, "mono"); s.title = text || ""; return s; }

function who(pseudo, id) { const s = el("span", pseudo || short(id), pseudo ? "" : "mono"); s.title = id || ""; return s; }


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
    const visible = btn.dataset.roles.split(",").includes(role) &&
      (btn.dataset.view !== "meetings" || state.me.meeting_scheduling === true);
    btn.hidden = !visible;
    if (visible && !first) first = btn.dataset.view;
    btn.onclick = () => selectView(btn.dataset.view);
  }

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
  meetings: loadMeetings,
  staff_signups: loadStaffSignups,
  security: loadSecurity,
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


function memberStatus(m) {
  const p = pill(m.status || "active");
  if (m.status !== "withdraw_pending" || !m.withdraw_at) return p;
  const days = Math.max(0, Math.ceil((new Date(m.withdraw_at) - Date.now()) / 86400000));
  const d = el("div");
  d.append(p, el("span", `D-${days} · ${new Date(m.withdraw_at).toLocaleDateString("ko-KR", { timeZone: "Asia/Seoul" })} 삭제`, "sub-code"));
  if (m.withdraw_reason) { const r = el("span", `사유: ${m.withdraw_reason}`, "sub-code"); r.title = m.withdraw_reason; d.append(r); }
  return d;
}



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

const withName = (code, name) => (name ? `${code}(${name})` : code);
const ageText = (m) => (m.age != null ? `만 ${m.age}세` : "-");


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
    if (x == null) return 1;
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
         memberStatus(m), actions(button("상세", () => showMember(m.member_id)))])),
    { key: listKey(tableState.members), searching: !!tableState.members.q, label: "회원 목록 페이지" });
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
  memberMembershipFacts(f, m.membership);
  memberEvidenceFacts(f, m.verified_evidence || []);
  fact(f, "소개", m.introduction ?? "-", "long");
  if (m.status === "withdraw_pending") {
    const by = m.withdraw_by_role === "member" ? "회원 본인 신청"
             : `${m.withdraw_by ?? "-"}${m.withdraw_by_role === "data_admin" ? " (총관리자)" : ""}`;
    fact(f, "탈퇴 요청", `${by} · ${toKst(m.withdraw_requested_at)} → ${toKst(m.withdraw_at)} 삭제 예정`);
    fact(f, "탈퇴 사유", m.withdraw_reason || "(입력 안 함)", "long");
  }
  const counselor = isCounselor();
  const matchRoot = $("member-matching-panel");
  matchRoot.hidden = !counselor;
  if (counselor) StaffMatchingUI.render({root: matchRoot, memberId, api: matchingStaffApi, isCurrent: () => $("member-detail-title").textContent === m.pseudo_id});
  fill("consents-body", "consents-empty", m.consents.map((c) => {
    const cells = [withName(c.counterpart_pseudo_id, c.counterpart_name), c.item, c.purpose, toKst(c.expires_at),
                   pill(c.revoked_at ? "revoked" : c.valid ? "approved" : "rejected")];
    if (counselor) cells.push("기존 동의 기록 · 새 발송은 위 매칭 동의에서 요청");
    return row(cells);
  }), { key: m.member_id, label: "제공 동의 페이지" });
  box.hidden = false;
  box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// 회원 상세: 승인된 증빙 결과(학력·재직은 위 줄에 표시) — 요약만, 원본·추출 값은 없음
const EVIDENCE_FACT_ORDER = ["income", "property", "marital", "identity", "photo"];
function memberEvidenceFacts(f, items) {
  const byKind = Object.fromEntries(items.map((v) => [v.kind, v]));
  const shown = EVIDENCE_FACT_ORDER.filter((k) => byKind[k]);
  if (!shown.length) { fact(f, "증빙 확인", "학력·재직 외 승인된 증빙 없음"); return; }
  for (const k of shown) {
    const v = byKind[k];
    const dd = el("dd");
    dd.append(el("span", v.summary || "검토 완료", "fact-verified"),
              el("span", `  · 승인 ${v.reviewed_at ? toKst(v.reviewed_at) : "-"}`, "fact-note"));
    f.append(el("dt", `${KIND_KO[k] || k} 증빙`), dd);
  }
}

// 회원 상세: 유료/무료, 남은 이용권, 구매일 (중계 서버에서 확인, 결제 수단·주문 번호는 받지 않음)
function memberMembershipFacts(f, ms) {
  if (!ms || !ms.available) {
    const why = { no_account: "로그인 계정 없음", transfer_unreachable: "중계 서버 연결 안 됨" }[ms?.reason] || "확인할 수 없음";
    fact(f, "회원 구분", `확인 불가 (${why})`);
    return;
  }
  const w = ms.wallet || {};
  const plan = ms.plan?.name || "정회원";
  const dd = el("dd");
  dd.append(el("span", ms.paid ? `유료 회원 · ${plan}` : "무료 회원", ms.paid ? "pill green" : "pill off"));
  f.append(el("dt", "회원 구분"), dd);
  if (ms.paid) {
    fact(f, "이용권", `남은 ${w.available ?? 0}회 / 총 ${w.total ?? 0}회 (사용 ${w.used ?? 0} · 상대 응답 대기 ${w.reserved ?? 0})`
      + (w.expires_at ? ` · ${toKst(w.expires_at)}까지` : ""));
  } else if (w.total) {
    fact(f, "이용권", `만료됨 (총 ${w.total}회 중 사용 ${w.used ?? 0}회)`);
  }
  const paid = (ms.orders || []).filter((o) => o.status === "paid");
  fact(f, "구매일", ms.last_paid_at
    ? `${toKst(ms.last_paid_at)}${paid.length > 1 ? ` (구매 ${paid.length}회)` : ""}`
    : "구매 내역 없음");
}

function alertInline(node, text) { node.textContent = text; node.hidden = false; }


async function loadRequests() {
  const { items } = await getJson("/api/export-requests");
  fill("requests-body", "requests-empty", items.map((r) =>
    row([r.label || mono(short(r.request_id)), r.recipient_pseudo_id ? withName(r.recipient_pseudo_id, r.recipient_name) : mono(short(r.recipient_id)), r.purpose,
         pill(r.request_status), toKst(r.expires_at), toKst(r.created_at)])));
}


async function requestIntroduction(m, c) {
  const out = $("request-result");
  const res = await api(`/api/members/${m.member_id}/introductions`, { method: "POST", json: { consent_id: c.consent_id } });
  if (!res.ok) { showResult(out, await describe(res), false); out.scrollIntoView({ block: "nearest" }); return; }
  const r = await res.json();
  showResult(out, `${m.pseudo_id} → ${c.counterpart_pseudo_id} 발송 요청 완료 (승인 대기) · ${r.label}`, true);
  out.scrollIntoView({ block: "nearest" });
  loadRequests();
}


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
  }), { key: listKey(tableState.manage), searching: !!tableState.manage.q, label: "회원 관리 목록 페이지" });
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


function pendingActions(m) {
  if (state.me.role === "data_admin")
    return actions(button("탈퇴 철회", () => cancelWithdraw(m)), button("즉시 탈퇴", () => withdrawNow(m), "btn sm danger"));
  if (m.withdraw_by_role === "data_admin") return el("span", "총관리자가 탈퇴 요청함", "pill amber");
  return actions(button("탈퇴 철회", () => cancelWithdraw(m)));
}

const who2 = (m) => `${m.pseudo_id} ${m.name ?? ""}`.trim();


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


async function loadReviews() {
  state.evidence = (await getJson("/api/evidence-files")).items;
  renderReviews();
}

const KIND_KO = { education: "학력", employment: "재직", identity: "신분증", marital: "혼인관계", income: "소득",
                  property: "부동산", photo: "프로필 사진" };
const VERDICT = { verified: ["진위 확인", "green"], suspicious: ["진위 의심", "red"], unchecked: ["미확인", "amber"] };
const CHECK_KO = { issue_format: "발급번호 형식", issue_checksum: "발급번호 검증숫자", registry_found: "발급대장에 있음",
                   registry_kind: "문서 종류 일치", name_match: "성명 일치", birth_match: "생년월일 일치",
                   registry_revoked: "폐기 문서 아님", metadata_removed: "사진 메타데이터(위치 등) 제거" };
const PII_KO = { resident_number: "주민등록번호", phone: "전화번호", email: "이메일", account_number: "계좌번호",
                 address: "주소", name: "이름" };
const FIELD_KO = { name: "성명", birth: "생년월일", issue_no: "발급번호", amount: "금액(원)", degree: "학위", employed: "재직 표시" };

function verdictPill(e) {
  if (!e.inspection) return el("span", "검사 대기", "pill off");
  if (e.inspection === "failed") return el("span", "검사 실패", "pill amber");
  const [label, color] = VERDICT[e.verdict] || [e.verdict, ""];
  return el("span", label, `pill ${color}`);
}

function renderReviews() {
  const want = state.evFilter ? state.evFilter.split(",") : null;
  const items = state.evidence.filter((e) => !want || want.includes(e.status));
  fill("reviews-body", "reviews-empty", items.map((e) => {
    const open = ["submitted", "in_review"].includes(e.status);
    const status = e.status === "reviewed" && e.review_result
      ? el("span", e.review_result === "passed" ? "통과" : "반려", `pill ${e.review_result === "passed" ? "green" : "red"}`)
      : pill(e.status);
    if (e.result_summary) status.title = e.result_summary;
    const fname = el("span", e.file_name || short(e.file_id), "mono");
    fname.title = `서류 ID ${e.file_id}`;
    return row([fname, memberCell({ pseudo_id: e.member_pseudo_id }),
      e.member_name ?? "-", KIND_KO[e.kind] || e.kind, toKst(e.created_at), verdictPill(e), status, e.reviewer || "-",
      toKst(e.delete_after) + (e.legal_hold ? " (보존)" : ""),
      open ? actions(button("검사·심사", () => openReviewPanel(e)), button("원본", () => openEvidence(e.file_id)))
           : (e.review_result === "passed" ? actions(button("결과", () => openReviewPanel(e))) : "-")]);
  }), { key: state.evFilter ?? "", label: "제출 서류 페이지" });
}

function selectField(label, options, value) {
  const wrap = el("label", label, "confirm-input");
  const sel = document.createElement("select");
  sel.append(el("option", "선택", ""));
  sel.firstChild.value = "";
  for (const o of options) { const opt = el("option", o); opt.value = o; if (o === value) opt.selected = true; sel.append(opt); }
  wrap.append(sel);
  return [wrap, sel];
}

async function openReviewPanel(e) {
  const panel = $("review-panel");
  panel.hidden = false;
  panel.replaceChildren(el("p", "자동 검사 결과를 불러오는 중입니다…", "muted"));
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
  let x;
  try { x = await getJson(`/api/evidence-files/${e.file_id}/inspection`); }
  catch (err) { panel.replaceChildren(el("p", err.message, "result err")); return; }
  const open = ["submitted", "in_review"].includes(e.status);
  const head = el("div", null, "section-title");
  head.append(el("h3", `${x.file_name || e.file_name || ""} · ${KIND_KO[e.kind] || e.kind}`),
              actions(...[open ? button("원본 열람", () => openEvidence(e.file_id)) : null,
                          open ? button("자동 검사 다시 실행", async () => {
                            const r = await api(`/api/evidence-files/${e.file_id}/inspect`, { method: "POST" });
                            if (!r.ok) return showResult($("reviews-result"), await describe(r), false);
                            await loadReviews(); openReviewPanel(state.evidence.find((v) => v.file_id === e.file_id) || e);
                          }) : null,
                          button("닫기", () => { panel.hidden = true; })].filter(Boolean)));
  panel.replaceChildren(head);
  if (x.status === "pending") {
    panel.append(el("p", "자동 검사 대기 중입니다 (보통 수십 초 안에 끝납니다). 잠시 후 다시 열거나 '자동 검사 다시 실행'을 누르세요.", "muted"));
  } else if (x.status === "failed") {
    panel.append(el("p", `자동 검사 실패: ${x.error || "-"} · 원본을 직접 확인해 심사하세요.`, "result err"));
  } else {
    const [vl, vc] = VERDICT[x.verdict] || [x.verdict, ""];
    const info = el("div", null, "inspect-grid");
    const left = el("div");
    left.append(el("h4", "진위 판단 (합성 발급대장 대조)"), el("span", vl, `pill ${vc}`));
    const ul = el("ul", null, "checks");
    for (const [k, v] of Object.entries(x.checks || {})) {
      const bad = k === "registry_revoked" ? v : !v;
      ul.append(el("li", `${bad ? "✗" : "✓"} ${CHECK_KO[k] || k}`, bad ? "bad" : "ok"));
    }
    left.append(ul, el("h4", "탐지·가림 처리한 개인정보"));
    const det = Object.entries(x.detected || {});
    left.append(el("p", det.length ? det.map(([k, n]) => `${PII_KO[k] || k} ${n}건`).join(" · ") : "탐지된 항목 없음", "muted"));
    left.append(el("h4", "읽어 낸 값 (직원 확인용 · 다른 회원에게 제공 안 함)"));
    const dl = el("dl", null, "facts");
    for (const [k, v] of Object.entries(x.fields || {})) {
      if (v === null || v === undefined || v === "") continue;
      dl.append(el("dt", FIELD_KO[k] || k), el("dd", k === "amount" ? Number(v).toLocaleString("ko-KR") : String(v)));
    }
    left.append(dl, el("p", `검사 ${toKst(x.inspected_at)} · ${x.version}`, "muted"));
    const right = el("div");
    right.append(el("h4", e.kind === "photo" ? "검토용 사진 (메타데이터 제거본)" : "마스킹 사본 미리보기"));
    if (x.has_masked) {
      const img = document.createElement("img");
      img.className = "masked-preview";
      img.alt = "마스킹 사본";
      const r = await api(`/api/evidence-files/${e.file_id}/masked`);
      if (r.ok) { img.src = URL.createObjectURL(await r.blob()); img.onload = () => setTimeout(() => URL.revokeObjectURL(img.src), 1000); right.append(img); }
    } else right.append(el("p", e.kind === "identity" ? "신분증은 사본을 만들지 않습니다." : "사본 없음", "muted"));
    info.append(left, right);
    panel.append(info);
  }
  if (!open) return;
  const opt = x.options || {};
  const proposed = x.proposed || {};
  const form = el("div", null, "review-form");
  let collect = () => ({});
  if (e.kind === "marital") {
    const [w, sel] = selectField("공개할 혼인관계", opt.marital || [], proposed.status);
    form.append(w); collect = () => ({ status: sel.value });
  } else if (e.kind === "income") {
    const [w, sel] = selectField("공개할 연소득 구간", opt.income_bands || [], proposed.band);
    form.append(w); collect = () => ({ band: sel.value });
  } else if (e.kind === "property") {
    const [w1, owns] = selectField("부동산 보유", ["보유", "보유 내역 없음"], proposed.owns === true ? "보유" : proposed.owns === false ? "보유 내역 없음" : "");
    const [w2, region] = selectField("소재 시·도 (보유 시)", opt.regions || [], proposed.region);
    form.append(w1, w2); collect = () => (owns.value === "보유" ? { owns: true, region: region.value } : owns.value ? { owns: false } : {});
  }
  form.append(el("p", e.kind === "identity" ? "통과하면 '본인 확인 완료'로만 기록됩니다." :
    "통과하면 위 공개 사실(구간·여부)로 요약이 만들어지고, 마스킹 사본이 결과로 보관됩니다.", "muted"));
  form.append(actions(
    button("통과", () => review(e.file_id, "passed", collect()), "btn sm primary"),
    button("반려", () => review(e.file_id, "rejected"), "btn sm danger")));
  panel.append(form);
}

async function openEvidence(id) {
  const win = window.open("", "_blank");
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

async function review(id, result, facts) {
  const res = await api(`/api/evidence-files/${id}/review`, { method: "POST", json: facts ? { result, facts } : { result } });
  showResult($("reviews-result"), res.ok ? `심사 완료 (${result === "passed" ? "통과" : "반려"})` : await describe(res), res.ok);
  if (res.ok) $("review-panel").hidden = true;
  loadReviews();
}


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
    const tr = row([materialName(r), who(r.requester_pseudo_id, r.requester_id),
                    who(r.recipient_pseudo_id && withName(r.recipient_pseudo_id, r.recipient_name), r.recipient_id), r.purpose,
                    pill(r.request_status), toKst(r.expires_at), actions(...btns)]);
    tr.dataset.id = r.request_id;
    return tr;
  }), { key: state.filter ?? "", label: "발송 신청 페이지" });
}

const SCOPE_KO = { name: "이름", profile: "공개 소개", education: "학력", employment: "재직", income: "소득 구간", marital_status: "혼인관계",
  property: "부동산", photo: "프로필 사진", documents: "마스킹 문서 사본", contact: "연락처" };

// 자료 이름: 기존 소개 자료는 이름(A-001_file1), 매칭 자료는 "자료 주인 → 받는 회원" + 짧은 번호
function materialName(r) {
  if (r.label) return r.label;
  const owner = r.member_pseudo_id ? withName(r.member_pseudo_id, r.member_name) : "자료 주인";
  const to = r.recipient_pseudo_id ? withName(r.recipient_pseudo_id, r.recipient_name) : "받는 회원";
  const box = el("span");
  box.append(el("strong", `${owner} → ${to}`), el("span", ` #${short(r.request_id)}`, "muted"));
  return box;
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
  const ownerText = r.member_pseudo_id ? withName(r.member_pseudo_id, r.member_name) : "자료 주인";
  const toText = r.recipient_pseudo_id ? withName(r.recipient_pseudo_id, r.recipient_name) : "받는 회원";
  $("detail-title").textContent = r.label ? `소개 자료 ${r.label}` : `${ownerText}의 자료 → ${toText}`;
  $("detail-status").replaceChildren(pill(r.request_status));
  const facts = $("detail-facts");
  facts.replaceChildren();
  fact(facts, "자료 이름", r.label || `${ownerText}의 소개 자료 (#${short(r.request_id)})`);
  const scopes = r.preview && Array.isArray(r.preview.scopes) ? r.preview.scopes : null;
  if (scopes) fact(facts, "제공 항목", scopes.map((x) => SCOPE_KO[x] || x).join(" · "));
  fact(facts, "신청 직원", (r.requester_pseudo_id || r.requester_id) + (mine ? " (본인)" : ""));
  fact(facts, "자료 주인 회원", r.member_pseudo_id ? withName(r.member_pseudo_id, r.member_name) : r.member_id);
  fact(facts, "받는 회원", r.recipient_pseudo_id ? withName(r.recipient_pseudo_id, r.recipient_name) : r.recipient_id);
  fact(facts, "동의", r.consent_label || short(r.consent_id));
  fact(facts, "목적", r.purpose === 'matching_introduction' ? '매칭 동의에 따른 검토 결과 제공' : r.purpose);
  fact(facts, "파일", r.label ? `${r.label}.json (v${r.file_version})` : `${short(r.file_id)} (v${r.file_version})`);
  fact(facts, "파일 해시", r.file_hash, "mono");
  fact(facts, "파일 검사", STATUS[r.scan_status]?.[0] || r.scan_status);
  fact(facts, "제공 기한", toKst(r.expires_at));
  fact(facts, "신청 시각", toKst(r.created_at));
  const prev = $("detail-preview");
  prev.replaceChildren();
  if (r.preview && typeof r.preview === "object") {
    const names = { schema_version: "자료 형식", member_id: "자료 주인 UUID", recipient_id: "수신자 UUID", grant_id: "회원 공개 동의 ID", match_id: "매칭 ID", scopes: "제공 항목", purpose: "제공 목적", display_name: "이름", age_band: "나이", job_group: "직군 · 직장", introduction: "상세" };
    for (const [k, v] of Object.entries(r.preview)) {
      if (k === 'fields' && Array.isArray(v)) {
        for (const field of v) fact(prev, field.label, `${field.value} · 검토 ${toKst(field.reviewed_at)}`, 'long');
      } else if (k === "scopes" && Array.isArray(v)) fact(prev, names[k], v.map((x) => SCOPE_KO[x] || x).join(" · "));
      else fact(prev, names[k] || k, typeof v === "string" ? v : JSON.stringify(v), k === "introduction" ? "long" : "");
    }
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

  const res = label
    ? await api("/api/approvals/revoke-by-label", { method: "POST", json: { label } })
    : await api(`/api/approvals/${encodeURIComponent(approvalId)}/revoke`, { method: "POST", json: {} });
  showResult($("approvals-result"), res.ok ? `회수 완료 (${label || short(approvalId)}) · 받는 회원은 더 이상 내려받을 수 없습니다` : await describe(res), res.ok);
  loadApprovals();
}


const notif = { items: [], selected: new Set(), timer: null };
const KIND_ICON = { security_incident: "🛡️", evidence_submitted: "📄", match_made: "💞", intro_requested: "📨", intro_decided: "✅",
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
    main.onclick = async () => {
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
  notif.timer = setInterval(() => { if (!document.hidden) loadNotifications(); }, 30000);
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
  if (res.status === 200) { state.me = await res.json(); showApp(); }
  else {
    showLogin();
    if (res.status === 403) {   // 자동 임시 잠금·정지 등: 서버 안내 문구를 로그인 화면에 보여 준다
      const body = await res.json().catch(() => ({}));
      $("login-msg").textContent = body.error?.message || "지금은 이 계정을 사용할 수 없습니다.";
      $("login-msg").hidden = false;
    }
  }
}

init();


async function loadMeetings() {
  await StaffMatchingUI.render({root: $('matching-overview-panel'), api: matchingStaffApi,
    isCurrent: () => Boolean(document.querySelector('#nav button.active[data-view="meetings"]'))});
}

async function matchingStaffApi(path, options = {}) {
  const res = await api(path, {method: options.method || "GET", ...(options.body !== undefined ? {json: options.body} : {})});
  if (!res.ok) throw new Error(await describe(res));
  return res.json();
}


async function loadStaffSignups() {
  $("staff-signup-result").hidden = true;
  await StaffSignupUI.renderAdmin({
    root: $("staff-signup-panel"), api, describe,
    toast: (text) => showResult($("staff-signup-result"), text, !/추적번호|실패|못했/.test(text)),
    confirmAsk: async (text) => (await ask("직원 가입 신청 처리", text,
      [{ label: "취소", value: "" }, { label: "확인", value: "ok", cls: "primary" }])) === "ok",
  });
}


async function loadSecurity() {
  $("security-result").hidden = true;
  await SecurityUI.render({
    root: $("security-panel"), api, describe,
    ask, lastNote: () => state.askText || null,
    toast: (text) => showResult($("security-result"), text, !/추적번호|실패|못했/.test(text)),
  });
}
