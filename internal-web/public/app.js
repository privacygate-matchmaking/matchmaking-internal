// PrivacyGate 내부 화면
// 메뉴 숨김은 사용 편의일 뿐 보안 통제가 아니다. 권한은 internal-api 가 매 요청 확인한다.
// 서버 문자열은 모두 textContent 로만 넣는다 (innerHTML 금지, CSP 로 인라인 스크립트·스타일 차단).
const state = { me: null, members: [], consents: {}, requests: [], filter: "" };
const $ = (id) => document.getElementById(id);

const ROLE_NAMES = { counselor: "상담", data_admin: "총관리자", approver: "승인" };
const STATUS = {
  pending: ["대기", "amber"], approved: ["승인", "green"], rejected: ["거절", "red"], revoked: ["회수", "red"],
  active: ["활동", "green"], withdrawn: ["탈퇴", ""],
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
function memberStatus(m) { return pill(m.status || "active"); }

async function loadMembers() {
  const { items } = await getJson("/api/members");
  state.members = items;
  $("members-count").textContent = `${items.length}명`;
  fill("members-body", "members-empty", items.map((m) =>
    row([m.pseudo_id, m.birth_year, m.job, m.counselors || "미배정", m.valid_consents, memberStatus(m),
         actions(button("상세", () => showMember(m.member_id)))])));
}

async function showMember(memberId) {
  const box = $("member-detail");
  const res = await api(`/api/members/${memberId}`);
  if (!res.ok) { box.hidden = true; return alertInline($("members-empty"), await describe(res)); }
  const m = await res.json();
  state.consents[m.member_id] = m.consents;
  $("member-detail-title").textContent = `${m.pseudo_id} · ${m.birth_year ?? "-"} · ${m.job ?? "-"}`;
  $("member-detail-status").replaceChildren(pill(m.status));
  const yes = (v) => el("span", v ? "매칭함" : "-", v ? "pill" : "muted");
  fill("matches-body", "matches-empty", m.matches.map((x) =>
    row([x.counterpart_pseudo_id, yes(x.i_matched), yes(x.they_matched),
         x.matched ? el("span", "매칭 성사", "pill green") : el("span", "대기", "muted")])));
  const counselor = isCounselor();
  fill("consents-body", "consents-empty", m.consents.map((c) => {
    const cells = [c.counterpart_pseudo_id, c.item, c.purpose, toKst(c.expires_at),
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
    row([mono(short(r.request_id)), mono(short(r.file_id)), r.purpose, pill(r.request_status),
         toKst(r.expires_at), toKst(r.created_at)])));
}

// 매칭 동의로 소개 자료 발송 요청: 자료는 서버가 회원 DB 로 만든다
async function requestIntroduction(m, c) {
  const out = $("request-result");
  const res = await api(`/api/members/${m.member_id}/introductions`, { method: "POST", json: { consent_id: c.consent_id } });
  if (!res.ok) { showResult(out, await describe(res), false); out.scrollIntoView({ block: "nearest" }); return; }
  const r = await res.json();
  showResult(out, `${m.pseudo_id} → ${c.counterpart_pseudo_id} 발송 요청 완료 (승인 대기) · 신청 ${short(r.request_id)} · "${r.profile.introduction}"`, true);
  out.scrollIntoView({ block: "nearest" });
  loadRequests();
}

// ---- ② 회원 관리 (정보 수정·탈퇴) ----
async function loadManage() {
  const { items } = await getJson("/api/members");
  state.members = items;
  $("stat-members").textContent = items.length;
  $("stat-active").textContent = items.filter((m) => m.status === "active").length;
  $("stat-withdrawn").textContent = items.filter((m) => m.status === "withdrawn").length;
  $("stat-evidence").textContent = items.reduce((n, m) => n + (m.open_evidence || 0), 0);
  fill("manage-body", "manage-empty", items.map((m) => {
    const active = m.status === "active";
    return row([m.pseudo_id, m.birth_year ?? "-", m.job ?? "-", m.counselors || "미배정",
                m.has_account ? "있음" : "-", memberStatus(m),
                active ? actions(button("수정", () => openEdit(m)),
                                 button("탈퇴", () => withdraw(m), "btn sm danger")) : "-"]);
  }));
  if (state.me.role === "data_admin") await loadExports();
}

function openEdit(m) {
  const f = $("edit-form").elements;
  f.member_id.value = m.member_id;
  f.birth_year.value = m.birth_year ?? "";
  f.job.value = m.job ?? "";
  $("edit-title").textContent = `회원 정보 수정 · ${m.pseudo_id}`;
  $("edit-card").hidden = false;
  $("edit-card").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function saveEdit(ev) {
  ev.preventDefault();
  const f = ev.target.elements;
  const res = await api(`/api/members/${encodeURIComponent(f.member_id.value)}`, {
    method: "PATCH", json: { birth_year: Number(f.birth_year.value), job: f.job.value.trim() } });
  showResult($("manage-result"), res.ok ? "회원 정보를 수정했습니다." : await describe(res), res.ok);
  if (res.ok) { $("edit-card").hidden = true; loadManage(); }
}

async function withdraw(m) {
  // confirm() 대화상자 대신 같은 버튼을 한 번 더 누르게 한다 (실수 방지)
  if (state.pendingWithdraw !== m.member_id) {
    state.pendingWithdraw = m.member_id;
    showResult($("manage-result"), `${m.pseudo_id} 탈퇴: 이름·연락처 삭제, 동의·매칭 철회. 되돌릴 수 없습니다. 진행하려면 '탈퇴'를 한 번 더 누르세요.`, false);
    return;
  }
  state.pendingWithdraw = null;
  const res = await api(`/api/members/${m.member_id}/withdraw`, { method: "POST", json: {} });
  if (!res.ok) return showResult($("manage-result"), await describe(res), false);
  const r = await res.json();
  showResult($("manage-result"), `${m.pseudo_id} 탈퇴 처리 완료 · 철회된 동의 ${r.revoked_consents}건`, true);
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
    return row([mono(short(e.file_id)), e.member_pseudo_id, toKst(e.created_at), status, e.reviewer || "-",
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
    const tr = row([mono(short(r.request_id)), mono(short(r.requester_id)), mono(short(r.recipient_id)), r.purpose,
                    pill(r.request_status), toKst(r.expires_at),
                    actions(button(r.request_status === "pending" && !mine ? "심사" : "상세", () => showRequest(r.request_id)))]);
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
  $("detail-title").textContent = `신청 ${short(r.request_id)}`;
  $("detail-status").replaceChildren(pill(r.request_status));
  const facts = $("detail-facts");
  facts.replaceChildren();
  fact(facts, "신청 ID", r.request_id, "mono");
  fact(facts, "신청자", r.requester_id + (mine ? " (본인)" : ""), "mono");
  fact(facts, "정보 주체 회원", r.member_id, "mono");
  fact(facts, "수신 회원", r.recipient_id, "mono");
  fact(facts, "동의 ID", r.consent_id, "mono");
  fact(facts, "목적", r.purpose);
  fact(facts, "파일", `${r.file_id} (v${r.file_version})`, "mono");
  fact(facts, "파일 해시", r.file_hash, "mono");
  fact(facts, "파일 검사", STATUS[r.scan_status]?.[0] || r.scan_status);
  fact(facts, "반출 기한", toKst(r.expires_at));
  fact(facts, "신청 시각", toKst(r.created_at));
  const prev = $("detail-preview");
  prev.replaceChildren();
  if (r.preview && typeof r.preview === "object") {
    const names = { member_pseudo_id: "회원(가명 ID)", age_band: "연령대", job_group: "직군", introduction: "소개" };
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
  if (r.approval_id) $("revoke-id").value = r.approval_id;
  $("request-detail").hidden = true;
  showResult($("approvals-result"),
    action === "approve" ? `승인 완료 · approval_id ${r.approval_id} (회수할 때 필요)` : "거절 완료", true);
  loadApprovals();
}

async function revoke(approvalId) {
  const res = await api(`/api/approvals/${encodeURIComponent(approvalId)}/revoke`, { method: "POST", json: {} });
  showResult($("approvals-result"), res.ok ? "회수 완료 · 수신자는 더 이상 내려받을 수 없습니다" : await describe(res), res.ok);
  loadApprovals();
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
