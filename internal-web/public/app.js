// PrivacyGate 내부 화면
// 메뉴 숨김은 사용 편의일 뿐 보안 통제가 아니다. 권한은 internal-api 가 매 요청 확인한다.
const state = { me: null };
const $ = (id) => document.getElementById(id);

const ROLE_NAMES = { counselor: "상담", data_admin: "데이터 관리", approver: "승인" };

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const method = (options.method || "GET").toUpperCase();
  if (method !== "GET" && state.me) headers["X-CSRF-Token"] = state.me.csrf_token;
  return fetch(path, { ...options, method, headers, credentials: "same-origin" });
}

// 오류 응답 {"error": {code, message, trace_id}} 를 한 줄로
async function describe(res) {
  try {
    const { error } = await res.json();
    if (error) return `${error.message} (${error.code}, 추적번호 ${error.trace_id})`;
  } catch (_) { /* 본문 없음 */ }
  return `응답 ${res.status}`;
}

// 서버는 UTC 로 주고, 화면은 한국 시간으로 표시
function toKst(iso) {
  return new Date(iso).toLocaleString("ko-KR", { timeZone: "Asia/Seoul" });
}
window.toKst = toKst;

function showLogin() {
  $("login-view").hidden = false;
  $("app-view").hidden = true;
  $("user-box").hidden = true;
  if (new URLSearchParams(location.search).get("login") === "failed") {
    $("login-msg").textContent = "로그인하지 못했습니다. 직원 계정인지 확인하세요.";
    $("login-msg").hidden = false;
  }
}

function showApp() {
  const { pseudo_id, role } = state.me;
  $("login-view").hidden = true;
  $("app-view").hidden = false;
  $("user-box").hidden = false;
  $("user-label").textContent = `${pseudo_id} · ${ROLE_NAMES[role] || role}`;
  let first = null;
  for (const tab of $("tabs").querySelectorAll("button")) {
    const visible = tab.dataset.roles.split(",").includes(role);
    tab.hidden = !visible;
    if (visible && !first) first = tab.dataset.view;
    tab.onclick = () => selectView(tab.dataset.view);
  }
  if (first) selectView(first);
}

function selectView(name) {
  for (const tab of $("tabs").querySelectorAll("button")) tab.classList.toggle("active", tab.dataset.view === name);
  for (const view of document.querySelectorAll(".view")) view.hidden = view.dataset.view !== name;
}

async function logout() {
  const res = await api("/auth/logout", { method: "POST" });
  location.assign(res.ok ? (await res.json()).logout_url : "/");
}

async function runExport() {
  const res = await api("/api/admin/member-exports", { method: "POST" });
  $("export-result").textContent = res.ok ? "요청 완료" : await describe(res);
}

async function init() {
  $("logout-btn").onclick = logout;
  $("export-btn").onclick = runExport;
  const res = await api("/api/me");
  if (res.status === 200) { state.me = await res.json(); showApp(); } else { showLogin(); }
}

init();
