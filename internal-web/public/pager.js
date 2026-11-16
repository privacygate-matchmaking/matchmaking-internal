// 직원 화면 목록 공통 페이지 나누기 (10개씩) + 전체 목록 검색.
// ListPager.apply(tbody, rows, opts)
//   rows   : 전체 행(<tr>) 배열. 검색은 이 전체 배열에서 하고, 결과를 다시 10개씩 나눈다.
//   opts.size     한 페이지 행 수 (기본 10)
//   opts.empty    빈 목록 안내 요소 (없으면 생략)
//   opts.search   true 면 표 위에 검색창을 만든다 (이미 검색창이 있는 목록은 false)
//   opts.searching 바깥 검색창에 검색어가 있는지 (빈 결과 문구를 "검색 결과가 없습니다." 로)
//   opts.key      검색어·필터 등. 바뀌면 1페이지로 돌아간다
//   opts.label    페이지 이동 영역 이름 (화면 읽기 프로그램용)
(function () {
  const states = new WeakMap();

  function numbers(page, pages) {
    if (pages <= 7) return Array.from({ length: pages }, (_, i) => i + 1);
    const out = [1];
    const from = Math.max(2, page - 1), to = Math.min(pages - 1, page + 1);
    if (from > 2) out.push(null);
    for (let i = from; i <= to; i++) out.push(i);
    if (to < pages - 1) out.push(null);
    out.push(pages);
    return out;
  }

  function make(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function anchor(tbody) {
    return tbody.closest('.tablewrap') || tbody.closest('table') || tbody;
  }

  function setup(tbody, opts) {
    const st = { rows: [], page: 1, q: '', key: undefined, opts };
    const at = anchor(tbody);
    st.nav = make('nav', 'pager');
    st.nav.setAttribute('aria-label', opts.label || '목록 페이지');
    at.after(st.nav);
    if (opts.search) {
      const bar = make('div', 'searchbar');
      const input = make('input');
      input.type = 'search';
      input.placeholder = opts.placeholder || '목록 전체에서 검색';
      input.setAttribute('aria-label', opts.placeholder || '목록 검색');
      input.oninput = () => { st.q = input.value.trim().toLowerCase(); st.page = 1; draw(tbody, st); };
      bar.append(input);
      at.before(bar);
      st.input = input;
    }
    if (st.opts.empty && st.baseEmpty === undefined) st.baseEmpty = st.opts.empty.textContent;
    states.set(tbody, st);
    return st;
  }

  function draw(tbody, st) {
    const { size = 10, empty } = st.opts;
    const q = st.q;
    const rows = q ? st.rows.filter((r) => r.textContent.toLowerCase().includes(q)) : st.rows;
    const pages = Math.max(1, Math.ceil(rows.length / size));
    st.page = Math.min(Math.max(1, st.page), pages);
    const start = (st.page - 1) * size;
    tbody.replaceChildren(...rows.slice(start, start + size));
    if (empty) {
      empty.hidden = rows.length > 0;
      const noMatch = !rows.length && (q ? st.rows.length > 0 : !!st.opts.searching);
      empty.textContent = noMatch ? '검색 결과가 없습니다.' : st.baseEmpty;
    }
    const nav = st.nav;
    nav.replaceChildren();
    nav.hidden = rows.length <= size;
    if (nav.hidden) return;
    const go = (p) => { st.page = p; draw(tbody, st); anchor(tbody).scrollIntoView({ block: 'nearest' }); };
    const step = (text, p, disabled, label) => {
      const b = make('button', 'pager-step', text);
      b.type = 'button'; b.disabled = disabled; b.setAttribute('aria-label', label);
      b.onclick = () => go(p);
      return b;
    };
    nav.append(step('‹', st.page - 1, st.page === 1, '이전 페이지'));
    for (const n of numbers(st.page, pages)) {
      if (n === null) { nav.append(make('span', 'pager-gap', '…')); continue; }
      const b = make('button', 'pager-num', String(n));
      b.type = 'button';
      if (n === st.page) { b.classList.add('current'); b.setAttribute('aria-current', 'page'); }
      b.onclick = () => go(n);
      nav.append(b);
    }
    nav.append(step('›', st.page + 1, st.page === pages, '다음 페이지'));
    nav.append(make('span', 'pager-info', `${rows.length}건 중 ${start + 1}–${Math.min(start + size, rows.length)}`));
  }

  function apply(tbody, rows, opts = {}) {
    const st = states.get(tbody) || setup(tbody, opts);
    st.opts = { ...st.opts, ...opts, search: st.opts.search };
    if (st.opts.empty && st.baseEmpty === undefined) st.baseEmpty = st.opts.empty.textContent;
    if (opts.key !== undefined && opts.key !== st.key) { st.page = 1; st.key = opts.key; }
    st.rows = rows;
    draw(tbody, st);
  }

  window.ListPager = { apply, numbers };
})();
