'use strict';
window.StaffMatchingUI = (() => {
  const states={pending:'상대 응답 대기',matched:'매칭 성사',rejected:'거절',cancelled:'신청 취소',expired:'응답 기한 만료',ended:'관계 종료',approved:'반출 승인',revoked:'철회'};
  const names={profile:'공개 소개',education:'학력 확인',employment:'재직 확인',photo:'사진',contact:'연락처',income:'소득',marital_status:'혼인 정보'};
  const date=v=>v?new Date(v).toLocaleString('ko-KR',{timeZone:'Asia/Seoul'}):'—';
  const el=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;};
  async function render(ctx) {
    const {root,api}=ctx;
    root.replaceChildren(el('p','신청·동의 현황을 불러오는 중입니다.'));
    try {
      const data=await api('/api/matching/overview'+(ctx.memberId?'?member_id='+encodeURIComponent(ctx.memberId):''));
      if(ctx.isCurrent&&!ctx.isCurrent())return;
      root.replaceChildren(el('h3','회원 신청·공개 동의 현황'));
      const refresh=el('button','현황 새로고침');refresh.type='button';refresh.className='btn sm';refresh.onclick=()=>render(ctx);root.append(refresh);
      if(!data.items.length)root.append(el('p','담당 회원의 매칭 신청 내역이 없습니다.'));
      for(const item of data.items) {
        const card=el('article');card.className='card mt16';
        card.append(el('h4',item.label||'담당 회원 매칭'),el('p',(states[item.status]||item.status)+' · 신청 '+date(item.created_at)));
        if(!item.grants.length)card.append(el('p','회원이 직접 설정한 공개 동의가 아직 없습니다.'));
        for(const g of item.grants) {
          const group=el('div');group.className='mt16';
          group.append(el('strong',`${g.owner_label||'자료 주인'} → ${g.recipient_label||'소개 상대'}`),
            el('p',g.scopes.map(s=>names[s]||s).join(' · ')),
            el('p',`${g.revoked_at?'철회':g.active?'유효':'만료 또는 관계 종료'} · 기한 ${date(g.expires_at)}`));
          if(g.can_prepare&&g.supported_scopes.length) {
            const form=el('form');const checks=[];
            form.append(el('p','동의된 항목 중 이번에 보낼 검토 결과를 선택하세요. 원본·실명·연락처는 포함하지 않습니다.'));
            for(const s of g.supported_scopes) {
              const label=el('label');const input=el('input');input.type='checkbox';input.value=s;input.checked=true;
              label.append(input,document.createTextNode(names[s]));form.append(label);checks.push(input);
            }
            const send=el('button','선택한 항목으로 발송 승인 요청');send.type='submit';send.className='btn primary sm';
            const result=el('p');result.setAttribute('role','status');form.append(send,result);
            form.onsubmit=async e=>{
              e.preventDefault();const scopes=checks.filter(c=>c.checked).map(c=>c.value);
              if(!scopes.length){result.textContent='제공할 항목을 선택하세요.';return;}
              if(!confirm('선택한 공개 항목으로 자료를 만들고 별도 승인 담당자에게 요청할까요?'))return;
              send.disabled=true;
              try{await api('/api/matching/releases',{method:'POST',body:{grant_id:g.grant_id,scopes}});await render(ctx);}
              catch(error){result.textContent=error.message;send.disabled=false;}
            };
            group.append(form);
          }
          for(const r of item.releases.filter(r=>r.consent_id===g.grant_id))group.append(el('p','자료 발송: '+(states[r.request_status]||r.request_status)+' · '+date(r.expires_at)));
          card.append(group);
        }
        card.append(el('p','매칭 수락은 공개 동의가 아닙니다. 성사된 건의 일정은 아래 만남 일정 관리에서 조율합니다.'));
        root.append(card);
      }
    }catch(error){root.replaceChildren(el('p',error.message));}
  }
  return {render};
})();
