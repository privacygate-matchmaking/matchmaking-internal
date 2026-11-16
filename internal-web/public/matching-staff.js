'use strict';
window.StaffMatchingUI = (() => {
  const states={pending:'상대 응답 대기',matched:'매칭 성사',rejected:'거절',cancelled:'신청 취소',expired:'응답 기한 만료',ended:'관계 종료',approved:'반출 승인',revoked:'철회'};
  const names={name:'이름',profile:'공개 소개',education:'학력 확인',employment:'재직 확인',income:'소득 구간',marital_status:'혼인관계',property:'부동산',photo:'검토된 프로필 사진',documents:'마스킹 문서 사본',contact:'연락처'};
  const date=v=>v?new Date(v).toLocaleString('ko-KR',{timeZone:'Asia/Seoul'}):'—';
  const el=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;};
  const meetingNames={none:'제안 없음',proposed:'회원 간 조율 중',awaiting_approval:'승인 대기',confirmed:'확정'};
  function cell(row,content){const td=el('td');if(content&&typeof content==='object')td.append(content);else td.textContent=content;row.append(td);}

  async function render(ctx) {
    const {root,api}=ctx;
    root.replaceChildren(el('p','신청·동의 현황을 불러오는 중입니다.'));
    try {
      const data=await api('/api/matching/overview'+(ctx.memberId?'?member_id='+encodeURIComponent(ctx.memberId):''));
      if(ctx.isCurrent&&!ctx.isCurrent())return;
      const head=el('div');head.className='row-between';
      const refresh=el('button','새로고침');refresh.type='button';refresh.className='btn sm';refresh.onclick=()=>render(ctx);
      head.append(el('h3',`담당 매칭 ${data.items.length}건`),refresh);
      root.replaceChildren(head);
      if(!data.items.length){root.append(el('p','담당 회원의 매칭 신청 내역이 없습니다.'));return;}
      const wrap=el('div');wrap.className='tablewrap';
      const table=el('table'),thead=el('thead'),tbody=el('tbody'),hr=el('tr');
      for(const h of ['매칭','상태','신청일','공개 동의','만남 일정','관리'])hr.append(el('th',h));
      thead.append(hr);table.append(thead,tbody);wrap.append(table);
      const detail=el('div');detail.className='card mt16';detail.hidden=true;
      root.append(wrap,detail);
      let selected=null;
      for(const item of data.items) {
        const tr=el('tr');
        const awaiting=item.meeting_state==='awaiting_approval';
        const meeting=el('span',item.status==='matched'?(meetingNames[item.meeting_state]||'—'):'—');
        if(awaiting)meeting.className='pill amber';
        const open=el('button','상세');open.type='button';open.className='btn sm';
        open.onclick=()=>{
          selected=item.match_id;
          for(const r of tbody.children)r.classList?.toggle('selected',r===tr);
          showDetail(ctx,item,detail,()=>selected===item.match_id);
        };
        cell(tr,item.label||'담당 회원 매칭');cell(tr,states[item.status]||item.status);cell(tr,date(item.created_at));
        cell(tr,item.grants.length?`${item.grants.filter(g=>g.active).length}/${item.grants.length} 유효`:'없음');
        cell(tr,meeting);cell(tr,open);tbody.append(tr);
      }
      if(window.ListPager)ListPager.apply(tbody,[...tbody.children],{size:10,search:true,placeholder:'매칭·상태·신청일로 검색',label:'매칭 목록 페이지'});
      if(ctx.matchId){const item=data.items.find(i=>i.match_id===ctx.matchId);if(item)showDetail(ctx,item,detail,()=>true);}
    }catch(error){root.replaceChildren(el('p',error.message));}
  }

  function showDetail(ctx,item,detail,isCurrent) {
    const {api}=ctx;
    detail.hidden=false;
    detail.replaceChildren(el('h3',item.label||'담당 회원 매칭'),el('p',(states[item.status]||item.status)+' · 신청 '+date(item.created_at)));
    if(item.status==='matched') {
      // 두 회원 중 한쪽만 담당해도 종료할 수 있다. 종료하면 공개 동의·일정이 함께 끝나고 두 회원에게 알림이 간다
      const endBox=el('div');endBox.className='row-between mt16';
      const endNote=el('p','관계를 종료하면 공개 동의와 만남 일정이 함께 종료되고, 두 회원의 소개 후보 맨 뒤에 다시 표시됩니다.');endNote.className='muted';
      const end=el('button','관계 종료');end.type='button';end.className='btn sm danger';
      end.onclick=async()=>{
        if(!confirm('이 매칭을 종료할까요? 공개 동의와 만남 일정이 함께 종료되고 되돌릴 수 없습니다.'))return;
        end.disabled=true;
        try{await api(`/api/matching/requests/${item.match_id}/end`,{method:'POST',body:{}});await render({...ctx,matchId:item.match_id});}
        catch(error){endNote.textContent=error.message;end.disabled=false;}
      };
      endBox.append(endNote,end);detail.append(endBox);
    }
    detail.append(el('h4','공개 동의·자료 발송'));
    if(!item.grants.length)detail.append(el('p','회원이 직접 설정한 공개 동의가 아직 없습니다. 매칭 수락은 공개 동의가 아닙니다.'));
    for(const g of item.grants) {
      const group=el('div');group.className='mt16';
      group.append(el('strong',`${g.owner_label||'자료 주인'} → ${g.recipient_label||'소개 상대'}`),
        el('p',g.scopes.map(s=>names[s]||s).join(' · ')),
        el('p',`${g.revoked_at?'철회':g.active?'유효':'만료 또는 관계 종료'} · 기한 ${date(g.expires_at)}`));
      if(g.can_prepare&&g.supported_scopes.length) {
        const form=el('form');const checks=[];
        form.append(el('p','승인 후 상대 회원 화면에 표시할 항목을 선택하세요. 회원이 동의했더라도 이 요청과 승인 담당자 승인이 있어야 상대에게 보입니다. 원본은 포함하지 않으며, 문서 사본은 함께 선택한 서류 항목의 마스킹 사본만 들어갑니다.'));
        if(g.scopes.includes('photo'))form.append(el('p',g.photo_ready?'프로필 사진: 두 회원 모두 사진 제공 동의 (선택 가능)':'프로필 사진: 상대 회원도 사진 제공에 동의해야 선택할 수 있습니다 (서로 제공해야 서로 봄).'));
        if(g.scopes.includes('contact'))form.append(el('p',g.contact_ready?'연락처: 일정 확정·상호 동의 확인됨 (선택 가능)':'연락처: 만남 일정 확정과 두 회원의 연락처 동의가 모두 있어야 선택할 수 있습니다.'));
        const checksBox=el('div');checksBox.className='check-row';
        for(const s of g.supported_scopes) {
          const label=el('label');const input=el('input');input.type='checkbox';input.value=s;input.checked=true;
          label.append(input,document.createTextNode(' '+(names[s]||s)));checksBox.append(label);checks.push(input);
        }
        const send=el('button','선택한 항목으로 발송 승인 요청');send.type='submit';send.className='btn primary sm';
        const result=el('p');result.setAttribute('role','status');form.append(checksBox,send,result);
        form.onsubmit=async e=>{
          e.preventDefault();const scopes=checks.filter(c=>c.checked).map(c=>c.value);
          if(!scopes.length){result.textContent='제공할 항목을 선택하세요.';return;}
          if(!confirm('선택한 공개 항목으로 자료를 만들고 별도 승인 담당자에게 요청할까요?'))return;
          send.disabled=true;
          try{await api('/api/matching/releases',{method:'POST',body:{grant_id:g.grant_id,scopes}});await render({...ctx,matchId:item.match_id});}
          catch(error){result.textContent=error.message;send.disabled=false;}
        };
        group.append(form);
      }
      for(const r of item.releases.filter(r=>r.consent_id===g.grant_id))group.append(el('p','자료 발송: '+(states[r.request_status]||r.request_status)+' · '+date(r.expires_at)));
      detail.append(group);
    }
    if(item.status==='matched'&&window.MeetingStaffUI) {
      detail.append(el('h4','만남 일정 승인'));
      const status=el('p');status.setAttribute('role','status');
      const box=el('div');detail.append(status,box);
      MeetingStaffUI.renderMatch({root:box,api,matchId:item.match_id,senderId:item.sender_id,
        toast:message=>{status.textContent=message;},isCurrent}).catch(error=>{box.textContent=error.message;});
    }
    detail.scrollIntoView?.({behavior:'smooth',block:'nearest'});
  }
  return {render};
})();
