/* Integration component for the internal team's authenticated staff page.
 * api(path, options) must return parsed JSON through internal-api's BFF and CSRF.
 * This component never receives JWTs or service secrets. */
'use strict';
window.MeetingStaffUI = (() => {
  const el=(tag,cls,text)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n;};
  const date=x=>new Date(x).toLocaleString('ko-KR',{timeZone:'Asia/Seoul'});
  const states={proposed:'회원 응답 대기',confirmed:'확정',cancelled:'취소',superseded:'이전 제안'};
  const replies={available:'가능',change_requested:'다른 일정 요청'};
  async function render({root,api,toast=()=>{},isCurrent=()=>true,matchLabel}) {
    if(typeof api!=='function')throw new Error('Authenticated internal BFF API adapter required');
    const matches=await api('/api/matching/requests');
    if(!root.isConnected||!isCurrent())return;
    root.replaceChildren(el('h2','','만남 일정 관리'));
    if(!matches.items.length){root.append(el('p','','일정을 조율할 담당 매칭이 없습니다.'));return;}
    const select=el('select');select.setAttribute('aria-label','담당 매칭 선택');
    matches.items.forEach((match,index)=>{const option=el('option','',matchLabel?matchLabel(match):`담당 매칭 ${index+1}`);option.value=match.match_id;select.append(option);});
    const panel=el('section');root.append(select,panel);
    let revision=0;
    async function load() {
      const version=++revision,mid=select.value;
      const data=await api(`/api/matching/requests/${mid}/meetings`);
      if(version!==revision||!panel.isConnected||!isCurrent())return;
      panel.replaceChildren();
      for(const item of data.items) {
        const card=el('article','meeting-card');
        card.append(el('h3','',`${date(item.starts_at)} · ${states[item.status]}`),el('p','',item.venue),el('p','',item.address));
        const selected=matches.items.find(match=>match.match_id===mid);
        for(const reply of item.replies)card.append(el('p','',
          `${reply.user_id===selected.sender_id?'신청 회원':'상대 회원'}: ${replies[reply.availability]}${reply.private_note?' / 담당 회원 의견: '+reply.private_note:''}`));
        const actions=el('div','matching-actions');
        if(item.status==='proposed'&&item.both_available&&item.can_reply) {
          const confirm=el('button','primary','양쪽 동의 확인 후 최종 확정');confirm.type='button';
          confirm.onclick=async()=>{
            if(!window.confirm('양쪽이 동의한 날짜·시간·장소를 최종 확정할까요?'))return;
            confirm.disabled=true;
            try {await api(`/api/matching/requests/${mid}/meetings/${item.proposal_id}/confirm`,{method:'POST',body:{}});toast('일정을 확정했습니다.');await load();}
            catch(error){toast(error.message);if(confirm.isConnected)confirm.disabled=false;}
          };actions.append(confirm);
        }
        if(['proposed','confirmed'].includes(item.status)) {
          const cancel=el('button','secondary','이 일정 취소');cancel.type='button';
          cancel.onclick=async()=>{
            if(!window.confirm('이 일정을 취소할까요? 추가 횟수 차감은 없습니다.'))return;
            cancel.disabled=true;
            try {await api(`/api/matching/requests/${mid}/meetings/${item.proposal_id}/cancel`,{method:'POST',body:{}});toast('일정을 취소했습니다.');await load();}
            catch(error){toast(error.message);if(cancel.isConnected)cancel.disabled=false;}
          };actions.append(cancel);
        }
        card.append(actions);panel.append(card);
      }
      if(data.items.some(item=>item.status==='confirmed'))return;
      const form=el('form','form-panel'),rows=[];
      form.append(el('h3','','새 일정 후보 제안'),el('p','','최대 3개입니다. 시간을 변경해 다시 제안하면 이전 응답은 재사용되지 않습니다.'));
      function add() {
        if(rows.length===3)return;
        const row=el('fieldset');row.append(el('legend','',`후보 ${rows.length+1}`));
        const time=el('input');time.type='datetime-local';time.required=true;time.setAttribute('aria-label','날짜·시간 (한국 시간)');
        const venue=el('input');venue.placeholder='장소';venue.required=true;venue.maxLength=120;venue.setAttribute('aria-label','장소');
        const address=el('input');address.placeholder='주소';address.required=true;address.maxLength=240;address.setAttribute('aria-label','주소');
        const item={time,venue,address};
        const remove=el('button','secondary','이 후보 삭제');remove.type='button';
        remove.onclick=()=>{if(rows.length===1)return;rows.splice(rows.indexOf(item),1);row.remove();addButton.disabled=false;};
        row.append(time,venue,address,remove);form.insertBefore(row,addButton);rows.push(item);
        addButton.disabled=rows.length===3;
      }
      const addButton=el('button','secondary','후보 추가');addButton.type='button';addButton.onclick=add;
      const submit=el('button','primary','새 후보 발송');submit.type='submit';form.append(addButton,submit);add();
      form.onsubmit=async event=>{
        event.preventDefault();submit.disabled=true;
        try {
          // Explicit KST offset avoids the operator's PC timezone changing appointments.
          const options=rows.map(({time,venue,address})=>({starts_at:new Date(time.value+':00+09:00').toISOString(),venue:venue.value,address:address.value}));
          await api(`/api/matching/requests/${mid}/meetings`,{method:'POST',body:{options}});toast('일정 후보를 전달했습니다.');await load();
        } catch(error){toast(error.message);if(submit.isConnected)submit.disabled=false;}
      };panel.append(form);
    }
    select.onchange=()=>load().catch(error=>toast(error.message));await load();
  }
  return {render};
})();
