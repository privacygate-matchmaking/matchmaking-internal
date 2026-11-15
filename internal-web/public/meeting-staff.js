/* Integration component for the internal team's authenticated staff page.
 * api(path, options) must return parsed JSON through internal-api's BFF and CSRF.
 * This component never receives JWTs or service secrets.
 * Members arrange meetings between themselves; staff only approve or reject the agreed option. */
'use strict';
window.MeetingStaffUI = (() => {
  const el=(tag,cls,text)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n;};
  const date=x=>new Date(x).toLocaleString('ko-KR',{timeZone:'Asia/Seoul'});
  const states={proposed:'회원 간 조율 중',confirmed:'승인 완료(확정)',cancelled:'반려·취소',superseded:'이전 제안'};
  const replies={available:'가능',change_requested:'다른 일정 요청'};

  async function renderMatch({root,api,matchId,senderId,toast=()=>{},isCurrent=()=>true}) {
    root.replaceChildren(el('p','muted','만남 일정을 불러오는 중입니다.'));
    const data=await api(`/api/matching/requests/${matchId}/meetings`);
    if(!root.isConnected||!isCurrent())return;
    root.replaceChildren();
    const open=data.items.filter(item=>['proposed','confirmed'].includes(item.status));
    if(!open.length){root.append(el('p','muted','회원들이 아직 일정을 제안하지 않았습니다. 일정은 두 회원이 직접 제안·합의합니다.'));}
    for(const item of open) {
      const card=el('article','meeting-card');
      card.append(el('strong','',`${date(item.starts_at)} · ${states[item.status]}`),el('p','',`${item.venue} · ${item.address}`));
      const who=uid=>uid===senderId?'신청 회원':'상대 회원';
      card.append(el('p','muted',`제안: ${who(item.proposed_by)}`));
      for(const reply of item.replies)card.append(el('p','',
        `${who(reply.user_id)}: ${replies[reply.availability]}${reply.private_note?' / 담당 회원 의견: '+reply.private_note:''}`));
      const actions=el('div','matching-actions');
      if(item.status==='proposed'&&item.both_available&&item.can_reply) {
        const approve=el('button','btn primary sm','합의된 일정 승인');approve.type='button';
        approve.onclick=async()=>{
          if(!window.confirm('두 회원이 합의한 날짜·시간·장소를 승인해 확정할까요?'))return;
          approve.disabled=true;
          try {await api(`/api/matching/requests/${matchId}/meetings/${item.proposal_id}/confirm`,{method:'POST',body:{}});toast('일정을 승인했습니다.');await renderMatch({root,api,matchId,senderId,toast,isCurrent});}
          catch(error){toast(error.message);if(approve.isConnected)approve.disabled=false;}
        };actions.append(approve);
      } else if(item.status==='proposed') {
        actions.append(el('span','muted','두 회원이 같은 후보에 합의하면 승인할 수 있습니다.'));
      }
      const reject=el('button','btn sm danger',item.status==='confirmed'?'확정 취소':'반려');reject.type='button';
      reject.onclick=async()=>{
        if(!window.confirm(item.status==='confirmed'?'확정된 일정을 취소할까요?':'이 일정을 반려할까요? 회원은 새 일정을 다시 제안할 수 있습니다.'))return;
        reject.disabled=true;
        try {await api(`/api/matching/requests/${matchId}/meetings/${item.proposal_id}/cancel`,{method:'POST',body:{}});toast('처리했습니다.');await renderMatch({root,api,matchId,senderId,toast,isCurrent});}
        catch(error){toast(error.message);if(reject.isConnected)reject.disabled=false;}
      };
      actions.append(reject);card.append(actions);root.append(card);
    }
  }
  return {renderMatch};
})();
