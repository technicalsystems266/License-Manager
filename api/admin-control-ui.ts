import { readFileSync } from "node:fs";
import { IncomingMessage, ServerResponse } from "node:http";

export default function adminControlUi(_req: IncomingMessage, res: ServerResponse) {
  let html = readFileSync(new URL("../web/admin-control.html", import.meta.url), "utf8");
  html = html.replace("</body>", `<script>
(function(){
  const originalLoadSettings = window.loadSettings;
  window.loadSettings = async function(){
    const state=document.getElementById('settingsState');
    if(state) state.textContent='Loading settings from License Master database…';
    try{
      const r=await fetch('/api/admin-settings',{headers:{authorization:'Bearer '+sessionStorage.getItem('orbitfs_admin_access_token')||''}});
      const d=await r.json().catch(()=>({}));
      if(!r.ok) throw new Error(d.error||'Unable to load settings');
      const s=d.settings||{};
      const box=document.getElementById('settingsBox');
      if(box) box.innerHTML='<b>Database</b><span class="badge">CONNECTED</span><b>Issuer</b><span>'+String(s.issuer||'—')+'</span><b>Audience</b><span>'+String(s.audience||'—')+'</span><b>Entitlement TTL</b><span>'+String(s.entitlement_ttl_seconds??'—')+' seconds</span><b>Grace period</b><span>'+String(s.grace_seconds??'—')+' seconds</span><b>API mode</b><span>'+String(s.api_mode||'online')+'</span><b>Offline grace</b><span>'+String(s.allow_offline_grace?'Enabled':'Disabled')+'</span>';
      const issuer=document.getElementById('issuer'); if(issuer) issuer.value=s.issuer||'';
      const audience=document.getElementById('audience'); if(audience) audience.value=s.audience||'';
      const ttl=document.getElementById('ttl'); if(ttl) ttl.value=s.entitlement_ttl_seconds||10800;
      const grace=document.getElementById('grace'); if(grace) grace.value=s.grace_seconds??604800;
      let controls=document.getElementById('lmAuthorityControls');
      if(!controls){ controls=document.createElement('div'); controls.id='lmAuthorityControls'; controls.className='card'; controls.style.marginTop='12px'; controls.innerHTML='<div class="head"><div><h2>API Authority Controls</h2><p class="sub">These controls are stored in master_license_settings and are authoritative for runtime enforcement.</p></div><span id="lmDbBadge" class="badge">DATABASE CONNECTED</span></div><div class="actions"><button class="btn primary" id="lmOnline">API Online</button><button class="btn warn" id="lmMaintenance">Maintenance</button><button class="btn danger" id="lmOffline">API Offline</button><label style="display:flex;align-items:center;gap:7px;font-size:10px"><input id="lmOfflineGrace" type="checkbox"> Allow offline grace</label><button class="btn" id="lmSaveAuthority">Save Authority</button></div><p id="lmAuthorityMsg" class="small"></p>'; const section=document.getElementById('api-settings'); if(section) section.appendChild(controls); }
      const graceToggle=document.getElementById('lmOfflineGrace'); if(graceToggle) graceToggle.checked=s.allow_offline_grace!==false;
      const mode=s.api_mode||'online';
      const msg=document.getElementById('lmAuthorityMsg'); if(msg) msg.textContent='Database connected. Current mode: '+mode;
      let selected=mode;
      ['lmOnline','lmMaintenance','lmOffline'].forEach(id=>{const b=document.getElementById(id); if(b)b.onclick=()=>{selected=id==='lmOnline'?'online':id==='lmMaintenance'?'maintenance':'offline'; if(msg)msg.textContent='Selected mode: '+selected+' — press Save Authority';};});
      const save=document.getElementById('lmSaveAuthority'); if(save) save.onclick=async()=>{try{const body={issuer:(document.getElementById('issuer')||{}).value||s.issuer,audience:(document.getElementById('audience')||{}).value||s.audience,entitlement_ttl_seconds:Number((document.getElementById('ttl')||{}).value||10800),grace_seconds:Number((document.getElementById('grace')||{}).value||604800),api_mode:selected,allow_offline_grace:!!(document.getElementById('lmOfflineGrace')||{}).checked,revision:Number(s.revision||1)+1};const rr=await fetch('/api/admin-settings',{method:'PATCH',headers:{authorization:'Bearer '+sessionStorage.getItem('orbitfs_admin_access_token'), 'content-type':'application/json'},body:JSON.stringify(body)});const dd=await rr.json().catch(()=>({}));if(!rr.ok)throw new Error(dd.error||'Unable to save settings');if(msg)msg.textContent='Saved to License Master database. Mode: '+selected;await window.loadSettings();}catch(e){if(msg)msg.textContent=e.message;}};
    }catch(e){ if(state) state.textContent='Unable to load settings: '+e.message; }
  };
  setTimeout(()=>{if(document.getElementById('api-settings'))window.loadSettings();},0);
})();
</script></body>`);
  res.statusCode = 200;
  res.setHeader("content-type", "text/html; charset=utf-8");
  res.setHeader("cache-control", "no-store, max-age=0");
  res.end(html);
}
