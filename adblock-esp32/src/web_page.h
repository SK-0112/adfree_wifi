#pragma once
#include <Arduino.h>

static const char DASHBOARD_HTML[] PROGMEM = R"HTML(<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AdBlock DNS</title><style>
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
background:#0f1115;color:#e6e8ec;line-height:1.5}
.wrap{max-width:900px;margin:0 auto;padding:1.2rem}
h1{font-size:1.25rem;margin:0 0 .2rem;display:flex;align-items:center;gap:.6rem}
.sub{color:#8b93a1;font-size:.82rem;margin-bottom:1.2rem}
.card{background:#171a21;border:1px solid #242833;border-radius:12px;padding:1rem;margin-bottom:1rem}
.card h2{font-size:.82rem;text-transform:uppercase;letter-spacing:.06em;color:#8b93a1;margin:0 0 .8rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.8rem}
.stat{background:#0f1115;border:1px solid #242833;border-radius:10px;padding:.8rem}
.stat .v{font-size:1.5rem;font-weight:600}
.stat .l{font-size:.72rem;color:#8b93a1;text-transform:uppercase;letter-spacing:.05em}
.pill{display:inline-flex;align-items:center;gap:.4rem;padding:.25rem .7rem;border-radius:99px;
font-size:.78rem;font-weight:600}
.on{background:#0d2f1d;color:#4ade80;border:1px solid #1a5334}
.off{background:#3a1d1d;color:#f87171;border:1px solid #5c2b2b}
.warn{background:#3a2f14;color:#fbbf24;border:1px solid #5c4a1f}
.dot{width:7px;height:7px;border-radius:99px;background:currentColor}
button{font:inherit;padding:.5rem .9rem;border-radius:8px;border:1px solid #2f3542;
background:#1e222b;color:#e6e8ec;cursor:pointer}
button:hover{background:#262b36}
button.primary{background:#2563eb;border-color:#2563eb;color:#fff}
button.primary:hover{background:#1d4ed8}
button.danger{background:#3a1d1d;border-color:#5c2b2b;color:#f87171}
.row{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center}
table{width:100%;border-collapse:collapse;font-size:.85rem}
td,th{text-align:left;padding:.4rem .3rem;border-bottom:1px solid #1f232c}
th{color:#8b93a1;font-weight:500;font-size:.72rem;text-transform:uppercase}
td.dom{font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
td.t{color:#8b93a1;white-space:nowrap;font-size:.78rem}
textarea,input[type=text],input[type=number]{width:100%;background:#0f1115;border:1px solid #2f3542;
color:#e6e8ec;border-radius:8px;padding:.5rem;font-family:ui-monospace,Menlo,Consolas,monospace;
font-size:.82rem}
textarea{min-height:90px;resize:vertical}
label{display:block;font-size:.75rem;color:#8b93a1;margin:.7rem 0 .25rem;text-transform:uppercase;
letter-spacing:.04em}
.muted{color:#8b93a1;font-size:.8rem}
.two{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
@media(max-width:640px){.two{grid-template-columns:1fr}}
#toast{position:fixed;bottom:1rem;left:50%;transform:translateX(-50%);background:#2563eb;color:#fff;
padding:.6rem 1.1rem;border-radius:8px;font-size:.85rem;opacity:0;transition:opacity .25s;
pointer-events:none;z-index:9}
#toast.show{opacity:1}
</style></head><body><div class="wrap">

<h1>AdBlock DNS <span id="state" class="pill off"><span class="dot"></span><span id="stateTxt">…</span></span></h1>
<div class="sub" id="ident">loading…</div>

<div class="card">
  <h2>Traffic</h2>
  <div class="grid">
    <div class="stat"><div class="v" id="sTotal">–</div><div class="l">Queries</div></div>
    <div class="stat"><div class="v" id="sBlocked">–</div><div class="l">Blocked</div></div>
    <div class="stat"><div class="v" id="sPct">–</div><div class="l">% Blocked</div></div>
    <div class="stat"><div class="v" id="sDomains">–</div><div class="l">Domains on list</div></div>
  </div>
  <div class="row" style="margin-top:.9rem">
    <button onclick="act('/api/toggle')" id="btnToggle">Toggle blocker</button>
    <button onclick="pause(300)">Pause 5 min</button>
    <button onclick="pause(3600)">Pause 1 hour</button>
    <button onclick="pause(-1)">Pause indefinitely</button>
    <button onclick="pause(0)">Resume</button>
  </div>
</div>

<div class="card">
  <h2>Health</h2>
  <table>
    <tr><th>Upstream DNS</th><td id="hUp">–</td></tr>
    <tr><th>Upstream state</th><td id="hUpState">–</td></tr>
    <tr><th>Blocklist updated</th><td id="hBlUpd">–</td></tr>
    <tr><th>Blocklist result</th><td id="hBlRes">–</td></tr>
    <tr><th>Timeouts / errors</th><td id="hErr">–</td></tr>
    <tr><th>Free heap / PSRAM</th><td id="hMem">–</td></tr>
    <tr><th>Flash storage</th><td id="hFs">–</td></tr>
    <tr><th>Uptime</th><td id="hUptime">–</td></tr>
    <tr><th>Firmware</th><td id="hFw">–</td></tr>
  </table>
  <div class="row" style="margin-top:.9rem">
    <button onclick="act('/api/refresh')">Refresh blocklist now</button>
    <button onclick="act('/api/otacheck')">Check for firmware update</button>
    <button class="danger" onclick="if(confirm('Reboot the device?'))act('/api/reboot')">Reboot</button>
  </div>
</div>

<div class="card">
  <h2>Recently blocked</h2>
  <table><thead><tr><th>Domain</th><th>Client</th><th>When</th></tr></thead>
  <tbody id="blocked"><tr><td class="muted" colspan="3">nothing yet</td></tr></tbody></table>
</div>

<div class="card">
  <h2>Lists</h2>
  <div class="two">
    <div>
      <label>Whitelist — never block (one per line)</label>
      <textarea id="wl"></textarea>
    </div>
    <div>
      <label>Blacklist — always block (one per line)</label>
      <textarea id="bl"></textarea>
    </div>
  </div>
  <label>Blocklist source URLs (one per line)</label>
  <textarea id="urls"></textarea>
  <div class="row" style="margin-top:.8rem">
    <button class="primary" onclick="saveLists()">Save lists</button>
    <span class="muted">Whitelist/blacklist apply instantly. New URLs apply on next refresh.</span>
  </div>
</div>

<div class="card">
  <h2>Settings</h2>
  <div class="two">
    <div>
      <label>Upstream DNS servers (one per line)</label>
      <textarea id="ups"></textarea>
    </div>
    <div>
      <label>Blocklist refresh interval (hours)</label>
      <input type="number" id="ivl" min="1" max="720">
      <label>Upstream timeout (ms)</label>
      <input type="number" id="tmo" min="200" max="5000">
      <label>OTA manifest URL</label>
      <input type="text" id="ota">
    </div>
  </div>
  <div class="row" style="margin-top:.8rem">
    <button class="primary" onclick="saveSettings()">Save settings</button>
    <label style="margin:0;text-transform:none"><input type="checkbox" id="led"> status LED</label>
  </div>
</div>

<div class="card">
  <h2>Network address</h2>
  <div class="muted" id="netnow">–</div>
  <label style="text-transform:none;margin-top:.8rem">
    <input type="checkbox" id="stEn"> Use a fixed (static) IP instead of DHCP
  </label>
  <div class="two" style="margin-top:.5rem">
    <div><label>IP address</label><input type="text" id="stIp" placeholder="192.168.0.95"></div>
    <div><label>Gateway (router)</label><input type="text" id="stGw" placeholder="192.168.0.1"></div>
  </div>
  <label>Subnet mask</label><input type="text" id="stMask" placeholder="255.255.255.0">
  <div class="row" style="margin-top:.8rem">
    <button class="primary" onclick="saveNet()">Save network</button>
    <span class="muted">Takes effect after reboot. Invalid entries fall back to DHCP.
    A DHCP reservation on your router is the safer option.</span>
  </div>
</div>

<div class="card">
  <h2>Security &amp; portability</h2>
  <div class="two">
    <div>
      <label>Admin username</label><input type="text" id="auUser">
      <label>New admin password (min 8 chars)</label><input type="password" id="auPass">
      <button class="primary" style="margin-top:.8rem" onclick="saveAdmin()">Change login</button>
    </div>
    <div>
      <label>Wi-Fi network (SSID)</label><input type="text" id="wfSsid">
      <label>Wi-Fi password</label><input type="password" id="wfPass">
      <button style="margin-top:.8rem" onclick="saveWifi()">Save Wi-Fi &amp; reboot</button>
    </div>
  </div>
  <p class="muted">Moving house? Enter the new Wi-Fi here before unplugging. If it ever
  fails to connect it starts its own setup hotspot, where you can set the network
  from a phone:<br>
  network <b id="apSsid">&hellip;</b> &middot; password <b id="apPass">&hellip;</b><br>
  These are unique to this board. Write them down &mdash; if it loses Wi-Fi you
  won't be able to open this page to look them up.</p>
</div>

<div class="card">
  <h2>Log</h2>
  <pre id="log" style="max-height:220px;overflow:auto;font-size:.72rem;color:#8b93a1;margin:0"></pre>
</div>

</div><div id="toast"></div>
<script>
function T(m){var t=document.getElementById('toast');t.textContent=m;t.className='show';
setTimeout(function(){t.className=''},1900)}
function fmtAge(s){if(!s||s<0)return 'never';if(s<60)return s+'s ago';
if(s<3600)return Math.floor(s/60)+'m ago';if(s<86400)return Math.floor(s/3600)+'h ago';
return Math.floor(s/86400)+'d ago'}
function fmtUp(s){var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
return (d?d+'d ':'')+(h?h+'h ':'')+m+'m'}
function esc(s){return String(s).replace(/[&<>"]/g,function(c){
return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
var loaded=false;
function refresh(){
 fetch('/api/status').then(function(r){return r.json()}).then(function(d){
  var st=document.getElementById('state'),tx=document.getElementById('stateTxt');
  if(d.blocking){st.className='pill on';tx.textContent='BLOCKING'}
  else if(d.paused){st.className='pill warn';tx.textContent=d.pause_left>0?'PAUSED '+Math.ceil(d.pause_left/60)+'m':'PAUSED'}
  else{st.className='pill off';tx.textContent='OFF'}
  document.getElementById('ident').textContent=
    d.hostname+'.local · '+d.ip+' · '+d.ssid+' ('+d.rssi+' dBm)';
  document.getElementById('sTotal').textContent=d.total.toLocaleString();
  document.getElementById('sBlocked').textContent=d.blocked.toLocaleString();
  document.getElementById('sPct').textContent=(d.total?(100*d.blocked/d.total).toFixed(1):'0.0')+'%';
  document.getElementById('sDomains').textContent=d.domains.toLocaleString();
  document.getElementById('hUp').textContent=d.upstream;
  document.getElementById('hUpState').innerHTML=d.upstream_ok
    ?'<span style="color:#4ade80">healthy</span>':'<span style="color:#fbbf24">degraded</span>';
  document.getElementById('hBlUpd').textContent=
    fmtAge(d.bl_age)+(d.bl_refreshing?' (refreshing now…)':'');
  document.getElementById('hBlRes').textContent=
    (d.bl_ok?'ok':'FAILED')+(d.bl_err?' — '+d.bl_err:'')+
    ' ['+d.bl_sources_ok+' ok / '+d.bl_sources_failed+' failed]';
  document.getElementById('hErr').textContent=d.timeouts+' / '+d.errors;
  document.getElementById('hMem').textContent=
    Math.round(d.heap/1024)+' KB / '+Math.round(d.psram/1024)+' KB';
  document.getElementById('hFs').textContent=
    Math.round(d.fs_used/1048576*10)/10+' MB used of '+Math.round(d.fs_total/1048576*10)/10+' MB';
  document.getElementById('hUptime').textContent=fmtUp(d.uptime);
  document.getElementById('hFw').textContent=d.fw+(d.ota_pending?' (pending verify)':'')+
    (d.ota_result?' — '+d.ota_result:'');
  var tb=document.getElementById('blocked');
  if(!d.recent.length){tb.innerHTML='<tr><td class="muted" colspan="3">nothing yet</td></tr>'}
  else{tb.innerHTML=d.recent.map(function(r){
    return '<tr><td class="dom">'+esc(r.d)+'</td><td class="t">'+esc(r.c)+
    '</td><td class="t">'+fmtAge(r.a)+'</td></tr>'}).reverse().join('')}
  document.getElementById('log').textContent=d.log.join('\n');
  if(!loaded){loaded=true;
   document.getElementById('wl').value=d.whitelist.join('\n');
   document.getElementById('bl').value=d.blacklist.join('\n');
   document.getElementById('urls').value=d.urls.join('\n');
   document.getElementById('ups').value=d.upstreams.join('\n');
   document.getElementById('ivl').value=d.interval;
   document.getElementById('tmo').value=d.timeout;
   document.getElementById('ota').value=d.ota_url||'';
   document.getElementById('led').checked=d.led;
   document.getElementById('stEn').checked=d.static_enable;
   document.getElementById('stIp').value=d.static_ip||d.ip;
   document.getElementById('stGw').value=d.static_gw||d.gw;
   document.getElementById('stMask').value=d.static_mask||d.mask;
   document.getElementById('auUser').value=d.admin_user||'admin';
   document.getElementById('wfSsid').value=d.ssid||'';
  }
  document.getElementById('netnow').textContent=
    'Currently '+(d.static_enable?'STATIC':'DHCP')+' · IP '+d.ip+' · gateway '+d.gw+
    ' · mask '+d.mask+' · MAC '+d.mac;
  if(d.ap_ssid){document.getElementById('apSsid').textContent=d.ap_ssid;}
  if(d.ap_pass){document.getElementById('apPass').textContent=d.ap_pass;}
 }).catch(function(){})
}
function act(u){fetch(u,{method:'POST'}).then(function(r){return r.text()})
 .then(function(t){T(t);refresh()})}
function pause(s){fetch('/api/pause?secs='+s,{method:'POST'}).then(function(r){return r.text()})
 .then(function(t){T(t);refresh()})}
function lines(id){return document.getElementById(id).value.split('\n')
 .map(function(s){return s.trim()}).filter(function(s){return s.length})}
function post(u,o){return fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify(o)}).then(function(r){return r.text()}).then(function(t){T(t);loaded=false;refresh()})}
function saveLists(){post('/api/lists',{whitelist:lines('wl'),blacklist:lines('bl'),urls:lines('urls')})}
function saveAdmin(){
 var p=document.getElementById('auPass').value;
 if(p.length<8){T('Password must be at least 8 characters');return}
 fetch('/api/admin',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({user:document.getElementById('auUser').value.trim(),new_pass:p})})
 .then(function(r){return r.text()}).then(function(t){T(t);
  document.getElementById('auPass').value=''})}
function saveWifi(){
 var s=document.getElementById('wfSsid').value.trim();
 if(!s){T('Enter an SSID');return}
 if(!confirm('Save Wi-Fi "'+s+'" and reboot now?'))return;
 fetch('/api/admin',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({wifi_ssid:s,wifi_pass:document.getElementById('wfPass').value})})
 .then(function(r){return r.text()}).then(function(t){T(t);
  setTimeout(function(){fetch('/api/reboot',{method:'POST'})},1200)})}
function saveNet(){post('/api/settings',{static_enable:document.getElementById('stEn').checked,
 static_ip:document.getElementById('stIp').value.trim(),
 static_gw:document.getElementById('stGw').value.trim(),
 static_mask:document.getElementById('stMask').value.trim()})}
function saveSettings(){post('/api/settings',{upstreams:lines('ups'),
 interval:+document.getElementById('ivl').value,timeout:+document.getElementById('tmo').value,
 ota_url:document.getElementById('ota').value,led:document.getElementById('led').checked})}
refresh();setInterval(refresh,3000);
</script></body></html>
)HTML";
