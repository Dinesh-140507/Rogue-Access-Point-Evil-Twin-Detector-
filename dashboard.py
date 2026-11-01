"""Local web dashboard (PDF section 4.5): a Flask server on http://127.0.0.1:5000.

It only reads the engine's state through the JSON endpoint /api/state, so a browser
problem cannot stop detection. All SSIDs are inserted with textContent, never innerHTML,
so a hostile network name cannot run code in the page (the XSS protection from the PDF).
"""
from flask import Flask, jsonify

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>AURA-Q Dashboard</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;background:#111827;color:#e5e7eb;margin:0;padding:24px}
 h1{font-size:22px;margin:0 0 4px} .sub{color:#9ca3af;font-size:13px;margin-bottom:18px}
 .banner{padding:16px 20px;border-radius:10px;font-size:18px;font-weight:600;margin-bottom:18px}
 .WAITING,.UNVERIFIED{background:#374151} .KNOWN{background:#065f46}
 .SUSPICIOUS{background:#991b1b} .SYSTEM_FAULT{background:#9a3412}
 .grid{display:grid;grid-template-columns:2fr 1fr;gap:18px}
 .card{background:#1f2937;border-radius:10px;padding:16px}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #374151;vertical-align:top}
 .pill{padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600}
 .p-KNOWN{background:#065f46}.p-UNVERIFIED{background:#4b5563}.p-SUSPICIOUS{background:#991b1b}
 .alert{border-left:4px solid #dc2626;padding:6px 10px;margin-bottom:10px;background:#111827;font-size:13px}
 .small{font-size:12px;color:#9ca3af}
</style></head>
<body>
<h1>AURA-Q Rogue AP &amp; Evil-Twin Detector</h1>
<div class="sub" id="meta">connecting...</div>
<div id="banner" class="banner WAITING">starting</div>
<div class="grid">
 <div class="card"><h3 style="margin-top:0">Networks heard</h3>
  <table><thead><tr><th>Status</th><th>Network (SSID)</th><th>BSSID</th><th>Mean RSSI</th><th>Samples</th><th>Why</th></tr></thead>
  <tbody id="aps"></tbody></table></div>
 <div>
  <div class="card" style="margin-bottom:18px"><h3 style="margin-top:0">Sensor (ESP32)</h3><div id="sensor" class="small"></div></div>
  <div class="card"><h3 style="margin-top:0">Alert log</h3><div id="alerts"></div></div>
 </div>
</div>
<script>
function el(tag, cls, text){const e=document.createElement(tag); if(cls) e.className=cls; if(text!==undefined) e.textContent=text; return e;}
async function refresh(){
  try{
    const r = await fetch('/api/state', {cache:'no-store'}); const s = await r.json();
    const b = document.getElementById('banner');
    b.className = 'banner ' + s.overall; b.textContent = s.headline;
    document.getElementById('meta').textContent = 'updated ' + s.updated + ' | analysis window ' + s.window_s + ' s';
    const tb = document.getElementById('aps'); tb.replaceChildren();
    for (const a of s.aps){
      const tr = document.createElement('tr');
      const td0 = document.createElement('td'); td0.appendChild(el('span','pill p-'+a.status,a.status)); tr.appendChild(td0);
      tr.appendChild(el('td','',a.ssid)); tr.appendChild(el('td','',a.bssid));
      tr.appendChild(el('td','',a.mean_rssi+' dBm')); tr.appendChild(el('td','',String(a.samples)));
      tr.appendChild(el('td','small',a.reasons.join('; ')));
      tb.appendChild(tr);
    }
    const sen = document.getElementById('sensor'); sen.replaceChildren();
    const sv = s.sensor || {};
    sen.appendChild(el('div','', 'Last data: ' + (sv.silence_s===null?'never':sv.silence_s+' s ago')));
    sen.appendChild(el('div','', 'Firmware state: ' + (sv.firmware_state||'?')));
    sen.appendChild(el('div','', 'Packets received: ' + (sv.packets||0) + '   dropped on board: ' + (sv.drops||0)));
    const al = document.getElementById('alerts'); al.replaceChildren();
    if (!s.alerts.length) al.appendChild(el('div','small','No alerts yet.'));
    for (const a of s.alerts.slice(0,15)){
      const d = el('div','alert', a.time + '  ' + a.status + '  score ' + a.score + '  ' + a.ssid + ' / ' + a.bssid);
      d.appendChild(el('div','small', a.reasons.join('; '))); al.appendChild(d);
    }
  }catch(e){ document.getElementById('meta').textContent = 'dashboard cannot reach the analysis process: ' + e; }
}
refresh(); setInterval(refresh, 1000);
</script></body></html>
"""


def create_app(get_state):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return PAGE

    @app.route("/api/state")
    def state():
        return jsonify(get_state())

    return app
