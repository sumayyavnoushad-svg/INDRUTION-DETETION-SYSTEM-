#!/usr/bin/env python3
from flask import Flask, render_template_string
import json, os, logging, requests, hashlib
from datetime import datetime
import pytz

app = Flask(__name__)
COWRIE_LOG = '/opt/cowrie-env/var/log/cowrie/cowrie.json'
CUSTOM_LOG = '/opt/ids-project/custom_attacks.json'
IST = pytz.timezone('Asia/Kolkata')

# === GEO API ===
API_URL = 'https://ipwhois.app/json/{}'
GEO_CACHE = {}

def get_geo(ip):
    if ip in ['127.0.0.1', '::1']: return "Local", "Local", "Local"
    if ip in GEO_CACHE: return GEO_CACHE[ip]
    try:
        r = requests.get(API_URL.format(ip), timeout=5)
        if r.status_code == 200:
            d = r.json()
            GEO_CACHE[ip] = (d.get('country','?'), d.get('city','?'), d.get('isp','?'))
            return GEO_CACHE[ip]
    except Exception as e:
        logging.error(f"GEO ERROR {ip}: {e}")
    return "?", "?", "?"

# === COWRIE: FULL SESSION DETAILS ===
def get_cowrie_sessions():
    sessions = {}
    if not os.path.exists(COWRIE_LOG): return []
    try:
        with open(COWRIE_LOG) as f:
            for line in f:
                try:
                    j = json.loads(line.strip())
                    sid = j.get('session')
                    if not sid: continue
                    if sid not in sessions:
                        sessions[sid] = {
                            'ip': '?', 'time': '', 'username': '?', 'password': '?',
                            'success': False, 'commands': [], 'duration': 0.0, 'client': 'Unknown'
                        }
                    s = sessions[sid]
                    if j.get('eventid') == 'cowrie.session.connect':
                        s['ip'] = j.get('src_ip', '?')
                        s['time'] = j.get('timestamp', '')
                        s['client'] = j.get('version', 'Unknown')
                    elif j.get('eventid') == 'cowrie.login.failed':
                        s['username'] = j.get('username', '?')
                        s['password'] = j.get('password', '?')
                    elif j.get('eventid') == 'cowrie.login.success':
                        s['username'] = j.get('username', '?')
                        s['password'] = j.get('password', '?')
                        s['success'] = True
                    elif j.get('eventid') == 'cowrie.command.input':
                        cmd = j.get('input', '').strip()
                        if cmd and cmd not in s['commands']:
                            s['commands'].append(cmd)
                    elif j.get('eventid') == 'cowrie.session.closed':
                        s['duration'] = float(j.get('duration', 0))
                except Exception as e:
                    logging.error(f"COWRIE PARSE ERROR: {e}")
    except Exception as e:
        logging.error(f"COWRIE READ ERROR: {e}")
    return sorted(sessions.values(), key=lambda x: x.get('time',''), reverse=True)[:20]

# === CUSTOM: FROM JSON ===
def get_custom_attacks():
    attacks = []
    if not os.path.exists(CUSTOM_LOG): return attacks
    try:
        with open(CUSTOM_LOG) as f:
            for line in f:
                try:
                    j = json.loads(line.strip())
                    attacks.append({
                        'time': j.get('timestamp', datetime.now(IST).isoformat()),
                        'ip': j.get('src_ip', '?'),
                        'username': j.get('username', '?'),
                        'password': j.get('password', '?'),
                        'command': j.get('command', '')
                    })
                except Exception as e:
                    logging.error(f"CUSTOM PARSE ERROR: {e}")
    except Exception as e:
        logging.error(f"CUSTOM READ ERROR: {e}")
    return sorted(attacks, key=lambda x: x['time'], reverse=True)[:20]

def utc_to_ist(ts):
    if not ts: return "N/A"
    try:
        if 'Z' in ts:
            utc = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        elif '+' in ts:
            utc = datetime.fromisoformat(ts)
        else:
            utc = datetime.fromisoformat(ts + '+00:00')
        return utc.astimezone(IST).strftime('%Y-%m-%d %H:%M:%S IST')
    except:
        return ts.split('.')[0].replace('T', ' ') + " IST"

HTML = '''
<!DOCTYPE html>
<html><head><title>Dual Honeypot Dashboard</title>
<meta http-equiv="refresh" content="10">
<style>
  body {font-family:monospace;background:#000;color:#0f0;margin:0;padding:0;}
  .tabs {overflow:hidden;background:#001100;border-bottom:1px solid #0f0;}
  .tablink {background:#001100;color:#0f0;float:left;border:none;outline:none;cursor:pointer;padding:14px 16px;font-size:17px;}
  .tablink:hover {background:#002200;}
  .tablink.active {background:#003300;color:#0ff;}
  .tabcontent {display:none;padding:20px;}
  .box {background:#001100;padding:15px;border:1px solid #0f0;border-radius:8px;margin:10px 0;}
  table {width:100%;border-collapse:collapse;font-size:0.9em;}
  th,td {border:1px solid #0f0;padding:8px;text-align:left;vertical-align:top;}
  th {background:#001100;}
  .ip {color:#0ff;font-weight:bold;}
  .success {color:#0f0;font-weight:bold;}
  .failed {color:#f00;font-weight:bold;}
  .cmd {font-size:0.8em;color:#0ff;background:#001a00;padding:2px 4px;border-radius:3px;margin:1px 0;display:block;}
  .na {color:#666;font-style:italic;}
</style>
</head><body>

<div class="tabs">
  <button class="tablink active" onclick="openTab(event,'Cowrie')">Cowrie (2222)</button>
  <button class="tablink" onclick="openTab(event,'Custom')">Custom (2223)</button>
</div>

<div id="Cowrie" class="tabcontent" style="display:block;">
  <h1>Cowrie Honeypot - Port 2222</h1>
  <div class="box">Last Updated: {{ now }} | Sessions: {{ cowrie|length }}</div>
  <table>
    <tr><th>Time (IST)</th><th>IP</th><th>Geo</th><th>Client</th><th>Creds</th><th>Status</th><th>Commands</th><th>Duration</th></tr>
    {% for s in cowrie %}
    {% set g = geo.get(s.ip, ('?','?','?')) %}
    <tr>
      <td>{{ utc_to_ist(s.time) }}</td>
      <td class="ip">{{ s.ip }}</td>
      <td>{{ g[0] }}<br><small>{{ g[1] }}, {{ g[2] }}</small></td>
      <td><small>{{ s.client }}</small></td>
      <td><small>{{ s.username }} / {{ s.password }}</small></td>
      <td>{% if s.success %}<span class="success">SUCCESS</span>{% else %}<span class="failed">FAILED</span>{% endif %}</td>
      <td>{% if s.commands %}{% for c in s.commands[:2] %}<div class="cmd">{{ c }}</div>{% endfor %}{% if s.commands|length > 2 %}<small>+{{ s.commands|length - 2 }} more</small>{% endif %}{% else %}<span class="na">N/A</span>{% endif %}</td>
      <td>{{ "%.1f"|format(s.duration) }}s</td>
    </tr>
    {% endfor %}
  </table>
</div>

<div id="Custom" class="tabcontent">
  <h1>Custom Honeypot - Port 2223</h1>
  <div class="box">Last Updated: {{ now }} | Attacks: {{ custom|length }}</div>
  <table>
    <tr><th>Time (IST)</th><th>IP</th><th>Geo</th><th>User/Pass</th><th>Command</th></tr>
    {% for a in custom %}
    {% set g = geo.get(a.ip, ('?','?','?')) %}
    <tr>
      <td>{{ utc_to_ist(a.time) }}</td>
      <td class="ip">{{ a.ip }}</td>
      <td>{{ g[0] }}<br><small>{{ g[1] }}, {{ g[2] }}</small></td>
      <td><small>{{ a.username }} / {{ a.password }}</small></td>
      <td>{% if a.command %}<div class="cmd">{{ a.command }}</div>{% else %}<i>login only</i>{% endif %}</td>
    </tr>
    {% endfor %}
  </table>
</div>

<script>
function openTab(evt, tabName) {
  document.querySelectorAll('.tabcontent').forEach(el => el.style.display = 'none');
  document.querySelectorAll('.tablink').forEach(el => el.classList.remove('active'));
  document.getElementById(tabName).style.display = 'block';
  evt.currentTarget.classList.add('active');
}
</script>

</body></html>
'''

@app.route('/')
def index():
    try:
        cowrie = get_cowrie_sessions()
        custom = get_custom_attacks()
        geo = {}
        for item in cowrie + custom:
            ip = item.get('ip', '?')
            if ip not in geo:
                geo[ip] = get_geo(ip)
        return render_template_string(HTML,
            cowrie=cowrie, custom=custom, geo=geo,
            now=datetime.now(IST).strftime('%Y-%m-%d %H:%M:%S IST'),
            utc_to_ist=utc_to_ist
        )
    except Exception as e:
        return f"<pre>ERROR: {e}</pre>", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
