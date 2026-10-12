import argparse
import json
import sqlite3
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HTML = '''<!doctype html><html><head><meta charset="utf-8"><title>Team EDR</title>
<style>body{font:16px system-ui;background:#101827;color:#e9eef7;margin:32px}h1{margin-bottom:4px}small{color:#aab8cd}.cards{display:flex;gap:18px;flex-wrap:wrap;margin:24px 0}.card,section{background:#1c293c;padding:20px;border-radius:12px}.card strong{display:block;font-size:28px}section{margin:18px 0;overflow:auto}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #35445c}pre{white-space:pre-wrap}button{padding:8px}#error{color:#ffb8a7}</style></head>
<body><h1>Team EDR</h1><small>Local monitoring • Rule-based detection • Notification response</small><p id="error"></p>
<div class="cards"><div class="card">Events<strong id="events">0</strong></div><div class="card">Alerts<strong id="alerts">0</strong></div><div class="card">Responses<strong id="responses">0</strong></div></div>
<section><h2>Recent alerts</h2><table><thead><tr><th>Detected</th><th>Rule</th><th>Severity</th><th>Source</th><th>Mode</th><th>Details</th></tr></thead><tbody id="rows"></tbody></table></section>
<section><h2>Collector and agent status history</h2><pre id="health"></pre></section>
<section><h2>Latest events</h2><pre id="recent"></pre></section>
<script>
function node(tag,text){let x=document.createElement(tag);x.textContent=text;return x;}
async function refresh(){try{let r=await fetch('/api/status');if(!r.ok)throw Error(await r.text());let d=await r.json();for(let k of ['events','alerts','responses'])document.getElementById(k).textContent=d.counts[k];let body=document.getElementById('rows');body.replaceChildren();for(let a of d.alerts){let row=document.createElement('tr');for(let v of [a.detection_timestamp,a.rule_id,a.severity+' / '+a.severity_label,a.source_ip,a.synthetic?'SYNTHETIC':'Live'])row.append(node('td',v));let cell=document.createElement('td'),detail=document.createElement('details');detail.append(node('summary','Evidence and timing'),node('pre',JSON.stringify(a,null,2)));cell.append(detail);row.append(cell);body.append(row);}document.getElementById('health').textContent=d.health.map(x=>JSON.stringify(x)).join('\\n');document.getElementById('recent').textContent=d.events.map(x=>JSON.stringify(x)).join('\\n');document.getElementById('error').textContent='';}catch(e){document.getElementById('error').textContent='Status unavailable: '+e.message;}}refresh();setInterval(refresh,3000);
</script></body></html>'''


def status(path):
    if not Path(path).is_file():
        raise FileNotFoundError('Start the agent first')
    connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        counts = {table:connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0] for table in ('events','alerts','responses')}
        output = {'counts':counts}
        for table in ('alerts','health','events'):
            output[table] = [dict(json.loads(row[1]), recorded_timestamp=row[0]) for row in connection.execute(f'SELECT recorded,payload FROM {table} ORDER BY id DESC LIMIT 30')]
        return output
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--database', default='runs/live.db')
    parser.add_argument('--port', type=int, default=8080)
    args = parser.parse_args()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/':
                data, kind, code = HTML.encode(), 'text/html; charset=utf-8', 200
            elif self.path == '/api/status':
                try:
                    data, kind, code = json.dumps(status(args.database)).encode(), 'application/json', 200
                except (sqlite3.Error, FileNotFoundError) as exc:
                    data, kind, code = str(exc).encode(), 'text/plain', 503
            else:
                data, kind, code = b'Not found', 'text/plain', 404
            self.send_response(code)
            self.send_header('Content-Type', kind)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *args):
            pass
    print(f'Open http://127.0.0.1:{args.port} in the Ubuntu VM browser', flush=True)
    server = ThreadingHTTPServer(('127.0.0.1',args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == '__main__':
    main()
