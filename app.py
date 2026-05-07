from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import hashlib, os, uuid
from urllib import request as urllib_req
import json as json_lib

DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK',
    'https://canary.discord.com/api/webhooks/1501700878216724670/y9xcb47TARckMxU5izVzx4xj7a-qvWivolWetWuNfEd-uS7gchi8GMwdJEN64Ba-gTW7')

def discord_log(title, color, fields):
    try:
        embed = {"title": title, "color": color, "fields": fields,
                 "timestamp": datetime.utcnow().isoformat()}
        data = json_lib.dumps({"embeds": [embed]}).encode('utf-8')
        req = urllib_req.Request(DISCORD_WEBHOOK, data=data,
            headers={'Content-Type': 'application/json'}, method='POST')
        urllib_req.urlopen(req, timeout=5)
    except:
        pass

app = Flask(__name__)

# Fix Render.com postgres:// → postgresql:// for SQLAlchemy
_db_url = os.environ.get('DATABASE_URL', 'sqlite:///zenox.db')
if _db_url.startswith('postgres://'):
    _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

ADMIN_SECRET = os.environ.get('ADMIN_SECRET', 'zenox_admin_2024')

# ── Models ────────────────────────────────────────────────────────────────────

class User(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)  # SHA256
    key      = db.Column(db.String(64), nullable=False)
    hwid     = db.Column(db.String(128), nullable=True)
    banned   = db.Column(db.Boolean, default=False)
    ban_until= db.Column(db.DateTime, nullable=True)
    created  = db.Column(db.DateTime, default=datetime.utcnow)

class Key(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    key      = db.Column(db.String(64), unique=True, nullable=False)
    duration = db.Column(db.String(32), nullable=False)  # Day/Week/Month/etc
    used     = db.Column(db.Boolean, default=False)
    blacklisted = db.Column(db.Boolean, default=False)
    created  = db.Column(db.DateTime, default=datetime.utcnow)
    expires  = db.Column(db.DateTime, nullable=True)

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def gen_key(duration):
    k = 'ZENOX-' + uuid.uuid4().hex[:8].upper() + '-' + uuid.uuid4().hex[:8].upper()
    now = datetime.utcnow()
    durations = {
        'Day':      now + timedelta(days=1),
        'Week':     now + timedelta(weeks=1),
        'Month':    now + timedelta(days=30),
        '3Month':   now + timedelta(days=90),
        'Year':     now + timedelta(days=365),
        '3Year':    now + timedelta(days=1095),
        'Lifetime': None
    }
    expires = durations.get(duration)
    return k, expires

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/login', methods=['POST'])
def login():
    d = request.get_json(silent=True) or {}
    username = d.get('username','').strip()
    password = d.get('password','').strip()
    hwid     = d.get('hwid','').strip()

    if not username or not password or not hwid:
        return jsonify({'status':'error','message':'Missing fields'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'status':'error','message':'Login Failed'}), 401
    if user.password != hash_pw(password):
        return jsonify({'status':'error','message':'Login Failed'}), 401

    # Ban check
    if user.banned:
        if user.ban_until and datetime.utcnow() > user.ban_until:
            user.banned = False
            db.session.commit()
        else:
            until = user.ban_until.strftime('%Y-%m-%d %H:%M') if user.ban_until else 'Permanent'
            return jsonify({'status':'error','message':f'Account banned until {until}'}), 403

    # Key expiry check
    key_obj = Key.query.filter_by(key=user.key).first()
    if key_obj:
        if key_obj.blacklisted:
            return jsonify({'status':'error','message':'Key blacklisted'}), 403
        if key_obj.expires and datetime.utcnow() > key_obj.expires:
            return jsonify({'status':'error','message':'Key expired'}), 403

    # HWID check
    if user.hwid and user.hwid != hwid:
        return jsonify({'status':'error','message':'HWID Does Not Match Please Open A Ticket'}), 403

    # First login - bind HWID
    if not user.hwid:
        user.hwid = hwid
        db.session.commit()

    discord_log("✅ Login", 0x00FF00, [
        {"name": "Username", "value": username, "inline": True},
        {"name": "HWID", "value": hwid[:16]+"...", "inline": True},
        {"name": "IP", "value": request.remote_addr or "unknown", "inline": True}
    ])
    return jsonify({'status':'ok','message':'Login successful','username':username}), 200


@app.route('/register', methods=['POST'])
def register():
    d = request.get_json(silent=True) or {}
    username = d.get('username','').strip()
    password = d.get('password','').strip()
    key      = d.get('key','').strip()
    hwid     = d.get('hwid','').strip()

    if not username or not password or not key or not hwid:
        return jsonify({'status':'error','message':'Missing fields'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'status':'error','message':'Username already taken'}), 409

    key_obj = Key.query.filter_by(key=key).first()
    if not key_obj:
        return jsonify({'status':'error','message':'Invalid key'}), 403
    if key_obj.used:
        return jsonify({'status':'error','message':'Key already used'}), 403
    if key_obj.blacklisted:
        return jsonify({'status':'error','message':'Key blacklisted'}), 403

    key_obj.used = True
    user = User(username=username, password=hash_pw(password), key=key, hwid=hwid)
    db.session.add(user)
    db.session.commit()

    discord_log("📝 Register", 0x0055FF, [
        {"name": "Username", "value": username, "inline": True},
        {"name": "Key", "value": key, "inline": True},
        {"name": "HWID", "value": hwid[:16]+"...", "inline": True},
        {"name": "IP", "value": request.remote_addr or "unknown", "inline": True}
    ])
    return jsonify({'status':'ok','message':'Account created'}), 200


# ── Admin routes (protected by ADMIN_SECRET) ─────────────────────────────────

def check_admin(d):
    return d.get('secret') == ADMIN_SECRET

@app.route('/admin/genkey', methods=['POST'])
def admin_genkey():
    d = request.get_json(silent=True) or {}
    if not check_admin(d):
        return jsonify({'status':'error','message':'Unauthorized'}), 401
    duration = d.get('duration','Month')
    # Accept a pre-generated key from client, or generate one server-side
    provided_key = d.get('key','').strip()
    if provided_key:
        k = provided_key
        now = datetime.utcnow()
        durations = {
            'Day':      now + timedelta(days=1),
            'Week':     now + timedelta(weeks=1),
            'Month':    now + timedelta(days=30),
            '3Month':   now + timedelta(days=90),
            'Year':     now + timedelta(days=365),
            '3Year':    now + timedelta(days=1095),
            'Lifetime': None
        }
        expires = durations.get(duration)
    else:
        k, expires = gen_key(duration)
    # Don't duplicate if key already exists
    if not Key.query.filter_by(key=k).first():
        key_obj = Key(key=k, duration=duration, expires=expires)
        db.session.add(key_obj)
        db.session.commit()
    return jsonify({'status':'ok','key':k,'duration':duration,
                    'expires': expires.strftime('%Y-%m-%d') if expires else 'Lifetime'}), 200

@app.route('/admin/ban', methods=['POST'])
def admin_ban():
    d = request.get_json(silent=True) or {}
    if not check_admin(d): return jsonify({'status':'error','message':'Unauthorized'}), 401
    username = d.get('username')
    duration_days = d.get('days', 0)
    user = User.query.filter_by(username=username).first()
    if not user: return jsonify({'status':'error','message':'User not found'}), 404
    user.banned = True
    user.ban_until = datetime.utcnow() + timedelta(days=duration_days) if duration_days > 0 else None
    db.session.commit()
    return jsonify({'status':'ok','message':f'{username} banned'}), 200

@app.route('/admin/unban', methods=['POST'])
def admin_unban():
    d = request.get_json(silent=True) or {}
    if not check_admin(d): return jsonify({'status':'error','message':'Unauthorized'}), 401
    user = User.query.filter_by(username=d.get('username')).first()
    if not user: return jsonify({'status':'error','message':'User not found'}), 404
    user.banned = False
    user.ban_until = None
    db.session.commit()
    return jsonify({'status':'ok'}), 200

@app.route('/admin/blacklist', methods=['POST'])
def admin_blacklist():
    d = request.get_json(silent=True) or {}
    if not check_admin(d): return jsonify({'status':'error','message':'Unauthorized'}), 401
    key_obj = Key.query.filter_by(key=d.get('key')).first()
    if not key_obj: return jsonify({'status':'error','message':'Key not found'}), 404
    key_obj.blacklisted = True
    db.session.commit()
    return jsonify({'status':'ok'}), 200

@app.route('/admin/resethwid', methods=['POST'])
def admin_resethwid():
    d = request.get_json(silent=True) or {}
    if not check_admin(d): return jsonify({'status':'error','message':'Unauthorized'}), 401
    user = User.query.filter_by(username=d.get('username')).first()
    if not user: return jsonify({'status':'error','message':'User not found'}), 404
    user.hwid = None
    db.session.commit()
    return jsonify({'status':'ok','message':'HWID reset'}), 200

@app.route('/admin/users', methods=['POST'])
def admin_users():
    d = request.get_json(silent=True) or {}
    if not check_admin(d): return jsonify({'status':'error','message':'Unauthorized'}), 401
    users = User.query.all()
    return jsonify({'status':'ok','users':[{
        'username':u.username,'banned':u.banned,'hwid':u.hwid[:8]+'...' if u.hwid else None,
        'key':u.key,'created':u.created.strftime('%Y-%m-%d')
    } for u in users]}), 200

@app.route('/admin/keys', methods=['POST'])
def admin_keys():
    d = request.get_json(silent=True) or {}
    if not check_admin(d): return jsonify({'status':'error','message':'Unauthorized'}), 401
    keys = Key.query.all()
    return jsonify({'status':'ok','keys':[{
        'key':k.key,'duration':k.duration,'used':k.used,'blacklisted':k.blacklisted,
        'expires':k.expires.strftime('%Y-%m-%d') if k.expires else 'Lifetime'
    } for k in keys]}), 200

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status':'ok','service':'Zenox Auth'}), 200

# Create tables on startup (works with gunicorn too)
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
