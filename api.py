from flask import Flask, request, session, jsonify, render_template_string, redirect, url_for, abort
from urllib.parse import urlparse
from datetime import datetime
import json
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = "nano_vault_secure_8822_alpha" # In production, use os.urandom(24)

# Security Headers & Config
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800 # 30 Minute timeout
)

DATA_FILE = "sites.json"
STATS_FILE = "stats.json"

# Initialize Data
for file, default in [(DATA_FILE, {}), (STATS_FILE, [])]:
    if not os.path.exists(file):
        with open(file, "w") as f:
            json.dump(default, f)

# ------------------------
# SECURITY MIDDLEWARE
# ------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged"):
            # Redirect to login if accessing UI, else return 403 for API
            if request.path == "/dashboard":
                return redirect(url_for('login_page'))
            return jsonify({"error": "Unauthorized Access"}), 403
        return f(*args, **kwargs)
    return decorated_function

# ------------------------
# CORE LOGIC
# ------------------------
def normalize(site):
    site = site.strip().lower()
    if not site.startswith("http"): site = "http://" + site
    return urlparse(site).netloc.replace("www.", "")

def load_db(file):
    with open(file, "r") as f: return json.load(f)

def save_db(file, data):
    with open(file, "w") as f: json.dump(data, f, indent=4)

def log_event():
    stats = load_db(STATS_FILE)
    stats.append(datetime.now().strftime("%Y-%m-%d"))
    save_db(STATS_FILE, stats[-5000:]) # Keep last 5k requests

# ------------------------
# API ENDPOINTS
# ------------------------

@app.route("/Nano")
@login_required
def nano():
    site_query = request.args.get("search")
    if not site_query: return jsonify({"status": "error", "msg": "Empty query"})
    
    log_event()
    site = normalize(site_query)
    db = load_db(DATA_FILE)
    
    if site in db:
        return jsonify({"status": "Found", "site": site, "bins": db[site]})
    return jsonify({"status": "Not Found"})

@app.route("/api/admin/login", methods=["POST"])
def api_login():
    data = request.json
    # High security: Clear existing session first
    session.clear()
    if data.get("username") == "Admin" and data.get("password") == "Admin@000":
        session.permanent = True
        session["logged"] = True
        return jsonify({"success": True})
    return jsonify({"success": False}), 401

@app.route("/api/admin/logout")
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route("/api/admin/add", methods=["POST"])
@login_required
def add():
    data = request.json
    site, bin_no = normalize(data["site"]), data["bin"]
    db = load_db(DATA_FILE)
    if site not in db: db[site] = []
    if bin_no not in db[site]: db[site].append(bin_no)
    save_db(DATA_FILE, db)
    return jsonify({"success": True})

@app.route("/api/admin/remove", methods=["POST"])
@login_required
def remove():
    site = normalize(request.json["site"])
    db = load_db(DATA_FILE)
    if site in db:
        del db[site]
        save_db(DATA_FILE, db)
        return jsonify({"success": True})
    return jsonify({"success": False})

@app.route("/api/admin/stats")
@login_required
def stats():
    db = load_db(DATA_FILE)
    logs = load_db(STATS_FILE)
    today = datetime.now().strftime("%Y-%m-%d")
    return jsonify({
        "count": len(db),
        "reqs": logs.count(today),
        "db_size": f"{os.path.getsize(DATA_FILE)/1024:.1f}KB"
    })

# ------------------------
# VIEWS (HTML)
# ------------------------

@app.route("/")
def login_page():
    if session.get("logged"): return redirect(url_for('dashboard'))
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>NanoLogin | Secure Gate</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        body { background: radial-gradient(circle at top left, #0f172a, #1e293b); height: 100vh; display: flex; align-items: center; justify-content: center; font-family: 'Inter', sans-serif; color: white; }
        .glass-box { background: rgba(255, 255, 255, 0.03); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.1); box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); }
    </style>
</head>
<body>
    <div class="glass-box p-10 rounded-3xl w-full max-w-md border-t border-white/20">
        <div class="text-center mb-8">
            <div class="inline-flex p-4 bg-blue-600/20 rounded-2xl mb-4"><i data-lucide="fingerprint" class="w-10 h-10 text-blue-400"></i></div>
            <h1 class="text-3xl font-bold tracking-tight">Access Control</h1>
            <p class="text-slate-400 mt-2">Enter credentials to unlock dashboard</p>
        </div>
        <div class="space-y-4">
            <div>
                <label class="text-xs font-semibold text-slate-500 uppercase ml-1">Identity</label>
                <input type="text" id="u" class="w-full bg-slate-900/50 border border-slate-700 p-4 rounded-xl mt-1 outline-none focus:border-blue-500 transition-all" placeholder="Username">
            </div>
            <div>
                <label class="text-xs font-semibold text-slate-500 uppercase ml-1">Keyphrase</label>
                <input type="password" id="p" class="w-full bg-slate-900/50 border border-slate-700 p-4 rounded-xl mt-1 outline-none focus:border-blue-500 transition-all" placeholder="••••••••">
            </div>
            <button onclick="doLogin()" class="w-full bg-blue-600 hover:bg-blue-500 py-4 rounded-xl font-bold text-lg mt-4 shadow-lg shadow-blue-900/20 transition-all active:scale-95">Verify Identity</button>
        </div>
    </div>
    <script>
        lucide.createIcons();
        function doLogin(){
            fetch("/api/admin/login", {
                method:"POST",
                headers:{"Content-Type":"application/json"},
                body:JSON.stringify({username:document.getElementById("u").value, password:document.getElementById("p").value})
            }).then(r=> r.ok ? window.location.href="/dashboard" : alert("Access Denied"));
        }
    </script>
</body>
</html>
""")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>Nano | System Admin</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        body { background: #020617; color: #f8fafc; font-family: 'Inter', sans-serif; }
        .card { background: #0f172a; border: 1px solid #1e293b; border-radius: 1.5rem; transition: all 0.3s; }
        .card:hover { border-color: #3b82f6; transform: translateY(-2px); }
        .input-dark { background: #1e293b; border: 1px solid #334155; border-radius: 0.75rem; padding: 0.75rem; width: 100%; outline: none; }
        .input-dark:focus { border-color: #3b82f6; }
    </style>
</head>
<body class="flex">

    <aside class="w-72 h-screen border-r border-slate-800 p-8 flex flex-col fixed">
        <div class="flex items-center gap-3 mb-12">
            <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-500/20">
                <i data-lucide="zap" class="text-white w-6 h-6"></i>
            </div>
            <span class="text-xl font-bold tracking-tight">NANO<span class="text-blue-500">GLAZE</span></span>
        </div>
        
        <nav class="space-y-2 flex-1">
            <div class="text-xs font-bold text-slate-500 uppercase tracking-widest mb-4">Core Management</div>
            <button class="w-full flex items-center gap-3 p-4 bg-blue-600/10 text-blue-400 rounded-2xl border border-blue-500/20">
                <i data-lucide="layout-grid" class="w-5 h-5"></i> Dashboard
            </button>
            <a href="/api/admin/logout" class="w-full flex items-center gap-3 p-4 text-slate-400 hover:bg-slate-800 rounded-2xl transition-all">
                <i data-lucide="log-out" class="w-5 h-5"></i> Terminate Session
            </a>
        </nav>
        
        <div class="p-4 bg-slate-900/50 rounded-2xl border border-slate-800">
            <p class="text-xs text-slate-500 mb-1">Status</p>
            <div class="flex items-center gap-2">
                <div class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                <span class="text-sm font-semibold">System Encrypted</span>
            </div>
        </div>
    </aside>

    <main class="ml-72 flex-1 p-12">
        <header class="flex justify-between items-start mb-12">
            <div>
                <h1 class="text-4xl font-extrabold tracking-tight">Control Center</h1>
                <p class="text-slate-400 mt-2">Manage your secure database entries</p>
            </div>
            <div class="text-right">
                <div id="clock" class="text-xl font-mono font-bold text-blue-500">00:00:00</div>
                <div class="text-slate-500 text-sm">Session Active</div>
            </div>
        </header>

        <div class="grid grid-cols-3 gap-6 mb-12">
            <div class="card p-8">
                <p class="text-slate-500 font-medium">Total Indexed Sites</p>
                <h2 id="st-count" class="text-4xl font-black mt-2">0</h2>
            </div>
            <div class="card p-8 border-l-4 border-l-blue-500">
                <p class="text-slate-500 font-medium">Requests Today</p>
                <h2 id="st-reqs" class="text-4xl font-black mt-2 text-blue-400">0</h2>
            </div>
            <div class="card p-8">
                <p class="text-slate-500 font-medium">Database Footprint</p>
                <h2 id="st-size" class="text-4xl font-black mt-2 text-indigo-400">0.0KB</h2>
            </div>
        </div>

        <div class="grid grid-cols-2 gap-8">
            <section class="card p-8">
                <h3 class="text-xl font-bold mb-6 flex items-center gap-2">
                    <i data-lucide="search" class="w-5 h-5 text-blue-400"></i> Query Database
                </h3>
                <div class="flex gap-2">
                    <input type="text" id="sq" class="input-dark" placeholder="Domain name...">
                    <button onclick="search()" class="bg-blue-600 px-6 rounded-xl font-bold hover:bg-blue-500 transition-all">Search</button>
                </div>
                <div id="res" class="mt-4 p-4 bg-slate-950 rounded-xl min-h-[80px] text-sm font-mono text-blue-300 overflow-auto border border-slate-800">
                    // Output awaiting query...
                </div>
            </section>

            <section class="card p-8">
                <h3 class="text-xl font-bold mb-6 flex items-center gap-2">
                    <i data-lucide="plus-circle" class="w-5 h-5 text-green-400"></i> Insert Entry
                </h3>
                <div class="space-y-4">
                    <input type="text" id="as" class="input-dark" placeholder="Site (domain.com)">
                    <input type="text" id="ab" class="input-dark" placeholder="Bin Number">
                    <button onclick="addSite()" class="w-full bg-green-600 py-3 rounded-xl font-bold hover:bg-green-500 transition-all">Execute Insertion</button>
                </div>
            </section>

            <section class="card p-8 col-span-2">
                <h3 class="text-xl font-bold mb-6 flex items-center gap-2 text-red-400">
                    <i data-lucide="trash-2" class="w-5 h-5"></i> Purge Records
                </h3>
                <div class="flex gap-4">
                    <input type="text" id="rs" class="input-dark flex-1" placeholder="Target domain to delete...">
                    <button onclick="removeSite()" class="bg-red-600/20 text-red-400 border border-red-500/30 px-10 rounded-xl font-bold hover:bg-red-600 hover:text-white transition-all">Confirm Deletion</button>
                </div>
            </section>
        </div>
    </main>

    <script>
        lucide.createIcons();
        function refresh() {
            fetch("/api/admin/stats").then(r=>r.json()).then(d=>{
                document.getElementById('st-count').innerText = d.count;
                document.getElementById('st-reqs').innerText = d.reqs;
                document.getElementById('st-size').innerText = d.db_size;
            });
        }
        function search() {
            fetch("/Nano?search="+document.getElementById('sq').value).then(r=>r.json()).then(d=>{
                document.getElementById('res').innerHTML = `<pre>${JSON.stringify(d, null, 2)}</pre>`;
                refresh();
            });
        }
        function addSite() {
            fetch("/api/admin/add", {
                method:"POST", headers:{"Content-Type":"application/json"},
                body: JSON.stringify({site: document.getElementById('as').value, bin: document.getElementById('ab').value})
            }).then(() => { alert("Record Added"); refresh(); });
        }
        function removeSite() {
            if(!confirm("Purge this record?")) return;
            fetch("/api/admin/remove", {
                method:"POST", headers:{"Content-Type":"application/json"},
                body: JSON.stringify({site: document.getElementById('rs').value})
            }).then(() => { alert("Record Deleted"); refresh(); });
        }
        setInterval(() => { document.getElementById('clock').innerText = new Date().toLocaleTimeString(); }, 1000);
        refresh();
    </script>
</body>
</html>
""")

if __name__ == "__main__":
    app.run(debug=True, port=8080)
