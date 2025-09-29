from flask import Flask, request, render_template, send_file, jsonify
import csv, io, re, datetime
from urllib.parse import unquote, urlparse, parse_qs

app = Flask(__name__)

# RULES: name -> regex (simple educational heuristics)
RULES = [
    ("SQL Injection", re.compile(r"(?i)(\bunion\b|\bselect\b|\binsert\b|\bdrop\b|\bupdate\b|\bdelete\b|\bwhere\b.*=|or\s+1=1|--|;|\bconcat\b)")),
    ("Cross Site Scripting (XSS)", re.compile(r"(?i)(<script\b|%3Cscript|onerror=|onload=|javascript:)")),
    ("Directory Traversal", re.compile(r"(\.\./|\.\.\\)")),
    ("Command Injection", re.compile(r"(?i)(\b(wget|curl|nc|bash|sh)\b|;|\|\||\&\&)")),
    ("Web-shell upload / suspicious file", re.compile(r"(?i)(cmd\.jsp|shell\.php|backdoor|webshell|\.asp$|\.jsp$|\.php$)")),
    ("SSRF", re.compile(r"(?i)(http://127\.0\.0\.1|http://localhost|file://)")),
    ("HTTP Parameter Pollution", re.compile(r"(\&.*\=.+\&.*\=)")),
    ("XML External Entity (XXE)", re.compile(r"(?i)<!ENTITY|SYSTEM\s+\"file:)")),
    ("Typosquatting / suspicious host", re.compile(r"(?i)(xn--|paypal-security|gooogle|facebok|micorsoft)")),
]

def tokenize_url(url):
    try:
        u = unquote(url)
    except:
        u = url
    # if no scheme, prefix to parse correctly
    if "://" not in u:
        if u.startswith("/"):
            u = "http://example.com" + u
        else:
            u = "http://" + u
    parsed = urlparse(u)
    path = parsed.path or "/"
    query = parsed.query or ""
    params = parse_qs(query)
    tokens = []
    tokens.append(parsed.netloc)
    tokens.append(path)
    for k, v in params.items():
        tokens.append(k)
        tokens += v
    tokens += [t for t in re.split(r'[\W_/]+', path) if t]
    return tokens

def rule_checks(text):
    findings = []
    for name, pattern in RULES:
        if pattern.search(text or ""):
            findings.append(name)
    return findings

def score_url(url):
    text = url if isinstance(url, str) else str(url)
    toks = tokenize_url(text)
    findings = rule_checks(text)
    # heuristic score: base on number of findings + numeric tokens count
    numeric_tokens = sum(1 for t in toks if re.search(r'\d{2,}', t))
    score = min(1.0, (len(findings) * 0.25) + (numeric_tokens / 10.0))
    return {"score": round(score, 2), "findings": findings, "tokens": toks}

# Simple in-memory store (for demo). For persistence, replace with SQLite/Postgres.
scan_history = []

@app.route("/", methods=["GET", "POST"])
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan_form():
    url = request.form.get("url_input", "").strip()
    if not url:
        return render_template("index.html", error="Please enter a URL or path.")
    result = score_url(url)
    # save lightweight history
    scan_history.insert(0, {
        "url": url,
        "score": result["score"],
        "findings": result["findings"],
        "time": datetime.datetime.utcnow().isoformat()
    })
    # keep only last 200
    if len(scan_history) > 200:
        scan_history.pop()
    return render_template("results.html", input=url, result=result)

@app.route("/upload", methods=["POST"])
def upload_csv():
    f = request.files.get("file")
    if not f:
        return render_template("index.html", error="Please upload a CSV file (column: url).")
    data = f.read().decode('utf-8', errors='ignore')
    reader = csv.DictReader(io.StringIO(data))
    rows = []
    for row in reader:
        # try standard column names
        url = row.get("url") or row.get("request") or next(iter(row.values()), "")
        res = score_url(url)
        rows.append({"url": url, "score": res["score"], "findings": ";".join(res["findings"])})
    # prepare CSV download
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["url", "score", "findings"])
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    output.seek(0)
    csv_bytes = output.getvalue().encode('utf-8')
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"urlshield_results_{timestamp}.csv"
    return send_file(io.BytesIO(csv_bytes), mimetype="text/csv", as_attachment=True, download_name=filename)

@app.route("/history")
def history():
    # show last 50 records for demo
    return render_template("history.html", items=scan_history[:50])

@app.route("/api/scan", methods=["POST"])
def api_scan():
    payload = request.get_json(force=True, silent=True)
    if not payload or "url" not in payload:
        return jsonify({"error": "send JSON with 'url' field"}), 400
    url = payload.get("url")
    res = score_url(url)
    return jsonify({"url": url, "result": res})

if __name__ == "__main__":
    # Debug True is fine for local demo, but disable in production
    app.run(host="0.0.0.0", port=8000, debug=True)
