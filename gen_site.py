import json
m = json.load(open("model.json"))
feats, mu, sd, coef, icpt = m["features"], m["mean"], m["scale"], m["coef"], m["intercept"]
susp = m["susp_words"]
mt = m["metrics"]
acc, auc, base = mt["cv_accuracy"], mt["auc"], mt["baseline_accuracy"]
DOMAIN = "phishguard.vercel.app"
JS_MODEL = f"""const FEATURES = {json.dumps(feats)};
const MEAN = {json.dumps(mu)};
const SCALE = {json.dumps(sd)};
const COEF = {json.dumps(coef)};
const INTERCEPT = {json.dumps(icpt)};
const SUSP_WORDS = {json.dumps(susp)};
function extractFeatures(url) {{
  const u = url.toLowerCase();
  const isHttps = u.startsWith("https://") ? 1 : 0;
  const rest = u.includes("://") ? u.split("://")[1] : u;
  const host = rest.split(/[/?#]/)[0];
  const path = rest.slice(host.length);
  const hasIp = /^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(host) ? 1 : 0;
  const parts = host.split(".");
  const numSub = hasIp ? 0 : Math.max(0, parts.length - 2);
  let susp = 0;
  SUSP_WORDS.forEach(w => {{ susp += u.split(w).length - 1; }});
  const digits = (u.match(/[0-9]/g) || []).length;
  return [u.length, (u.match(/\\./g) || []).length, (u.match(/-/g) || []).length,
    digits, u.includes("@") ? 1 : 0, hasIp, numSub, susp, isHttps, path.length];
}}
function phishProb(url) {{
  const x = extractFeatures(url);
  let z = INTERCEPT;
  const contrib = [];
  for (let i = 0; i < 10; i++) {{
    const s = (x[i] - MEAN[i]) / SCALE[i];
    z += s * COEF[i];
    contrib.push({{name: FEATURES[i], value: x[i], c: s * COEF[i]}});
  }}
  const p = 1 / (1 + Math.exp(-z));
  return {{prob: p * 100, contrib: contrib, feats: x}};
}}"""
index = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhishGuard — Phishing URL Detector | AI/ML Project</title>
<meta name="description" content="PhishGuard checks any link for phishing signs — suspicious words, IP hosts, fake subdomains and more — using a logistic regression model trained on 1,000 URLs. Paste a link and check it live in your browser.">
<link rel="canonical" href="https://{DOMAIN}/">
<meta property="og:title" content="PhishGuard — Phishing URL Detector">
<meta property="og:description" content="Paste any link and instantly see its phishing risk, with the exact reasons the model flagged it.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://{DOMAIN}/">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="PhishGuard — Phishing URL Detector">
<meta name="twitter:description" content="Logistic regression phishing URL detector. Check any link live in your browser.">
<script type="application/ld+json">{{"@context":"https://schema.org","@type":"WebApplication","name":"PhishGuard","applicationCategory":"EducationalApplication","description":"Phishing URL detector using logistic regression on URL features.","url":"https://{DOMAIN}/"}}</script>
<style>
body{{font-family:Arial,Helvetica,sans-serif;color:#000;background:#fff;max-width:720px;margin:0 auto;padding:24px;line-height:1.5}}
h1{{font-size:2em}} label{{display:block;margin:12px 0 4px;font-weight:bold}}
input{{width:100%;padding:10px;font-size:16px;border:1px solid #000;border-radius:4px;box-sizing:border-box}}
button{{margin-top:16px;margin-right:8px;padding:12px 24px;font-size:17px;background:#000;color:#fff;border:none;border-radius:4px;cursor:pointer}}
#result{{margin-top:24px;padding:20px;border:2px solid #000;border-radius:8px;display:none}}
#result b{{font-size:2em}}
.bar{{height:14px;background:#000;margin:2px 0 8px}}
.note{{color:#333;font-size:.95em}} code{{background:#f2f2f2;padding:2px 5px}}
.safe{{border-color:#000}} .warn{{border-color:#000}}
table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #999;padding:6px 8px;text-align:left}}
</style>
</head>
<body>
<h1>&#128737;&#65039; PhishGuard — Phishing URL Detector</h1>
<p class="note">A 2nd-year B.Tech AI/ML project by Vikranth Reddy. A logistic regression model trained on 1,000 URLs (500 genuine, 500 phishing) reads 10 clues from any link — suspicious words, IP-address hosts, extra subdomains, hyphens, missing HTTPS and more — and returns a phishing-risk score. 5-fold CV: <b>accuracy = {acc:.1%}, AUC = {auc:.3f}</b> vs a 50.0% coin-flip baseline. (Trained on synthetic URLs, so treat the score as a classroom demo, not a security verdict.)</p>
<label>Paste a URL to check</label>
<input id="url" type="text" value="https://secure-login-verify.com/login/verify">
<button onclick="check()">Check This Link</button>
<button onclick="trySafe()">Try a safe one</button>
<div id="result"></div>
<p class="note">How it works: the URL is broken into 10 numbers (length, dots, hyphens, digits, &lsquo;@&rsquo;, IP host, subdomain count, suspicious-word count, HTTPS, path length). Each is standardised, multiplied by the model&apos;s learned weight, and passed through a sigmoid to give a phishing probability. The same weights run in this page and in the Python training script (<code>train.py</code>), so the browser result matches the trained model exactly.</p>
<p class="note">Try it: <code>https://secure-login-verify.com/login/verify</code> &rarr; phishing, about 99.9%. <code>http://185.23.44.19/login/verify</code> &rarr; phishing, about 99.6% (an IP address instead of a domain name is a classic red flag). <code>https://www.google.com/search?q=laptop</code> &rarr; phishing, about 0.1%.</p>
<p><a href="https://github.com/HVRGAMING2705/phishguard">View source on GitHub</a></p>
<script>
{JS_MODEL}
const LABELS = {{"url_len": "URL length", "num_dots": "Dots in URL", "num_hyphens": "Hyphens", "num_digits": "Digits", "has_at": "'@' in URL", "has_ip": "IP address as host", "num_subdomains": "Extra subdomains", "susp_words": "Suspicious words", "is_https": "Uses HTTPS", "path_len": "Path length"}};
function verdict(p) {{
  if (p >= 70) return "&#128680; LIKELY PHISHING";
  if (p >= 30) return "&#9888;&#65039; SUSPICIOUS — CHECK CAREFULLY";
  return "&#9989; LOOKS SAFE";
}}
function check() {{
  const url = document.getElementById("url").value.trim();
  const r = phishProb(url);
  const el = document.getElementById("result");
  el.style.display = "block";
  let html = "<b>" + verdict(r.prob) + " — " + r.prob.toFixed(1) + "% phishing risk</b><br><br>";
  html += "<div class=bar style='width:" + Math.min(100, r.prob).toFixed(1) + "%'></div>";
  const top = r.contrib.slice().sort((a, b) => Math.abs(b.c) - Math.abs(a.c)).slice(0, 5);
  html += "<p><b>Top reasons:</b></p><table><tr><th>Clue</th><th>Value</th><th>Pushes risk</th></tr>";
  top.forEach(t => {{
    html += "<tr><td>" + LABELS[t.name] + "</td><td>" + t.value + "</td><td>" + (t.c >= 0 ? "&#9650; up " : "&#9660; down ") + Math.abs(t.c).toFixed(2) + "</td></tr>";
  }});
  html += "</table><p class=note>Classroom demo trained on synthetic URLs — never enter passwords on a link this tool flags, and never treat a low score as a guarantee.</p>";
  el.innerHTML = html;
}}
function trySafe() {{ document.getElementById("url").value = "https://www.google.com/search?q=laptop"; check(); }}
</script>
</body>
</html>
"""
open("index.html", "w").write(index)
vercel = {
 "headers": [{"headers": [
   {"key": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains; preload"},
   {"key": "X-Content-Type-Options", "value": "nosniff"},
   {"key": "X-Frame-Options", "value": "SAMEORIGIN"},
   {"key": "Referrer-Policy", "value": "strict-origin-when-cross-origin"},
   {"key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()"},
   {"key": "Cross-Origin-Opener-Policy", "value": "same-origin"},
   {"key": "Access-Control-Allow-Origin", "value": f"https://{DOMAIN}"},
   {"key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'self'; frame-ancestors 'self'"}],
  "source": "/(.*)"}]}
open("vercel.json", "w").write(json.dumps(vercel, indent=1))
open("404.html", "w").write(f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Page Not Found — PhishGuard</title><style>body{{font-family:Arial,sans-serif;color:#000;max-width:640px;margin:60px auto;padding:24px}}</style></head><body><h1>404 — Page not found</h1><p>This page does not exist on PhishGuard.</p><p><a href="https://{DOMAIN}/">Back to PhishGuard</a></p></body></html>""")
open("robots.txt", "w").write(f"User-agent: *\nAllow: /\nSitemap: https://{DOMAIN}/sitemap.xml\n")
open("sitemap.xml", "w").write(f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://{DOMAIN}/</loc></url></urlset>
""")
open("README.md", "w").write(f"""# PhishGuard — Phishing URL Detector

A 2nd-year B.Tech AI/ML project by Vikranth Reddy (Woxsen University).

Logistic regression (C=1.0) on 10 standardized URL features (URL length, dots, hyphens, digits, '@' present, IP host, subdomain count, suspicious-word count, HTTPS flag, path length), trained on 1,000 synthetic URLs (500 legit / 500 phishing, seed 42).

- 5-fold CV accuracy: {acc:.1%}, AUC: {auc:.3f} (coin-flip baseline: {base:.1%})
- Live demo: https://{DOMAIN} (runs fully in the browser — no backend)
- `train.py` trains the model and writes `model.json`; `index.html` applies the same weights in JavaScript, including a per-feature reason breakdown.
""")
samples = json.load(open("parity_samples.json"))
parity = JS_MODEL + "\n" + "\n".join(
    f"console.log(JSON.stringify({{url: {json.dumps(s['url'])}, js: phishProb({json.dumps(s['url'])}).prob / 100, py: {json.dumps(s['prob'])}}}));"
    for s in samples)
open("parity.js", "w").write(parity)
print("site files written, acc", acc)
