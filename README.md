# PhishGuard — Phishing URL Detector

A 2nd-year B.Tech AI/ML project by Vikranth Reddy (Woxsen University).

Logistic regression (C=1.0) on 10 standardized URL features (URL length, dots, hyphens, digits, '@' present, IP host, subdomain count, suspicious-word count, HTTPS flag, path length), trained on 1,000 synthetic URLs (500 legit / 500 phishing, seed 42).

- 5-fold CV accuracy: 99.9%, AUC: 1.000 (coin-flip baseline: 50.0%)
- Live demo: https://phishguard.vercel.app (runs fully in the browser — no backend)
- `train.py` trains the model and writes `model.json`; `index.html` applies the same weights in JavaScript, including a per-feature reason breakdown.
