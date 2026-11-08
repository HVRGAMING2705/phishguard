import json, re, random
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_predict, StratifiedKFold
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report

SUSP_WORDS = ["login", "verify", "secure", "update", "account", "free", "bank",
              "password", "confirm", "suspend", "prize", "winner", "urgent",
              "unlock", "gift"]
FEATURES = ["url_len", "num_dots", "num_hyphens", "num_digits", "has_at",
            "has_ip", "num_subdomains", "susp_words", "is_https", "path_len"]

def extract(url):
    u = url.lower()
    is_https = 1 if u.startswith("https://") else 0
    rest = u.split("://", 1)[1] if "://" in u else u
    host = re.split(r"[/?#]", rest)[0]
    path = rest[len(host):]
    has_ip = 1 if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host) else 0
    parts = host.split(".")
    num_sub = max(0, len(parts) - 2) if not has_ip else 0
    susp = sum(u.count(w) for w in SUSP_WORDS)
    return [len(u), u.count("."), u.count("-"), sum(c.isdigit() for c in u),
            1 if "@" in u else 0, has_ip, num_sub, susp, is_https, len(path)]

LEGIT_DOMAINS = ["google.com", "youtube.com", "amazon.in", "github.com",
                 "woxsen.edu.in", "wikipedia.org", "irctc.co.in", "flipkart.com",
                 "linkedin.com", "microsoft.com", "stackoverflow.com",
                 "netflix.com", "paytm.com", "icicibank.com", "onlinesbi.sbi",
                 "nptel.ac.in", "coursera.org", "udemy.com", "zomato.com",
                 "swiggy.com", "reddit.com", "x.com", "instagram.com",
                 "drive.google.com", "mail.google.com", "en.wikipedia.org",
                 "docs.google.com", "canva.com", "spotify.com"]
LEGIT_PATHS = ["/login", "/account/settings", "/search?q=laptop", "/products/12345",
               "/watch?v=dQw4w9WgXcQ", "/about", "/help", "/checkout", "/profile",
               "/courses/python-basics", "/order/98765", "/settings/privacy",
               "/blog/how-to-learn-ai", "/r/learnprogramming", "/in/vikranth-reddy",
               "/home", "/dashboard", "/support/contact", "/offers/today-deals",
               "/learn/machine-learning", "/cart", "/notifications", "/explore"]
LEGIT_PREFIX = ["", "", "", "www.", "www.", "app.", "support.", "blog."]

PHISH_DOMAINS = ["secure-login-verify.com", "paypal-secure-update.net",
                 "free-gift-card-claim.xyz", "bank-account-verify-now.com",
                 "apple-id-locked.info", "amazon-prize-winner.club",
                 "verify-your-account-urgent.com", "unlock-your-account-now.net",
                 "login-secure-banking.com", "update-payment-info.org",
                 "google-drive-share-free.tk", "facebook-security-alert.net",
                 "netflix-account-suspended.com", "instagram-verify-now.xyz",
                 "sbi-online-secure-login.com", "flipkart-lucky-draw-winner.in",
                 "microsoft-account-recovery.live", "whatsapp-gift-claim.com",
                 "secure-paypal-confirmation.com", "free-iphone-winner-now.club"]
PHISH_PATHS = ["/login/verify", "/secure/update/account", "/free/prize/claim",
               "/account/suspended/unlock", "/verify-now", "/login?session=expired",
               "/update/payment-details", "/confirm/identity", "/gift/card/redeem",
               "/security/alert/verify", "/bank/login/secure", "/winner/claim-now",
               "/account/locked/reset", "/free/recharge/offer", "/verify/password",
               "/urgent/action-required", "/login/secure-verify", "/prize/claim/2026"]
PHISH_SUBS = ["login.secure.verify.", "account-update.", "secure.login.",
              "verify.account.", "payment.update.", "free.claim.",
              "support.secure.", "login.verify.secure."]
IPS = ["185.23.44.19", "103.45.67.89", "45.132.78.201", "91.234.56.78",
       "176.45.99.12", "203.0.113.44"]

rng = random.Random(42)
urls, y = [], []
for _ in range(500):
    d = rng.choice(LEGIT_DOMAINS)
    p = rng.choice(LEGIT_PREFIX) + d
    scheme = "https" if rng.random() < 0.97 else "http"
    urls.append(f"{scheme}://{p}{rng.choice(LEGIT_PATHS)}")
    y.append(0)
for _ in range(500):
    kind = rng.random()
    if kind < 0.15:
        urls.append(f"http://{rng.choice(IPS)}{rng.choice(PHISH_PATHS)}")
    elif kind < 0.30:
        urls.append(f"http://google.com@{rng.choice(PHISH_DOMAINS)}{rng.choice(PHISH_PATHS)}")
    elif kind < 0.45:
        urls.append(f"https://{rng.choice(PHISH_SUBS)}{rng.choice(PHISH_DOMAINS)}{rng.choice(PHISH_PATHS)}")
    else:
        scheme = "https" if rng.random() < 0.55 else "http"
        urls.append(f"{scheme}://{rng.choice(PHISH_DOMAINS)}{rng.choice(PHISH_PATHS)}")
    y.append(1)

X = np.array([extract(u) for u in urls], dtype=float)
y = np.array(y)
mu, sd = X.mean(axis=0), X.std(axis=0)
sd[sd == 0] = 1.0
Xs = (X - mu) / sd
model = LogisticRegression(C=1.0, max_iter=2000).fit(Xs, y)
skf = StratifiedKFold(5, shuffle=True, random_state=42)
pred_cv = cross_val_predict(LogisticRegression(C=1.0, max_iter=2000), Xs, y, cv=skf)
proba_cv = cross_val_predict(LogisticRegression(C=1.0, max_iter=2000), Xs, y,
                             cv=skf, method="predict_proba")[:, 1]
acc = float(accuracy_score(y, pred_cv))
auc = float(roc_auc_score(y, proba_cv))
base = float(max(np.bincount(y)) / len(y))
print(f"n={len(urls)} phish_rate={y.mean():.3f}")
print(f"CV accuracy={acc:.3f} AUC={auc:.3f} baseline={base:.3f}")
print(classification_report(y, pred_cv, target_names=["legit", "phishing"], digits=3))
print("feature means:", dict(zip(FEATURES, np.round(mu, 2).tolist())))
print("coef:", dict(zip(FEATURES, np.round(model.coef_[0], 3).tolist())))

mj = {"features": FEATURES, "mean": mu.tolist(), "scale": sd.tolist(),
      "coef": model.coef_[0].tolist(), "intercept": float(model.intercept_[0]),
      "susp_words": SUSP_WORDS,
      "metrics": {"cv_accuracy": acc, "auc": auc, "baseline_accuracy": base,
                  "n": len(urls), "phish_rate": float(y.mean())}}
with open("model.json", "w") as f:
    json.dump(mj, f, indent=1)

def py_prob(url):
    x = (np.array(extract(url), dtype=float) - mu) / sd
    z = float(model.intercept_[0] + x @ model.coef_[0])
    return 1 / (1 + np.exp(-z))

samples = [
    "https://www.google.com/search?q=laptop",
    "https://github.com/HVRGAMING2705/moodlens",
    "https://secure-login-verify.com/login/verify",
    "http://185.23.44.19/login/verify",
    "http://google.com@free-gift-card-claim.xyz/free/prize/claim",
    "https://login.secure.verify.paypal-secure-update.net/secure/update/account",
    "https://www.amazon.in/products/12345",
]
for s in samples:
    print(repr(s), "-> phishing", round(py_prob(s) * 100, 2), "%")
with open("parity_samples.json", "w") as f:
    json.dump([{"url": s, "prob": py_prob(s)} for s in samples], f, indent=1)
