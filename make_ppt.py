from pptx import Presentation
from pptx.util import Inches, Pt
import sys
DOMAIN = sys.argv[1] if len(sys.argv) > 1 else "phishguard.vercel.app"
prs = Presentation(); prs.slide_width = Inches(13.33); prs.slide_height = Inches(7.5)
def add(i, title, lines):
    s = prs.slides.add_slide(prs.slide_layouts[1])
    s.shapes.title.text = title
    tf = s.placeholders[1].text_frame; tf.word_wrap = True
    for j, ln in enumerate(lines):
        p = tf.paragraphs[0] if j == 0 else tf.add_paragraph()
        p.text = ln; p.font.size = Pt(20); p.space_after = Pt(10)
add(0, "PhishGuard — Phishing URL Detector", ["An AI/ML project by Vikranth Reddy", "B.Tech CSE (AI & ML), 2nd Year — Woxsen University", "A model that reads any link and tells you whether it is a phishing trap — before you click it"])
add(1, "The Problem", ["Phishing links are the most common way accounts get stolen — fake bank, delivery and prize pages", "The links look almost real: a trusted name, a few extra words, a login page that steals your password", "Most people cannot tell a real link from a fake one by looking at it", "An automatic link checker gives a fast risk verdict before anyone types a password"])
add(2, "The Solution — PhishGuard", ["Paste any URL into the browser demo", "The model returns a phishing-risk percentage plus the exact reasons it flagged", "Top reasons shown: suspicious words, IP-address host, extra subdomains, missing HTTPS", "Runs fully in the browser — no backend, no waiting, no data sent anywhere"])
add(3, "Tech Stack", ["Python + scikit-learn: dataset and model training", "Logistic regression (C = 1.0) on 10 standardised URL features", "HTML, CSS and vanilla JavaScript for the interactive demo", "GitHub for source control, Vercel for free hosting"])
add(4, "Architecture", ["Dataset: 1,000 synthetic URLs — 500 genuine, 500 phishing (seed 42)", "URL -> 10 features (length, dots, hyphens, digits, '@', IP host, subdomains, suspicious words, HTTPS, path length) -> standardise -> logistic regression -> sigmoid -> model.json", "model.json ships with the site; JavaScript applies the same formula and shows per-feature contributions", "Training script: train.py; site generator: gen_site.py"])
add(5, "Live Demo", ["Try it: paste a link and press Check This Link", "Phishing example: https://secure-login-verify.com/login/verify -> phishing, about 99.9%", "IP-host example: http://185.23.44.19/login/verify -> phishing, about 99.6%", f"Demo: https://{DOMAIN}"])
add(6, "Results", ["5-fold cross-validation accuracy: 99.9%, AUC: 1.000", "Baseline (coin flip on a balanced set): 50.0% accuracy — about a 2x lift", "Strongest signals: suspicious-word count and URL length push risk up; HTTPS pulls it down", "Browser demo matches Python probabilities exactly on all test samples (diff < 1e-14)"])
add(7, "Future Scope", ["Train on a real-world labelled URL dataset (e.g. PhishTank) instead of synthetic URLs", "Add more features: domain age, SSL certificate validity, page-content checks", "Build a browser extension that warns before a phishing page loads", "Add a URL shortener expander so shortened links can be checked too"])
add(8, "Thank You", ["PhishGuard — Phishing URL Detector", "Vikranth Reddy, B.Tech CSE (AI & ML), Woxsen University", "Source: github.com/HVRGAMING2705/phishguard", "Questions welcome!"])
prs.save("/home/hatch/workspace/goals/daily-ai-ml-project-factory/files/AIML_PhishGuard_2026-11-08.pptx")
print("slides:", len(prs.slides._sldIdLst))
