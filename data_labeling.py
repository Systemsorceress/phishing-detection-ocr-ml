import pandas as pd
import re
import unicodedata
import difflib
from io import StringIO
import chardet

# --- Config ---
CSV_FILE = "screen_monitor_auto_labeled.csv"
OCR_COL = "ocr_text"
LABEL_COL = "label"

PHISHING_KEYWORDS = [
    "verify your account", "update password", "click here", "urgent action",
    "security alert", "account suspended", "login immediately", "Suspicious", "Bank Alert", "Account Locked",
    "confirm identity", "bank account", "credit card", "unusual activity", "spam", "security"
]

BRANDS = ["paypal", "bank", "microsoft", "google", "facebook", "amazon", "apple"]
SUSPICIOUS_URL_REGEX = r"(https?://[^\s]+)"

# --- Helper functions ---
def normalize(text):
    text = str(text).lower()
    text = unicodedata.normalize("NFKD", text)
    return re.sub(r"[^a-z0-9\s:/.-]", " ", text)

def detect_url(text):
    norm = normalize(text)
    urls = re.findall(SUSPICIOUS_URL_REGEX, norm)
    max_sim = 0
    for u in urls:
        for b in BRANDS:
            s = difflib.SequenceMatcher(None, u, b).ratio()
            if s > 0.6:
                max_sim = max(max_sim, s)
    return urls, max_sim

def score_phishing(text):
    norm = normalize(text)
    kw_count = sum(1 for kw in PHISHING_KEYWORDS if kw in norm)
    sensitive_words = ["password", "credit", "card", "ssn", "cvv", "security", "billing"]
    sensitive_score = sum(1 for w in sensitive_words if w in norm) / len(sensitive_words)
    _, url_score = detect_url(text)
    caps_ratio = sum(1 for c in text if c.isupper()) / max(1, len(text))
    score = kw_count * 0.4 + sensitive_score * 0.2 + url_score * 0.3 + caps_ratio * 0.1
    return min(score, 1.0)

# --- Detect CSV encoding ---
with open(CSV_FILE, "rb") as f:
    raw_data = f.read(100000)  # read first 100k bytes
    result = chardet.detect(raw_data)
    encoding = result["encoding"] or "utf-8"
    print(f"Detected encoding: {encoding}")

# --- Load CSV safely ---
with open(CSV_FILE, "rb") as f:
    text = f.read().decode(encoding, errors="replace")  # replace invalid bytes
df = pd.read_csv(StringIO(text))
df[OCR_COL] = df[OCR_COL].fillna("")

# --- Automatic labeling ---
labels = []
scores = []

for text in df[OCR_COL]:
    score = score_phishing(text)
    scores.append(score)
    
    if score >= 0.35:
        labels.append(1)
    elif score <= 0.1:
        labels.append(0)
    else:
        labels.append(-1)

df[LABEL_COL] = labels
df["phishing_score"] = scores

# --- Save labeled dataset ---
df.to_csv(CSV_FILE, index=False)
print(f"Automatically labeled dataset saved to {CSV_FILE}")

# --- Optional summary ---
print("Label counts:\n", df[LABEL_COL].value_counts())
print("Score stats:\n", df["phishing_score"].describe())
print("Uncertain samples: ", (df[LABEL_COL] == -1).sum())
