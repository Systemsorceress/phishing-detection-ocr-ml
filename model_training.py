import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

# --- Config ---
CSV_FILE = "screen_monitor_auto_labeled.csv"  # your auto-labeled dataset
OCR_COL = "ocr_text"
LABEL_COL = "label"
ML_MODEL_PATH = "ocr_ml_model.pkl"

# --- Load dataset with encoding handling ---
try:
    df = pd.read_csv(CSV_FILE, encoding='utf-8')
except UnicodeDecodeError:
    df = pd.read_csv(CSV_FILE, encoding='latin1')  # fallback for messy OCR files

df[OCR_COL] = df[OCR_COL].fillna("")

# --- Keep only confident labels (0 = safe, 1 = phishing) ---
df_ml = df[df[LABEL_COL].isin([0, 1])].copy()

# Combine window title + OCR text if available (optional)
df_ml['text_input'] = df_ml[OCR_COL]  # can add window titles if useful

X = df_ml['text_input']
y = df_ml[LABEL_COL]

# --- Split dataset ---
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# --- Vectorize text ---
vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1,2))
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# --- Train model ---
model = LogisticRegression(max_iter=1000)
model.fit(X_train_vec, y_train)

# --- Evaluate ---
y_pred = model.predict(X_test_vec)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))

# --- Save model ---
joblib.dump({'model': model, 'vectorizer': vectorizer}, ML_MODEL_PATH)
print(f"ML model saved to {ML_MODEL_PATH}")
