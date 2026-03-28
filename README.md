# phishing-detection-ocr-ml
Hybrid OCR + Machine Learning system for real-time phishing detection
# 🛡️ Real-Time Phishing Detection System (OCR + Machine Learning)

## 🚀 Overview
This project implements a **real-time phishing detection system** that analyzes on-screen content using **OCR and Machine Learning**.

It extends a research paper approach by replacing rule-based detection with a **hybrid ML-driven model**, significantly improving accuracy and reducing false positives.

---

## 📌 Key Innovation
Unlike traditional keyword-based detection, this system combines:

- ✅ Deterministic verification layer (rule-based filtering)
- 🤖 Machine Learning classifier (TF-IDF + Logistic Regression)

This hybrid approach enables:
- Better generalization
- Reduced false positives
- Robust performance under OCR noise

---

## 🧱 System Pipeline
1. Capture screen (MSS)
2. Extract text using OCR (Tesseract)
3. Preprocess & normalize text
4. Apply verification scoring layer
5. Run ML classifier (Logistic Regression)
6. Output phishing probability
7. Display real-time alert

---

## ⚙️ Tech Stack
- Python
- Tesseract OCR
- MSS (screen capture)
- PyWinAuto / Tkinter
- Scikit-learn
- TF-IDF Vectorization
- Logistic Regression

---

## 🧠 Machine Learning Details
- Model: Logistic Regression
- Features: TF-IDF text representation
- Dataset: Auto-generated OCR logs (~1000+ samples)
- Accuracy: **97%**
- Precision: **97%**
- Recall: **96%**

---

## 📊 Results
The hybrid ML model significantly outperforms rule-based detection:

| Metric     | Rule-Based | ML Model |
|-----------|----------|---------|
| Accuracy  | ~70%     | 97%     |
| Precision | ~60%     | 97%     |
| Recall    | ~75%     | 96%     |

---


---

## ▶️ How to Run

```bash
pip install -r requirements.txt
python src/screen_monitor.py

⚠️ Limitations
Dependent on OCR quality
Cannot detect image-only phishing
Limited dataset diversity
🚀 Future Work
Transformer models (BERT)
Vision-based phishing detection
Multi-modal analysis
Real-time deployment as background service
🔬 Research Contribution

This project:

Replicates a research paper
Identifies real limitations
Proposes and implements a novel ML-based solution
Achieves significant performance improvements
👨‍💻 Author

Malaika Arif


---

# ✅ STEP 5 — requirements.txt

Create file:

``` id="c4q1z8"
pytesseract
opencv-python
mss
pywinauto
scikit-learn
pandas
numpy
joblib
