"""
screen_monitor_uia_fixed_ml.py
Improved Screen monitor + overlay + click logging with UI Automation (pywinauto) and OCR (Tesseract),
plus phishing detection, ML prediction, and popup warning.

ML predictions now trigger phishing alerts.
"""

import threading
import time
import csv
import os
from datetime import datetime
import re
import sys

import mss
from PIL import Image
import numpy as np
import cv2

# OCR may be optional
try:
    import pytesseract
    pytesseract_available = True
except Exception:
    pytesseract_available = False

# ML imports
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib  # to save/load trained models

# Allow easy debug toggle
DEBUG = True

# Windows-specific imports
try:
    import win32gui
    import win32process
    import win32con
    import win32com.client as win32com_client
    from pynput import mouse
    import tkinter as tk
    from pywinauto import Desktop
except Exception as e:
    if DEBUG:
        print("Windows-specific imports failed:", e)

# === CONFIG ===
CAPTURE_INTERVAL = 0.6
OCR_REGION_SIZE = 900
LOG_FILE = "screen_monitor_auto_labeled.csv"
OVERLAY_OFFSET = (16, 16)
MAX_OCR_CHARS = 1000
MIN_MEAN_CONF = 30  # minimum average confidence (0-100) from tesseract to accept OCR

EMAIL_CLIENTS = ["Gmail", "Outlook", "Yahoo Mail", "Thunderbird", "Mail"]
PHISHING_KEYWORDS = [
    "verify your account", "update password", "click here", "urgent action",
    "Unsual Transaction", "security alert", "account suspended",
    "login immediately", "Suspicious", "Bank Alert", "Account Locked",
    "confirm identity", "bank account", "credit card", "unusual activity",
    "verify identity", "reset password", "verify billing", "payment failed",
    "Update Required", "Patch", "Urgent"
]

# If Tesseract isn't in PATH, set full path here (uncomment and edit):
# pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# === Init log ===
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp_utc", "event", "x", "y", "active_window_title",
            "explorer_path", "uia_control_type", "uia_control_name",
            "ocr_text", "ocr_mean_conf", "ml_label"
        ])

# Shared state
state = {
    "mouse_x": 0,
    "mouse_y": 0,
    "last_click": None,
    "last_ocr": "",
    "active_window": "",
    "uia_control_type": "",
    "uia_control_name": "",
    "explorer_path": "",
    "last_phishing_alert": 0,
    "last_ocr_conf": 0,
    "running": True
}

# === Helpers ===
def get_foreground_window_title_and_hwnd():
    try:
        hwnd = win32gui.GetForegroundWindow()
        title = win32gui.GetWindowText(hwnd)
        return title, hwnd
    except Exception:
        return "", None

def try_get_explorer_path_from_hwnd(hwnd):
    try:
        if not hwnd:
            return ""
        shell = win32com_client.Dispatch("Shell.Application")
        windows = shell.Windows()
        for w in windows:
            try:
                if int(w.HWND) == int(hwnd):
                    doc = getattr(w, 'Document', None)
                    if doc is not None:
                        folder = getattr(doc, 'Folder', None)
                        if folder is not None:
                            selfobj = getattr(folder, 'Self', None)
                            if selfobj is not None:
                                path = getattr(selfobj, 'Path', None)
                                if path:
                                    return str(path)
            except Exception:
                continue
    except Exception:
        pass
    return ""

def capture_region_around(x, y, size):
    half = size // 2
    left = max(0, x - half)
    top = max(0, y - half)
    monitor = {"left": left, "top": top, "width": size, "height": size}
    with mss.mss() as sct:
        img = sct.grab(monitor)
        pil = Image.frombytes("RGB", img.size, img.rgb)
        return cv2.cvtColor(np.array(pil), cv2.COLOR_RGB2BGR)

def preprocess_for_ocr(bgr_img):
    gray = cv2.cvtColor(bgr_img, cv2.COLOR_BGR2GRAY)
    h, w = gray.shape[:2]
    scale = 2.0 if max(w, h) < 1500 else 1.5
    gray = cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_CUBIC)
    gray = cv2.medianBlur(gray, 3)
    try:
        th = cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY, 15, 8
        )
    except Exception:
        _, th = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    return th

def ocr_image_bgr(bgr_img):
    if not pytesseract_available:
        if DEBUG:
            print("pytesseract not available. Install pytesseract and Tesseract OCR.")
        return "", 0
    try:
        pre = preprocess_for_ocr(bgr_img)
        pil = Image.fromarray(pre)
        custom_config = "--oem 3 --psm 6"
        data = pytesseract.image_to_data(pil, output_type=pytesseract.Output.DICT, config=custom_config)
        texts = []
        confs = []
        n_boxes = len(data.get('text', []))
        for i in range(n_boxes):
            txt = data['text'][i].strip()
            conf = -1
            try:
                conf = int(data['conf'][i])
            except Exception:
                try:
                    conf = float(data['conf'][i])
                except Exception:
                    conf = -1
            if txt:
                texts.append(txt)
            if conf >= 0:
                confs.append(conf)
        if texts:
            mean_conf = int(sum(confs) / len(confs)) if confs else 0
            text = " ".join(texts)
            return text.strip(), mean_conf
        else:
            return "", 0
    except Exception as e:
        if DEBUG:
            print("OCR error:", e)
        return "", 0

def get_uia_element_at_point(x, y):
    try:
        d = Desktop(backend="uia", timeout=0.5)
        elem = d.from_point(x, y)
        info = getattr(elem, "element_info", None)
        if info:
            ctype = getattr(info, "control_type", "") or getattr(info, "control_type_name", "") or str(type(elem))
            name = getattr(info, "name", "") or getattr(elem, "window_text", "") or ""
            return str(ctype), str(name)
        else:
            ctype = getattr(elem, "control_type", "")
            name = getattr(elem, "window_text", "")
            return str(ctype), str(name)
    except Exception:
        return "", ""

# === PHISHING DETECTION ===
def is_email_client(title: str) -> bool:
    if not title:
        return False
    return any(app.lower() in title.lower() for app in EMAIL_CLIENTS)

def normalize_text_for_match(text: str) -> str:
    t = re.sub(r"[^0-9a-zA-Z\s]", " ", text.lower())
    t = re.sub(r"\s+", " ", t).strip()
    return t

def is_phishing_text(text: str) -> bool:
    if not text:
        return False
    text_norm = normalize_text_for_match(text)
    for kw in PHISHING_KEYWORDS:
        if kw in text_norm:
            if DEBUG:
                print("Phishing exact match:", kw)
            return True
    return False

def show_phishing_popup():
    try:
        def popup():
            win = tk.Toplevel()
            win.attributes("-topmost", True)
            win.title("⚠️ Phishing Alert")
            tk.Label(
                win, text="This email looks suspicious!",
                bg="#b22222", fg="white",
                font=("Segoe UI", 12, "bold"),
                padx=20, pady=10
            ).pack()
            tk.Label(
                win,
                text="Be careful before clicking any links. Consider contacting IT or the sender.",
                font=("Segoe UI", 10),
                bg="white",
                fg="black",
                padx=10,
                pady=5
            ).pack()
            tk.Button(win, text="OK", command=win.destroy,
                      bg="#333", fg="white").pack(pady=5)
        if root:
            root.after(0, popup)
    except Exception as e:
        print("Popup error:", e)

# === ML MODEL ===
ML_MODEL_PATH = "ocr_ml_model.pkl"
ml_model = None
ml_vectorizer = None

if os.path.exists(ML_MODEL_PATH):
    try:
        ml_model_data = joblib.load(ML_MODEL_PATH)
        ml_vectorizer = ml_model_data['vectorizer']
        ml_model = ml_model_data['model']
        if DEBUG:
            print("ML model loaded successfully.")
    except Exception as e:
        print("Failed to load ML model:", e)
        ml_model = None
        ml_vectorizer = None

def ml_predict(ocr_text: str, window_title: str) -> str:
    """Return ML label (e.g., 'phishing' or 'safe'), normalized lowercase."""
    if not ml_model or not ml_vectorizer or not ocr_text:
        return ""
    try:
        text_input = (window_title or "") + " " + ocr_text
        X = ml_vectorizer.transform([text_input])
        pred = ml_model.predict(X)
        return str(pred[0]).strip().lower()
    except Exception as e:
        if DEBUG:
            print("ML prediction error:", e)
        return ""

# === Mouse listener ===
def on_move(x, y):
    state["mouse_x"] = int(x)
    state["mouse_y"] = int(y)

def on_click(x, y, button, pressed):
    if pressed:
        title, hwnd = get_foreground_window_title_and_hwnd()
        explorer_path = try_get_explorer_path_from_hwnd(hwnd)
        uia_type, uia_name = get_uia_element_at_point(int(x), int(y))
        ocr_text = state["last_ocr"]
        ocr_conf = state.get("last_ocr_conf", 0)
        ml_label = ml_predict(ocr_text, title)
        timestamp = datetime.utcnow().isoformat()

        with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp, "click", int(x), int(y), title,
                explorer_path, uia_type, uia_name,
                ocr_text, ocr_conf, ml_label
            ])

        if DEBUG:
            print(f"[{timestamp}] click @({x},{y}) win='{title}' "
                  f"uia='{uia_type}' name='{uia_name}' ml={ml_label}")

mouse_listener = mouse.Listener(on_move=on_move, on_click=on_click)
mouse_listener.start()

# === OCR + UIA + PHISHING + ML Loop ===
def ocr_and_uia_loop():
    while state.get("running", True):
        try:
            mx = state["mouse_x"]
            my = state["mouse_y"]
            title, hwnd = get_foreground_window_title_and_hwnd()
            explorer_path = try_get_explorer_path_from_hwnd(hwnd)
            uia_type, uia_name = get_uia_element_at_point(mx, my)

            # Perform OCR
            ocr_text = ""
            ocr_conf = 0
            if pytesseract_available:
                img = capture_region_around(mx, my, OCR_REGION_SIZE)
                rawtext, conf = ocr_image_bgr(img)

                if rawtext and conf >= MIN_MEAN_CONF:
                    ocr_text = " ".join(rawtext.split())[:MAX_OCR_CHARS]
                    ocr_conf = conf
                else:
                    if DEBUG and rawtext:
                        print(f"OCR ignored (low conf {conf})")
                    ocr_text = ""
                    ocr_conf = conf

            # ML prediction
            ml_label = ml_predict(ocr_text, title)

            # === Combined PHISHING DETECTION (Keyword + ML) ===
            now = time.time()
            combined_text = (title or "") + "\n" + (ocr_text or "")
            is_email = is_email_client(title) or "mail" in title.lower()

            keyword_flag = is_phishing_text(combined_text)
            ml_is_phish = ml_label in ["phishing", "phish"]

            if is_email and combined_text and (now - state["last_phishing_alert"] > 15):
                if keyword_flag or ml_is_phish:
                    state["last_phishing_alert"] = now
                    show_phishing_popup()

                    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerow([
                            datetime.utcnow().isoformat(),
                            "phishing_alert",
                            mx, my, title,
                            explorer_path, uia_type, uia_name,
                            combined_text, ocr_conf, ml_label
                        ])

            # Update state
            state.update({
                "last_ocr": ocr_text,
                "last_ocr_conf": ocr_conf,
                "active_window": title,
                "uia_control_type": uia_type,
                "uia_control_name": uia_name,
                "explorer_path": explorer_path
            })

            # Log snapshot
            timestamp = datetime.utcnow().isoformat()
            with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp, "snapshot", mx, my, title,
                    explorer_path, uia_type, uia_name,
                    ocr_text, ocr_conf, ml_label
                ])

            time.sleep(CAPTURE_INTERVAL)

        except Exception as e:
            if DEBUG:
                print("OCR/UIA loop error:", e)
            time.sleep(0.8)

ocr_thread = threading.Thread(target=ocr_and_uia_loop, daemon=True)
ocr_thread.start()

# === Overlay ===
root = None

try:
    root = tk.Tk()
    root.attributes("-topmost", True)
    root.overrideredirect(True)
    root.attributes("-alpha", 0.92)
    label = tk.Label(
        root,
        text="Initializing...",
        font=("Segoe UI", 5),
        bg="#222222",
        fg="#FFFFFF",
        padx=4,
        pady=2,
        justify="left",
        anchor="w",
        bd=1,
        relief="solid",
        wraplength=260
    )
    label.pack()

    def build_overlay_text():
        win = state["active_window"] or ""
        explorer = state.get("explorer_path", "")
        uia_t = state.get("uia_control_type", "")
        uia_n = state.get("uia_control_name", "")
        ocr = state.get("last_ocr", "")
        conf = state.get("last_ocr_conf", 0)
        ml = ml_predict(ocr, win)
        lines = []
        if win:
            lines.append(f"Win: {win}")
        if explorer:
            lines.append(f"Folder: {explorer}")
        if uia_t or uia_n:
            lines.append(f"Under cursor: {(uia_t + ' — ' + uia_n).strip()}")
        if ocr:
            lines.append(f"OCR({conf}%): {ocr[:180]}")
        if ml:
            lines.append(f"ML: {ml}")
        if not lines:
            lines = ["No data"]
        return "\n".join(lines)

    def update_overlay():
        try:
            mx = state["mouse_x"]
            my = state["mouse_y"]
            text = build_overlay_text()
            label.configure(text=text)
            x = mx + OVERLAY_OFFSET[0]
            y = my + OVERLAY_OFFSET[1]
            screen_w = root.winfo_screenwidth()
            screen_h = root.winfo_screenheight()
            w = label.winfo_reqwidth()
            h = label.winfo_reqheight()
            if x + w > screen_w:
                x = mx - w - OVERLAY_OFFSET[0]
            if y + h > screen_h:
                y = my - h - OVERLAY_OFFSET[1]
            root.geometry(f"+{x}+{y}")
        except Exception:
            pass
        root.after(180, update_overlay)

    root.after(500, update_overlay)

except Exception as e:
    print("Overlay/init error:", e)
    root = None

# === Start / Clean shutdown ===
try:
    print("Screen monitor (UIA+OCR+ML+Phishing) running. Log:", LOG_FILE)
    if root:
        root.mainloop()
    else:
        while True:
            time.sleep(1)
except KeyboardInterrupt:
    print("Stopping...")
    state["running"] = False
    try:
        mouse_listener.stop()
    except Exception:
        pass
    sys.exit(0)
except Exception as e:
    print("Overlay/main loop error:", e)
    state["running"] = False
    try:
        mouse_listener.stop()
    except Exception:
        pass
    sys.exit(1)
