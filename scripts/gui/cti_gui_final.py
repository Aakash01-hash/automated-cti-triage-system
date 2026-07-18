import sys
import os
import re
import threading
import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime

# ---------------------------------------------------------
# FOOLPROOF PATH FIX
# ---------------------------------------------------------
# Dynamically resolve root
CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------
# LOCAL IMPORTS
# ---------------------------------------------------------
from scripts.inference.ip_checker import check_ips
from scripts.inference.predict_cti import predict_cti
from scripts.realtime.realtime_cti import get_latest_cves
from scripts.realtime.ip_checker_live import check_ip_live
from scripts.realtime.hash_checker_live import check_hash_live
from utils.report_generator import generate_forensic_pdf

# ---------------------------------------------------------
# GLOBAL STATE
# ---------------------------------------------------------
last_result = None

# ================= TEXT SPLIT =================
def split_cti_samples(text):
    samples = re.split(r'\n\s*\n', text)
    return [s.strip() for s in samples if len(s.strip()) > 30]

# ================= EXPLANATION =================
def generate_explanation(features, prediction, indicators):
    explanation = []
    if prediction == "LOW":
        explanation.append("No strong threat indicators detected")
        return explanation
    if features.get("attack_related", 0):
        explanation.append("Suspicious attack behavior detected")
    if indicators.get('cves'):
        explanation.append(f"CVEs found: {', '.join(indicators['cves'])}")
    if indicators.get('hashes'):
        explanation.append(f"Hashes found: {len(indicators['hashes'])}")
    if features.get("keyword_score", 0) > 5:
        explanation.append("High threat score calculated")
    return explanation

# ================= ANALYZE =================
def analyze_text():
    global last_result
    text = input_text.get("1.0", tk.END).strip()
    if not text: 
        return

    samples = split_cti_samples(text)
    output_text.delete("1.0", tk.END)

    for idx, sample in enumerate(samples):
        result = predict_cti(sample)
        features = result.get("features", {})
        indicators = result.get("indicators", {})
        prediction = result.get("prediction", "UNKNOWN")
        explanation = result.get("explanation") or generate_explanation(features, prediction, indicators)
        ip_results = check_ips(sample)

        # Store for reporting
        last_result = {
            "text": sample,
            "prediction": prediction,
            "ml_prediction": result.get("ml_prediction", prediction),
            "confidence": result.get("confidence"),
            "probabilities": result.get("probabilities", {}),
            "features": features,
            "explanation": explanation,
            "indicators": indicators,
            "entities": result.get("entities", {}),
            "forensic": result.get("forensic", {}),
            "ips_local": ip_results # Needed for the old TXT report
        }

        # -------- OUTPUT TO GUI --------
        output_text.insert(tk.END, f"\n===== SAMPLE {idx+1} =====\n")
        tag = "high" if prediction == "HIGH" else "medium" if prediction == "MEDIUM" else "low"
        output_text.insert(tk.END, f"Prediction: {prediction}\n\n", tag)
        
        for e in explanation:
            output_text.insert(tk.END, f"- {e}\n")

        if indicators.get('files'):
            output_text.insert(tk.END, "\nFile Artifacts:\n")
            for f in indicators['files']:
                output_text.insert(tk.END, f"- {f}\n")

        # THREADING: IP FETCH
        output_text.insert(tk.END, "\nIP Analysis:\n")
        if ip_results:
            for ip, status in ip_results:
                output_text.insert(tk.END, f"- {ip} ({status})\n")
                threading.Thread(target=fetch_live_ip_data, args=(ip,), daemon=True).start()
        else:
            output_text.insert(tk.END, "No IPs found\n")

        # THREADING: HASH FETCH
        if indicators.get('hashes'):
            output_text.insert(tk.END, "\nHash Reputation (VirusTotal):\n")
            for h in indicators['hashes']:
                output_text.insert(tk.END, f"- {h}\n")
                threading.Thread(target=fetch_live_hash_data, args=(h,), daemon=True).start()

# ---------------- THREAD CALLBACKS ----------------
def fetch_live_ip_data(ip):
    live_data = check_ip_live(ip)
    root.after(0, update_gui_with_ip_data, ip, live_data)

def update_gui_with_ip_data(ip, live_data):
    if "error" not in live_data:
        res = f"   [Live] {ip} -> Abuse: {live_data['abuse_score']}% | {live_data['country']} | {live_data['isp']}\n"
    else:
        res = f"   [Live] {ip} -> ⚠️ Check failed ({live_data['error']})\n"
    output_text.insert(tk.END, res)

def fetch_live_hash_data(file_hash):
    live_data = check_hash_live(file_hash)
    root.after(0, update_gui_with_hash_data, file_hash, live_data)

def update_gui_with_hash_data(file_hash, live_data):
    short_hash = file_hash[:8] + "..."
    if live_data.get("found"):
        res = f"   [Live VT] {short_hash} -> 🚨 {live_data['malicious']}/{live_data['total']} Malicious | Family: {live_data['family']}\n"
    else:
        res = f"   [Live VT] {short_hash} -> 🟢 {live_data.get('error', 'Clean')}\n"
    output_text.insert(tk.END, res)
    output_text.see(tk.END)

# ---------------- LIVE CVE FEED ----------------
def fetch_live_cves():
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, "Fetching live CVEs... please wait.\n")
    root.update()
    
    cves = get_latest_cves()
    output_text.delete("1.0", tk.END)
    
    if not cves:
        output_text.insert(tk.END, "❌ Unable to fetch CVEs\n")
        return

    output_text.insert(tk.END, "🔥 Latest CVEs (Live):\n\n")
    for c in cves:
        output_text.insert(tk.END, f"{c['cve_id']} | {c['severity']}\n{c['description']}\n{'-'*50}\n")

# ---------------- REPORTING ----------------
def generate_report():
    """Generates the basic TXT report"""
    if not last_result:
        output_text.insert(tk.END, "\n❌ No data to generate report. Analyze first.\n")
        return

    out_dir = os.path.join(PROJECT_ROOT, "outputs")
    os.makedirs(out_dir, exist_ok=True)
    filename = os.path.join(out_dir, f"cti_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=== CTI ANALYSIS REPORT ===\n\n")
        f.write("Input Text:\n" + last_result["text"] + "\n\n")
        f.write(f"Prediction: {last_result['prediction']}\n\n")
        f.write("Explanation:\n")
        for e in last_result["explanation"]:
            f.write(f"- {e}\n")
        f.write("\nIP Analysis:\n")
        for ip, status in last_result["ips_local"]:
            f.write(f"- {ip}: {status}\n")

    output_text.insert(tk.END, f"\n\n✅ TXT Report saved: {filename}\n")

def generate_pdf_report():
    """Generates the Universal Forensic PDF using ReportLab"""
    if not last_result:
        output_text.insert(tk.END, "\n❌ No data to generate report. Analyze first.\n")
        return

    out_dir = os.path.join(PROJECT_ROOT, "outputs")
    os.makedirs(out_dir, exist_ok=True)
    filename = os.path.join(out_dir, f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    
    try:
        output_text.insert(tk.END, "\n⏳ Generating Forensic PDF (Fetching Live APIs...)\n")
        root.update() # Force UI to show loading text
        
        # We pass last_result as a list to match the WebApp's expected format
        generate_forensic_pdf([last_result], filename)
        
        output_text.insert(tk.END, f"\n📄 PDF Report successfully saved: {filename}\n")
    except Exception as e:
        output_text.insert(tk.END, f"\n❌ Error generating PDF: {str(e)}\n")

# ---------------- GUI SETUP ----------------
root = tk.Tk()
root.title("CTI SOC Triage System")
root.geometry("800x700")

title_label = tk.Label(root, text="DFIR Threat Intelligence Analyzer", font=("Arial", 16, "bold"))
title_label.pack(pady=10)

input_text = scrolledtext.ScrolledText(root, height=10)
input_text.pack(padx=10, pady=10, fill=tk.BOTH)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=5)
tk.Button(btn_frame, text="Analyze Evidence", command=analyze_text, width=15, bg="lightblue").grid(row=0, column=0, padx=5)
tk.Button(btn_frame, text="Fetch Live CVEs", command=fetch_live_cves, width=15).grid(row=0, column=1, padx=5)
tk.Button(btn_frame, text="Generate TXT", command=generate_report, width=15).grid(row=0, column=2, padx=5)
tk.Button(btn_frame, text="Generate PDF", command=generate_pdf_report, width=15, bg="#d4eaf7").grid(row=0, column=3, padx=5)

output_text = scrolledtext.ScrolledText(root, height=18, bg="#030914", fg="#e2e8f0")
output_text.pack(padx=10, pady=10, fill=tk.BOTH)

output_text.tag_config("high", foreground="#ff3366", font=("Arial", 10, "bold"))
output_text.tag_config("medium", foreground="#ffaa00", font=("Arial", 10, "bold"))
output_text.tag_config("low", foreground="#00ff88", font=("Arial", 10, "bold"))

root.mainloop()
