import os
import sys
import time
from flask import Flask, render_template, request, jsonify, send_file

# ---------------------------------------------------------
# FOOLPROOF PATH FIX
# ---------------------------------------------------------
# Dynamically resolve root (Go up one level from webapp to CTI)
CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------
# IMPORTS
# ---------------------------------------------------------
from scripts.inference.predict_cti import predict_cti, predict_multiple_cti
from utils.report_generator import generate_forensic_pdf

try:
    from scripts.realtime.realtime_cti import get_latest_cves
except ImportError:
    get_latest_cves = None

try:
    from scripts.realtime.hash_checker_live import check_hash_live
except ImportError:
    check_hash_live = None
app = Flask(__name__)

# ---------------------------------------------------------
# HOME & HEALTH
# ---------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/health")
def health():
    return jsonify({"status": "running"})

# ---------------------------------------------------------
# ANALYSIS ROUTES
# ---------------------------------------------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        text = data.get("text", "")
        if not text.strip():
            return jsonify({"error": "Empty input"}), 400
        result = predict_cti(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

@app.route("/analyze-multi", methods=["POST"])
def analyze_multi():
    try:
        data = request.get_json()
        text = data.get("text", "")
        if not text.strip():
            return jsonify({"error": "Empty input"}), 400

        results = predict_multiple_cti(text)
        if not results:
            results = [predict_cti(text)]

        total = len(results)
        high = sum(1 for r in results if r["prediction"] == "HIGH")
        ioc = sum(r["features"]["ioc_count"] for r in results)

        return jsonify({
            "total_samples": total,
            "high": high,
            "ioc": ioc,
            "results": results
        })
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

# ---------------------------------------------------------
# LIVE ENRICHMENT ROUTE
# ---------------------------------------------------------
@app.route("/check-hash", methods=["POST"])
def check_hash():
    try:
        data = request.get_json()
        file_hash = data.get("hash")
        if not file_hash:
            return jsonify({"error": "No hash provided"}), 400
            
        if check_hash_live:
            result = check_hash_live(file_hash)
            return jsonify(result)
        else:
            return jsonify({"error": "Hash checker module not found"}), 501
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------------------------------------------------
# DYNAMIC REPORTING ROUTES (NO CACHE & CUSTOM METADATA)
# ---------------------------------------------------------
@app.route("/generate-report", methods=["POST"])
def generate_report():
    try:
        data = request.get_json()
        text = data.get("text", "")
        
        # Extract the new metadata from the frontend (with defaults if empty)
        analyst_name = data.get("analyst_name", "SOC Analyst")
        purpose = data.get("purpose", "Automated Threat Triage")
        tlp = data.get("tlp", "AMBER")

        if not text.strip():
            return jsonify({"error": "Empty input"}), 400

        results = predict_multiple_cti(text)
        
        # Create a unique filename using a timestamp to defeat caching
        timestamp = int(time.time())
        filename = f"forensic_report_{timestamp}.pdf"
        
        output_dir = os.path.join(PROJECT_ROOT, "outputs")
        os.makedirs(output_dir, exist_ok=True)
        file_path = os.path.join(output_dir, filename)
        
        # Pass the custom metadata to the PDF generator
        generate_forensic_pdf(results, file_path, analyst_name, purpose, tlp)
        
        # Return the unique filename to the frontend
        return jsonify({"message": "Report generated", "filename": filename})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/download-report/<filename>")
def download_report(filename):
    # Serve the exact unique file requested by the frontend
    file_path = os.path.join(PROJECT_ROOT, "outputs", filename)
    if os.path.exists(file_path):
        response = send_file(file_path, as_attachment=True, mimetype='application/pdf')
        # Extra safeguard: Force headers to prevent any caching
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    else:
        return "Report not found. Generate it first.", 404

# ---------------------------------------------------------
# LIVE CVE FEED
# ---------------------------------------------------------
@app.route("/fetch-cves")
def fetch_cves():
    if get_latest_cves:
        return jsonify(get_latest_cves())
    return jsonify([])

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
