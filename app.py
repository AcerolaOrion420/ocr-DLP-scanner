"""
Flask Web Application & REST API for DLP Scanner.
Provides:
- Web dashboard for file upload and real-time text scanning
- OCR integration via Tesseract
- Algorithmic and Regex DLP detection
- Report generation & Redacted text export
"""

import os
import io
import json
from flask import Flask, request, jsonify, render_template, send_file, Response
from werkzeug.utils import secure_filename
from dlp.parser import DocumentParser
from dlp.scanner import DLPScanner

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB max upload
app.config["UPLOAD_EXTENSIONS"] = [
    ".txt", ".csv", ".tsv", ".log", ".json", ".xml", ".md",
    ".docx", ".pdf",
    ".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp"
]

parser = DocumentParser()
scanner = DLPScanner()

# Preset sample test cases for user convenience
SAMPLE_CASES = {
    "leak_full": (
        "CONFIDENTIAL INTERNAL AUDIT REPORT\n"
        "Employee: Rajesh Kumar Sharma\n"
        "Department: Cloud Infrastructure Security\n\n"
        "Identity Credentials:\n"
        "- Aadhaar Card UID: 2345 6789 0124 (Verhoeff verified)\n"
        "- Permanent Account Number (PAN): ABCPS1234F\n"
        "- Sarathi Driving License: MH-02-20180012345\n"
        "- Passport Number: K1234567\n"
        "- Voter ID (EPIC): ABC1234567\n\n"
        "Corporate Billing & Expense Accounts:\n"
        "- Primary Visa Card: 4111 1111 1111 1111\n"
        "- Alternate RuPay Card: 6061 2345 6789 1234\n"
        "- Salary IFSC: HDFC0001234\n\n"
        "Contact Details:\n"
        "- Primary Mobile: +91 98765 43210\n"
        "- Official Email: rajesh.sharma@cyberdefense-corp.in\n\n"
        "Please secure this data immediately before distribution."
    ),
    "financial": (
        "Customer Transaction Summary:\n"
        "Account Holder: Sunita Patel\n"
        "Card Number (Mastercard): 5424 0000 0000 0015\n"
        "PAN Card: AAACP1234F\n"
        "Aadhaar Number: 3123 4567 8906\n"
        "Registered Phone: +91-91234-56789\n"
        "Email: sunita.patel@fintech-pay.org\n"
        "Bank Branch IFSC: SBIN0004567\n"
    ),
    "clean": (
        "SYSTEM HEALTH AND METRICS LOG - 2026-10-12\n"
        "Server: prod-worker-cluster-04\n"
        "Status: 200 OK\n"
        "Memory Usage: 42.4%\n"
        "CPU Load: 1.14 (1 min), 0.98 (5 min), 0.85 (15 min)\n"
        "Active connections: 1,420\n"
        "No PII or customer financial credentials found in standard server telemetry.\n"
        "All audit logs conform to security baseline standards."
    ),
}


@app.route("/")
def index():
    """Render the DLP Scanner Dashboard."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan_endpoint():
    """
    Scan endpoint accepting either:
    1. Multipart file upload ('file' field)
    2. JSON payload with 'text' field
    """
    force_ocr = request.form.get("force_ocr", "false").lower() in ("true", "1")

    # Case 1: File Upload
    if "file" in request.files:
        uploaded_file = request.files["file"]
        if uploaded_file.filename == "":
            return jsonify({"success": False, "error": "No file selected"}), 400

        filename = secure_filename(uploaded_file.filename) or "document.txt"
        file_bytes = uploaded_file.read()

        if len(file_bytes) == 0:
            return jsonify({"success": False, "error": "Uploaded file is empty"}), 400

        try:
            parsed_doc = parser.parse_file(file_bytes, filename, force_ocr=force_ocr)
            scan_result = scanner.scan(parsed_doc.raw_text)

            return jsonify({
                "success": True,
                "input_type": "file",
                "filename": parsed_doc.filename,
                "file_type": parsed_doc.file_type,
                "ocr_applied": parsed_doc.ocr_applied,
                "page_count": parsed_doc.page_count,
                "metadata": parsed_doc.metadata,
                "raw_text": parsed_doc.raw_text,
                "result": scan_result.to_dict(),
            })
        except Exception as e:
            app.logger.exception("File scan error")
            return jsonify({"success": False, "error": f"Scan processing failed: {str(e)}"}), 500

    # Case 2: JSON payload
    data = request.get_json(silent=True) or {}
    text = data.get("text") or request.form.get("text", "")

    if not text.strip():
        return jsonify({"success": False, "error": "No text or file provided for scan"}), 400

    try:
        scan_result = scanner.scan(text)
        return jsonify({
            "success": True,
            "input_type": "text",
            "filename": "Direct Text Input",
            "file_type": "Text Buffer",
            "ocr_applied": False,
            "page_count": 1,
            "metadata": {},
            "raw_text": text,
            "result": scan_result.to_dict(),
        })
    except Exception as e:
        app.logger.exception("Text scan error")
        return jsonify({"success": False, "error": f"Scan error: {str(e)}"}), 500


@app.route("/api/sample/<sample_type>", methods=["GET"])
def get_sample(sample_type):
    """Retrieve sample test text for quick testing."""
    if sample_type in SAMPLE_CASES:
        return jsonify({
            "success": True,
            "sample_type": sample_type,
            "text": SAMPLE_CASES[sample_type],
        })
    return jsonify({"success": False, "error": "Unknown sample type"}), 404


@app.route("/api/download/redacted", methods=["POST"])
def download_redacted():
    """Download redacted sanitized text as a .txt file."""
    text = request.form.get("text", "")
    filename = request.form.get("filename", "sanitized_document.txt")
    if not filename.endswith(".txt"):
        filename = os.path.splitext(filename)[0] + "_sanitized.txt"

    mem_file = io.BytesIO()
    mem_file.write(text.encode("utf-8"))
    mem_file.seek(0)

    return send_file(
        mem_file,
        as_attachment=True,
        download_name=filename,
        mimetype="text/plain; charset=utf-8",
    )


@app.route("/api/download/report", methods=["POST"])
def download_report():
    """Download full scan report as a JSON file."""
    report_json = request.form.get("report_json", "{}")
    mem_file = io.BytesIO()
    mem_file.write(report_json.encode("utf-8"))
    mem_file.seek(0)

    return send_file(
        mem_file,
        as_attachment=True,
        download_name="dlp_audit_report.json",
        mimetype="application/json",
    )


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint confirming OCR and algorithmic verifiers."""
    import shutil
    tesseract_available = shutil.which("tesseract") is not None
    pdftoppm_available = shutil.which("pdftoppm") is not None

    return jsonify({
        "status": "healthy",
        "ocr_available": tesseract_available,
        "pdf_ocr_available": pdftoppm_available,
        "supported_verifiers": [v.name for v in scanner.verifiers],
        "algorithmic_verifications": ["Verhoeff (Aadhaar)", "Luhn (Credit/Debit)"],
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
