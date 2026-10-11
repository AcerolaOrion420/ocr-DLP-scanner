# 🛡️ Sentinel DLP Scanner & OCR Engine

> **High-Performance Data Loss Prevention (DLP) Dashboard with Optical Character Recognition (OCR) and Multi-Tier Algorithmic & Regex Verification.**

---

## 📌 Overview

**Sentinel DLP** is an enterprise-grade Data Loss Prevention application designed to scan text, office documents, PDFs, and scanned image records for sensitive Personally Identifiable Information (PII), national identity documents, and payment credentials.

It combines **Tesseract OCR (with automated image preprocessing)**, **Dihedral $D_5$ Verhoeff checksum validation**, **Luhn Mod-10 checksum validation**, and **Structural Regex parsing** to minimize false positives while actively catching leaks before data egress.

---

## 🚀 Key Features

### 1. Multi-Tier Detection Engine
* **Aadhaar Card (UIDAI)**:
  * **Algorithmic Validation**: Complete **Verhoeff algorithm** implementation based on Dihedral group $D_5$ permutation and multiplication matrices.
  * Formats: 12-digit standard, space-separated (`XXXX XXXX XXXX`), hyphenated, and continuous. Rejects numbers beginning with 0 or 1.
* **Credit & Debit Cards**:
  * **Algorithmic Validation**: **Luhn algorithm (Mod 10)** checksum verification.
  * **Card Brand / Network Identification**: Automatically flags **Visa**, **Mastercard**, **American Express**, **RuPay (India)**, **Discover**, **Diners Club**, **JCB**, and **Maestro**.
* **Permanent Account Number (PAN Card)**:
  * **Regex + Structural Validation**: 10-character standard CBDT specification (`[A-Z]{5}[0-9]{4}[A-Z]`).
  * **Entity Status Inspection**: Parses and labels the 4th character (Individual, Company, HUF, Firm/LLP, Trust, Government Agency, etc.).
* **Indian Driving License (DL)**:
  * **Regex + State Code Validation**: MoRTH Sarathi format (`SS-RR-YYYYNNNNNNN`) and legacy state formats verified against official Indian State and Union Territory codes (MH, DL, KA, TN, UP, GJ, etc.).
* **Indian Passport**:
  * Standard 8-character passport specification (`1 letter + 7 numeric digits`).
* **Voter ID (EPIC)**:
  * Election Commission of India 10-character EPIC format (`3 letters + 7 numeric digits`).
* **Bank IFSC & Contact PII**:
  * RBI IFSC branch codes, Indian mobile numbers (+91 / standard 10-digit), and RFC-compliant email addresses.

---

### 2. Multi-Format Ingestion & OCR Pipeline
* **Images**: `.png`, `.jpg`, `.jpeg`, `.bmp`, `.tiff`, `.webp` processed via **Tesseract OCR** with automated grayscale conversion, dynamic scaling, and contrast enhancement.
* **PDFs**: `.pdf` parsed natively via `pypdf`, with automatic fallback to raster OCR via `pdf2image` (pdftoppm) for scanned documents without a text layer.
* **Office Documents**: Microsoft Word `.docx` documents (paragraphs, nested table cells, headers).
* **Plain Text & Code**: `.txt`, `.csv`, `.log`, `.json`, `.xml`, `.md`, `.sql`, etc.

---

### 3. Cybersecurity Dashboard & Remediation
* **Leak Threat Scoring**: Real-time risk categorization (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `CLEAN`) and numerical risk score (0-100%).
* **Threat Audit Log**: Interactive findings table with verification method badges (⚡ Algorithmic vs 🔍 Regex), masked secrets, and context snippets.
* **Dual Document Viewer**:
  * **Threat Highlighted View**: Visually highlights sensitive leaks with colored badges.
  * **Sanitized / Scrubbed View**: Ready-to-share version where all sensitive secrets are masked.
  * **Raw Extracted Text View**: Inspect raw OCR output.
* **Export Actions**:
  * 📋 Copy Sanitized Text to clipboard with one click.
  * 💾 Download Sanitized Document (`.txt`).
  * 📊 Export Complete DLP Audit Report (`.json`).

---

## 📐 Architecture Diagram

```
                             [ User / Client ]
                                    │
               ┌────────────────────┴────────────────────┐
               │                                         │
        [ Direct Text ]                           [ File Upload ]
               │                          (.pdf, .docx, .png, .jpg, .txt)
               │                                         │
               │                              ┌──────────┴──────────┐
               │                              │  DocumentParser     │
               │                              │  - Native Parser    │
               │                              │  - Tesseract OCR    │
               │                              └──────────┬──────────┘
               │                                         │
               └────────────────────┬────────────────────┘
                                    │ (Raw Text Buffer)
                                    ▼
                         ┌──────────────────────┐
                         │      DLPScanner      │
                         └──────────┬───────────┘
                                    │
            ┌───────────────────────┴───────────────────────┐
            ▼                                               ▼
┌─────────────────────────┐                     ┌─────────────────────────┐
│  Algorithmic Verifiers  │                     │     Regex Verifiers     │
├─────────────────────────┤                     ├─────────────────────────┤
│ • Aadhaar (Verhoeff D5) │                     │ • PAN Card (+ Status)   │
│ • Cards (Luhn Mod-10)   │                     │ • Driving License (RTO) │
│   (Visa, RuPay, MC, etc)│                     │ • Passport / Voter ID   │
└───────────┬─────────────┘                     │ • IFSC / Phone / Email  │
            │                                   └───────────┬─────────────┘
            └───────────────────────┬───────────────────────┘
                                    │ (Overlap Resolution & Deduplication)
                                    ▼
                         ┌──────────────────────┐
                         │     ScanResult       │
                         │ - Risk Score (0-100) │
                         │ - Redacted Text      │
                         │ - Highlighted HTML   │
                         │ - Audit Findings     │
                         └──────────────────────┘
```

---

## 🛠️ Installation & Setup

### Prerequisites
Make sure **Python 3.10+**, **Tesseract OCR**, and **Poppler** are installed on your system.

#### On Ubuntu / Debian:
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv tesseract-ocr poppler-utils
```

#### On macOS (Homebrew):
```bash
brew install tesseract poppler python
```

---

### Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/AcerolaOrion420/ocr-DLP-scanner.git
   cd ocr-DLP-scanner
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**:
   ```bash
   python app.py
   ```
   The web dashboard will be accessible at: **`http://localhost:5000`**

---

## 🧪 Running Automated Tests

Run the full test suite with `pytest`:

```bash
pytest tests/ -v
```

All 39 unit and integration tests verify:
* Verhoeff multiplication and permutation algorithms
* Luhn check digit calculation and card issuer identification
* Aadhaar, Credit Card, PAN, DL, Passport, Voter ID verifiers
* Overlap resolution and precedence
* Document parsing and OCR image generation
* Flask REST endpoints and download handlers

---

## 🌐 REST API Reference

### 1. Scan Text or Document
* **Endpoint**: `POST /api/scan`
* **Content-Type**: `application/json` OR `multipart/form-data`

#### JSON Example:
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "Confidential PAN: ABCPS1234F and Aadhaar: 2345 6789 0124"}'
```

#### File Upload Example:
```bash
curl -X POST http://localhost:5000/api/scan \
  -F "file=@/path/to/document.pdf" \
  -F "force_ocr=false"
```

### 2. System Health & Verifier Status
* **Endpoint**: `GET /api/health`
```bash
curl http://localhost:5000/api/health
```

### 3. Load Quick Test Cases
* **Endpoint**: `GET /api/sample/<sample_type>`
  * Supported types: `leak_full`, `financial`, `clean`

---

## 📜 License
MIT License. Built for proactive data privacy, compliance auditing, and secure document exchange.
