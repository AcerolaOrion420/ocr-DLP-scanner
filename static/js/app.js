/**
 * Sentinel DLP Scanner - Frontend Controller
 * Handles drag-and-drop ingestion, OCR & text scanning,
 * threat filtering, dual document inspection, and report export.
 */

document.addEventListener("DOMContentLoaded", () => {
    // State
    let currentScanData = null;
    let selectedFile = null;
    let activeFindingsFilter = "all";

    // DOM Elements - Navigation & Tabs
    const tabButtons = document.querySelectorAll(".tab-btn");
    const tabContents = document.querySelectorAll(".tab-content");

    // Ingestion Elements
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("fileInput");
    const selectedFilePill = document.getElementById("selectedFilePill");
    const selectedFileName = document.getElementById("selectedFileName");
    const selectedFileSize = document.getElementById("selectedFileSize");
    const removeFileBtn = document.getElementById("removeFileBtn");
    const forceOcrCheckbox = document.getElementById("forceOcrCheckbox");
    const scanFileBtn = document.getElementById("scanFileBtn");
    const fileBtnSpinner = document.getElementById("fileBtnSpinner");

    const rawTextInput = document.getElementById("rawTextInput");
    const charCount = document.getElementById("charCount");
    const clearTextBtn = document.getElementById("clearTextBtn");
    const scanTextBtn = document.getElementById("scanTextBtn");
    const textBtnSpinner = document.getElementById("textBtnSpinner");

    const presetCards = document.querySelectorAll(".preset-card");

    // Scanning Loader
    const scanningLoader = document.getElementById("scanningLoader");
    const loaderStatusMsg = document.getElementById("loaderStatusMsg");

    // Results Elements
    const resultsSection = document.getElementById("resultsSection");
    const riskBanner = document.getElementById("riskBanner");
    const riskBannerIcon = document.getElementById("riskBannerIcon");
    const riskBannerTitle = document.getElementById("riskBannerTitle");
    const riskScoreBadge = document.getElementById("riskScoreBadge");
    const riskBannerMsg = document.getElementById("riskBannerMsg");

    const totalViolationsCount = document.getElementById("totalViolationsCount");
    const algoValidatedCount = document.getElementById("algoValidatedCount");
    const criticalHighCount = document.getElementById("criticalHighCount");
    const ingestionModeText = document.getElementById("ingestionModeText");
    const ingestionMetaFooter = document.getElementById("ingestionMetaFooter");

    // Findings Table & Filters
    const findingsTableBody = document.getElementById("findingsTableBody");
    const emptyFindingsMessage = document.getElementById("emptyFindingsMessage");
    const filterPills = document.querySelectorAll(".filter-pill");
    const filterAllCount = document.getElementById("filterAllCount");
    const filterAlgoCount = document.getElementById("filterAlgoCount");
    const filterCritCount = document.getElementById("filterCritCount");
    const filterHighCount = document.getElementById("filterHighCount");

    // Document Viewer
    const viewerTabBtns = document.querySelectorAll(".viewer-tab-btn");
    const viewerPanes = document.querySelectorAll(".viewer-pane");
    const highlightedHtmlContent = document.getElementById("highlightedHtmlContent");
    const redactedTextContent = document.getElementById("redactedTextContent");
    const rawTextContent = document.getElementById("rawTextContent");

    // Actions
    const copyRedactedBtn = document.getElementById("copyRedactedBtn");
    const downloadRedactedBtn = document.getElementById("downloadRedactedBtn");
    const downloadReportBtn = document.getElementById("downloadReportBtn");
    const toast = document.getElementById("toast");

    // -------------------------------------------------------------
    // Tab Switching
    // -------------------------------------------------------------
    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            tabButtons.forEach(b => b.classList.remove("active"));
            tabContents.forEach(c => c.classList.remove("active"));

            btn.classList.add("active");
            const targetId = btn.getAttribute("data-tab");
            document.getElementById(targetId).classList.add("active");
        });
    });

    // -------------------------------------------------------------
    // File Ingestion & Drag and Drop
    // -------------------------------------------------------------
    ["dragenter", "dragover"].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add("dragover");
        });
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove("dragover");
        });
    });

    dropzone.addEventListener("drop", (e) => {
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            handleFileSelect(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener("change", (e) => {
        if (e.target.files && e.target.files.length > 0) {
            handleFileSelect(e.target.files[0]);
        }
    });

    function handleFileSelect(file) {
        selectedFile = file;
        selectedFileName.textContent = file.name;
        selectedFileSize.textContent = formatBytes(file.size);
        selectedFilePill.style.display = "inline-flex";
        scanFileBtn.disabled = false;
    }

    removeFileBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        selectedFile = null;
        fileInput.value = "";
        selectedFilePill.style.display = "none";
        scanFileBtn.disabled = true;
    });

    function formatBytes(bytes) {
        if (bytes === 0) return "0 Bytes";
        const k = 1024;
        const sizes = ["Bytes", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
    }

    // -------------------------------------------------------------
    // Textarea Controls
    // -------------------------------------------------------------
    rawTextInput.addEventListener("input", () => {
        charCount.textContent = `${rawTextInput.value.length} characters`;
    });

    clearTextBtn.addEventListener("click", () => {
        rawTextInput.value = "";
        charCount.textContent = "0 characters";
    });

    // -------------------------------------------------------------
    // Presets
    // -------------------------------------------------------------
    presetCards.forEach(card => {
        card.addEventListener("click", async () => {
            const presetType = card.getAttribute("data-preset");
            try {
                const res = await fetch(`/api/sample/${presetType}`);
                const data = await res.json();
                if (data.success) {
                    rawTextInput.value = data.text;
                    charCount.textContent = `${data.text.length} characters`;

                    // Switch to text tab and trigger scan automatically
                    tabButtons.forEach(b => b.classList.remove("active"));
                    tabContents.forEach(c => c.classList.remove("active"));
                    const textTabBtn = document.querySelector('[data-tab="text-tab"]');
                    textTabBtn.classList.add("active");
                    document.getElementById("text-tab").classList.add("active");

                    showToast(`Loaded preset: ${presetType}`);
                    scanText();
                }
            } catch (err) {
                showToast("Failed to load preset: " + err.message);
            }
        });
    });

    // -------------------------------------------------------------
    // Scan Execution
    // -------------------------------------------------------------
    scanFileBtn.addEventListener("click", scanFile);
    scanTextBtn.addEventListener("click", scanText);

    async function scanFile() {
        if (!selectedFile) return;

        setScanningState(true, "file");
        loaderStatusMsg.textContent = selectedFile.type.includes("image") || selectedFile.name.match(/\.(png|jpe?g|bmp|tiff)$/i)
            ? "Executing Tesseract OCR pass & running Verhoeff / Luhn algorithmic verification..."
            : "Parsing document structure & scanning for sensitive data leaks...";

        const formData = new FormData();
        formData.append("file", selectedFile);
        formData.append("force_ocr", forceOcrCheckbox.checked ? "true" : "false");

        try {
            const response = await fetch("/api/scan", {
                method: "POST",
                body: formData,
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.error || "File scan failed");
            }
            renderScanResults(data);
            showToast("Document scanned successfully!");
        } catch (err) {
            showToast("Error: " + err.message);
        } finally {
            setScanningState(false, "file");
        }
    }

    async function scanText() {
        const text = rawTextInput.value.trim();
        if (!text) {
            showToast("Please enter or paste text to scan.");
            return;
        }

        setScanningState(true, "text");
        loaderStatusMsg.textContent = "Analyzing tokens & validating Aadhaar / Card checksums...";

        try {
            const response = await fetch("/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text }),
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.error || "Text scan failed");
            }
            renderScanResults(data);
            showToast("Text scanned successfully!");
        } catch (err) {
            showToast("Error: " + err.message);
        } finally {
            setScanningState(false, "text");
        }
    }

    function setScanningState(isScanning, type) {
        if (isScanning) {
            scanningLoader.style.display = "block";
            resultsSection.style.display = "none";
            if (type === "file") {
                scanFileBtn.disabled = true;
                fileBtnSpinner.style.display = "inline-block";
            } else {
                scanTextBtn.disabled = true;
                textBtnSpinner.style.display = "inline-block";
            }
        } else {
            scanningLoader.style.display = "none";
            if (type === "file") {
                scanFileBtn.disabled = false;
                fileBtnSpinner.style.display = "none";
            } else {
                scanTextBtn.disabled = false;
                textBtnSpinner.style.display = "none";
            }
        }
    }

    // -------------------------------------------------------------
    // Results Rendering
    // -------------------------------------------------------------
    function renderScanResults(data) {
        currentScanData = data;
        const res = data.result;

        // 1. Alert Banner
        riskBanner.className = `alert-banner banner-${res.risk_level.toLowerCase()}`;
        riskScoreBadge.textContent = `Risk Score: ${res.risk_score}/100`;

        if (res.risk_level === "CRITICAL") {
            riskBannerIcon.textContent = "🚨";
            riskBannerTitle.textContent = "CRITICAL DATA LEAK DETECTED";
            riskBannerMsg.textContent = "High-risk credentials such as Aadhaar (Verhoeff checksum verified) or Credit/Debit card numbers (Luhn verified) were identified in this stream!";
        } else if (res.risk_level === "HIGH") {
            riskBannerIcon.textContent = "⚠️";
            riskBannerTitle.textContent = "HIGH SENSITIVITY PII LEAK DETECTED";
            riskBannerMsg.textContent = "National identifiers like PAN card, Driving License, or Passport numbers were uncovered in this document.";
        } else if (res.risk_level === "MEDIUM") {
            riskBannerIcon.textContent = "⚠️";
            riskBannerTitle.textContent = "MODERATE DATA LEAK DETECTED";
            riskBannerMsg.textContent = "Voter IDs, mobile numbers, or banking branch codes were detected in this document stream.";
        } else if (res.risk_level === "LOW") {
            riskBannerIcon.textContent = "ℹ️";
            riskBannerTitle.textContent = "LOW SENSITIVITY TOKENS DETECTED";
            riskBannerMsg.textContent = "Public or low-risk identifiers like email addresses were found in this stream.";
        } else {
            riskBannerIcon.textContent = "🛡️";
            riskBannerTitle.textContent = "ALL CLEAR — ZERO DATA LEAKS FOUND";
            riskBannerMsg.textContent = "No PII, national IDs, or payment card numbers were detected. Document appears clean and safe for distribution.";
        }

        // 2. Metrics Cards
        totalViolationsCount.textContent = res.findings_count;
        algoValidatedCount.textContent = res.algorithmic_matches_count;
        criticalHighCount.textContent = (res.severity_breakdown.CRITICAL || 0) + (res.severity_breakdown.HIGH || 0);

        if (data.ocr_applied) {
            ingestionModeText.textContent = "Optical OCR";
            ingestionMetaFooter.textContent = `Tesseract engine (${data.page_count} page${data.page_count > 1 ? "s" : ""})`;
        } else {
            ingestionModeText.textContent = data.file_type || "Native Text";
            ingestionMetaFooter.textContent = `${res.text_length.toLocaleString()} characters parsed`;
        }

        // 3. Filter Counts
        filterAllCount.textContent = res.findings_count;
        filterAlgoCount.textContent = res.algorithmic_matches_count;
        filterCritCount.textContent = res.severity_breakdown.CRITICAL || 0;
        filterHighCount.textContent = res.severity_breakdown.HIGH || 0;

        // 4. Findings Table
        renderFindingsTable(res.findings);

        // 5. Document Viewer Content
        highlightedHtmlContent.innerHTML = res.highlighted_html || "<p class='text-muted'>[No document content]</p>";
        redactedTextContent.textContent = res.redacted_text || "[No document content]";
        rawTextContent.textContent = data.raw_text || "[No document content]";

        // Show Results
        resultsSection.style.display = "flex";
        resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    // -------------------------------------------------------------
    // Findings Table & Filtering
    // -------------------------------------------------------------
    function renderFindingsTable(findings) {
        findingsTableBody.innerHTML = "";

        const filtered = findings.filter(f => {
            if (activeFindingsFilter === "algo") return f.is_algorithmic;
            if (activeFindingsFilter === "CRITICAL") return f.severity === "CRITICAL";
            if (activeFindingsFilter === "HIGH") return f.severity === "HIGH";
            return true;
        });

        if (filtered.length === 0) {
            emptyFindingsMessage.style.display = "block";
            return;
        }

        emptyFindingsMessage.style.display = "none";

        filtered.forEach(f => {
            const tr = document.createElement("tr");

            const iconMap = {
                "Aadhaar Card": "🆔",
                "Aadhaar Virtual ID (VID)": "🪪",
                "PAN Card": "📋",
                "Driving License": "🚗",
                "Passport": "🛂",
                "Voter ID (EPIC)": "🗳️",
                "Phone Number": "📱",
                "Email Address": "✉️",
                "Bank IFSC Code": "🏦",
            };
            const icon = iconMap[f.verifier_name] || (f.category === "Financial" ? "💳" : "🔒");

            const algoTagHtml = f.is_algorithmic
                ? `<span class="algo-tag">⚡ ${escapeHtml(f.validation_method)}</span>`
                : `<span class="regex-tag">🔍 ${escapeHtml(f.validation_method)}</span>`;

            tr.innerHTML = `
                <td><strong>#${f.id}</strong></td>
                <td>
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span style="font-size: 1.2rem;">${icon}</span>
                        <div>
                            <div style="font-weight: 700; color: #fff;">${escapeHtml(f.verifier_name)}</div>
                            <div style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(f.category)}</div>
                        </div>
                    </div>
                </td>
                <td>
                    <span class="badge-sev sev-${f.severity.toLowerCase()}">${f.severity}</span>
                </td>
                <td>${algoTagHtml}</td>
                <td><code class="masked-code">${escapeHtml(f.masked_value)}</code></td>
                <td><div class="snippet-text">${escapeHtml(f.context_snippet)}</div></td>
            `;

            findingsTableBody.appendChild(tr);
        });
    }

    filterPills.forEach(pill => {
        pill.addEventListener("click", () => {
            filterPills.forEach(p => p.classList.remove("active"));
            pill.classList.add("active");
            activeFindingsFilter = pill.getAttribute("data-filter");

            if (currentScanData) {
                renderFindingsTable(currentScanData.result.findings);
            }
        });
    });

    // -------------------------------------------------------------
    // Document Viewer Tabs
    // -------------------------------------------------------------
    viewerTabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            viewerTabBtns.forEach(b => b.classList.remove("active"));
            viewerPanes.forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            const viewType = btn.getAttribute("data-view");
            if (viewType === "highlighted") document.getElementById("paneHighlighted").classList.add("active");
            if (viewType === "redacted") document.getElementById("paneRedacted").classList.add("active");
            if (viewType === "raw") document.getElementById("paneRaw").classList.add("active");
        });
    });

    // -------------------------------------------------------------
    // Export & Remediation Actions
    // -------------------------------------------------------------
    copyRedactedBtn.addEventListener("click", async () => {
        if (!currentScanData) return;
        const text = currentScanData.result.redacted_text;
        try {
            await navigator.clipboard.writeText(text);
            showToast("Sanitized text copied to clipboard!");
        } catch (err) {
            // Fallback for non-https or older browser context
            const ta = document.createElement("textarea");
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand("copy");
            document.body.removeChild(ta);
            showToast("Sanitized text copied to clipboard!");
        }
    });

    downloadRedactedBtn.addEventListener("click", () => {
        if (!currentScanData) return;
        const text = currentScanData.result.redacted_text;
        const filename = (currentScanData.filename || "document").replace(/\.[^/.]+$/, "") + "_sanitized.txt";
        
        const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast("Downloaded sanitized text file!");
    });

    downloadReportBtn.addEventListener("click", () => {
        if (!currentScanData) return;
        const report = {
            scanner: "Sentinel DLP Engine",
            scan_timestamp: new Date().toISOString(),
            source_file: currentScanData.filename,
            source_type: currentScanData.file_type,
            ocr_applied: currentScanData.ocr_applied,
            summary: {
                risk_level: currentScanData.result.risk_level,
                risk_score: currentScanData.result.risk_score,
                findings_count: currentScanData.result.findings_count,
                algorithmic_verifications: currentScanData.result.algorithmic_matches_count,
                severity_breakdown: currentScanData.result.severity_breakdown,
            },
            findings: currentScanData.result.findings,
        };

        const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `dlp_audit_report_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast("Downloaded full DLP audit report (.json)!");
    });

    // -------------------------------------------------------------
    // Toast Helper
    // -------------------------------------------------------------
    function showToast(msg) {
        toast.textContent = msg;
        toast.style.display = "block";
        setTimeout(() => {
            toast.style.display = "none";
        }, 3500);
    }

    function escapeHtml(str) {
        if (!str) return "";
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
