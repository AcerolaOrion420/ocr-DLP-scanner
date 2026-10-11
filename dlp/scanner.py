"""
DLP Scanner: Orchestrates verifiers, handles match deduplication,
context extraction, text redaction, HTML markup, and risk assessment.
"""

import html
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from dlp.verifiers import ALL_VERIFIERS, BaseVerifier, RawFinding


SEVERITY_WEIGHTS = {
    "CRITICAL": 35,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
}

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


@dataclass
class Finding:
    id: int
    verifier_name: str
    category: str
    severity: str
    is_algorithmic: bool
    raw_value: str
    masked_value: str
    start: int
    end: int
    validation_method: str
    context_snippet: str
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    text_length: int
    findings_count: int
    risk_level: str  # CLEAN, LOW, MEDIUM, HIGH, CRITICAL
    risk_score: int  # 0 to 100
    severity_breakdown: Dict[str, int]
    algorithmic_matches_count: int
    findings: List[Finding]
    redacted_text: str
    highlighted_html: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text_length": self.text_length,
            "findings_count": self.findings_count,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "severity_breakdown": self.severity_breakdown,
            "algorithmic_matches_count": self.algorithmic_matches_count,
            "findings": [f.to_dict() for f in self.findings],
            "redacted_text": self.redacted_text,
            "highlighted_html": self.highlighted_html,
        }


class DLPScanner:
    """
    Main DLP scanning engine.
    """

    def __init__(self, verifiers: Optional[List[BaseVerifier]] = None):
        self.verifiers = verifiers if verifiers is not None else ALL_VERIFIERS

    def scan(self, text: str) -> ScanResult:
        if not text:
            return ScanResult(
                text_length=0,
                findings_count=0,
                risk_level="CLEAN",
                risk_score=0,
                severity_breakdown={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                algorithmic_matches_count=0,
                findings=[],
                redacted_text="",
                highlighted_html="",
            )

        raw_findings: List[RawFinding] = []
        for verifier in self.verifiers:
            try:
                matches = verifier.find_all(text)
                raw_findings.extend(matches)
            except Exception as e:
                # Keep scanner resilient against corrupted or unexpected inputs
                continue

        # Deduplicate and resolve overlapping ranges
        filtered_findings = self._resolve_overlaps(raw_findings)

        # Build final Finding objects with context snippets
        findings: List[Finding] = []
        for idx, rf in enumerate(filtered_findings, start=1):
            snippet = self._build_context_snippet(text, rf.start, rf.end, rf.masked_value)
            findings.append(
                Finding(
                    id=idx,
                    verifier_name=rf.verifier_name,
                    category=rf.category,
                    severity=rf.severity,
                    is_algorithmic=rf.is_algorithmic,
                    raw_value=rf.raw_value,
                    masked_value=rf.masked_value,
                    start=rf.start,
                    end=rf.end,
                    validation_method=rf.validation_method,
                    context_snippet=snippet,
                    details=rf.details,
                )
            )

        # Build redacted text and highlighted HTML
        redacted_text = self._build_redacted_text(text, findings)
        highlighted_html = self._build_highlighted_html(text, findings)

        # Metrics & Risk score calculation
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        algo_count = 0
        total_risk_points = 0

        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            if f.is_algorithmic:
                algo_count += 1
            total_risk_points += SEVERITY_WEIGHTS.get(f.severity, 5)

        # Calculate overall risk level
        if severity_counts["CRITICAL"] > 0:
            risk_level = "CRITICAL"
        elif severity_counts["HIGH"] > 0:
            risk_level = "HIGH"
        elif severity_counts["MEDIUM"] > 0:
            risk_level = "MEDIUM"
        elif severity_counts["LOW"] > 0:
            risk_level = "LOW"
        else:
            risk_level = "CLEAN"

        risk_score = min(100, total_risk_points) if findings else 0

        return ScanResult(
            text_length=len(text),
            findings_count=len(findings),
            risk_level=risk_level,
            risk_score=risk_score,
            severity_breakdown=severity_counts,
            algorithmic_matches_count=algo_count,
            findings=findings,
            redacted_text=redacted_text,
            highlighted_html=highlighted_html,
        )

    def _resolve_overlaps(self, raw_findings: List[RawFinding]) -> List[RawFinding]:
        """
        Sort and filter overlapping spans based on:
        1. Algorithmic verification status (Verhoeff/Luhn takes priority)
        2. Severity level
        3. Match length (longer match wins)
        """
        if not raw_findings:
            return []

        # Sort criteria:
        # Start index ascending
        # Tie-breaker 1: is_algorithmic descending
        # Tie-breaker 2: severity order descending
        # Tie-breaker 3: span length (end - start) descending
        sorted_findings = sorted(
            raw_findings,
            key=lambda x: (
                x.start,
                -(1 if x.is_algorithmic else 0),
                -SEVERITY_ORDER.get(x.severity, 0),
                -(x.end - x.start),
            ),
        )

        non_overlapping: List[RawFinding] = []
        for current in sorted_findings:
            if not non_overlapping:
                non_overlapping.append(current)
                continue

            last = non_overlapping[-1]

            # If there is no overlap
            if current.start >= last.end:
                non_overlapping.append(current)
            else:
                # There is overlap, determine which one to keep
                # Algorithmic check priority
                if current.is_algorithmic and not last.is_algorithmic:
                    non_overlapping[-1] = current
                elif not current.is_algorithmic and last.is_algorithmic:
                    continue
                else:
                    # Severity check
                    curr_sev = SEVERITY_ORDER.get(current.severity, 0)
                    last_sev = SEVERITY_ORDER.get(last.severity, 0)
                    if curr_sev > last_sev:
                        non_overlapping[-1] = current
                    elif curr_sev == last_sev:
                        # Length check
                        if (current.end - current.start) > (last.end - last.start):
                            non_overlapping[-1] = current

        return non_overlapping

    def _build_context_snippet(
        self, text: str, start: int, end: int, masked_value: str, window: int = 35
    ) -> str:
        """
        Extract snippet surrounding the sensitive data with masking.
        """
        prefix_start = max(0, start - window)
        prefix = text[prefix_start:start]
        if prefix_start > 0:
            prefix = "..." + prefix

        suffix_end = min(len(text), end + window)
        suffix = text[end:suffix_end]
        if suffix_end < len(text):
            suffix = suffix + "..."

        # Clean newlines for snippet readability
        clean_prefix = " ".join(prefix.split())
        clean_suffix = " ".join(suffix.split())

        return f"{clean_prefix} [{masked_value}] {clean_suffix}"

    def _build_redacted_text(self, text: str, findings: List[Finding]) -> str:
        """
        Replace all sensitive findings in text with masked representations.
        """
        if not findings:
            return text

        # Sort findings by start index ascending
        sorted_f = sorted(findings, key=lambda x: x.start)
        chunks = []
        last_idx = 0

        for f in sorted_f:
            chunks.append(text[last_idx : f.start])
            chunks.append(f.masked_value)
            last_idx = f.end

        chunks.append(text[last_idx:])
        return "".join(chunks)

    def _build_highlighted_html(self, text: str, findings: List[Finding]) -> str:
        """
        Generate safely escaped HTML with colored badges for sensitive data.
        """
        if not findings:
            return f"<pre class='dlp-document-pre'>{html.escape(text)}</pre>"

        sorted_f = sorted(findings, key=lambda x: x.start)
        html_chunks = []
        last_idx = 0

        for f in sorted_f:
            # Safe HTML escape non-sensitive text
            html_chunks.append(html.escape(text[last_idx : f.start]))
            
            # Badge markup
            sev_class = f.severity.lower()
            badge_title = f"{f.verifier_name} ({f.severity}) - {f.validation_method}"
            algo_badge = '<span class="badge-algo">ALGO</span> ' if f.is_algorithmic else ""

            safe_val = html.escape(f.raw_value)
            mark_tag = (
                f'<mark class="dlp-leak dlp-leak-{sev_class}" '
                f'data-finding-id="{f.id}" '
                f'title="{html.escape(badge_title)}">'
                f'<span class="leak-tag">{algo_badge}{html.escape(f.verifier_name)}</span>'
                f'<span class="leak-content">{safe_val}</span>'
                f'</mark>'
            )
            html_chunks.append(mark_tag)
            last_idx = f.end

        html_chunks.append(html.escape(text[last_idx:]))
        return f"<div class='dlp-document-body'>{''.join(html_chunks)}</div>"
