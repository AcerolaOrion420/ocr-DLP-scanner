"""
Integration tests for Flask Web App and REST API endpoints.
"""

import io
import json
import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestFlaskEndpoints:
    def test_dashboard_home(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert b"SENTINEL" in response.data
        assert b"Document &amp; Data Ingestion" in response.data or b"Document & Data Ingestion" in response.data

    def test_health_check(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "healthy"
        assert "supported_verifiers" in data
        assert "Aadhaar Card" in data["supported_verifiers"]

    def test_scan_text_valid(self, client):
        payload = {
            "text": "Alert: PAN ABCPS1234F and Aadhaar 2345 6789 0124 leaked!"
        }
        response = client.post(
            "/api/scan",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["result"]["findings_count"] == 2
        assert data["result"]["risk_level"] == "CRITICAL"
        assert data["result"]["algorithmic_matches_count"] >= 1

    def test_scan_text_empty(self, client):
        response = client.post(
            "/api/scan",
            data=json.dumps({"text": ""}),
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False

    def test_scan_file_upload(self, client):
        file_content = b"Financial leak: Visa Card 4111 1111 1111 1111"
        data = {
            "file": (io.BytesIO(file_content), "leak.txt"),
            "force_ocr": "false",
        }
        response = client.post(
            "/api/scan",
            data=data,
            content_type="multipart/form-data",
        )
        assert response.status_code == 200
        res = response.get_json()
        assert res["success"] is True
        assert res["result"]["findings_count"] == 1
        assert "Visa" in res["result"]["findings"][0]["verifier_name"]

    def test_get_sample(self, client):
        response = client.get("/api/sample/leak_full")
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "2345 6789 0124" in data["text"]

    def test_download_redacted(self, client):
        response = client.post(
            "/api/download/redacted",
            data={"text": "Clean sanitized text", "filename": "safe.txt"},
        )
        assert response.status_code == 200
        assert b"Clean sanitized text" in response.data
