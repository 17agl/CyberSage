from threat_intel.enricher import enrich_alert, get_ip_reputation, is_private_ip


def test_private_ip_classification():
    # RFC 1918 addresses
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("172.16.0.100") is True
    assert is_private_ip("127.0.0.1") is True

    # Public addresses
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("198.51.100.23") is False
    assert is_private_ip("203.0.113.88") is False


def test_private_ips_never_assigned_threat_score():
    res = get_ip_reputation("192.168.1.50")
    assert res["is_private"] is True
    assert res["reputation"] == "internal"
    assert res["threat_score"] == 0


def test_public_threat_intel_match():
    res = get_ip_reputation("198.51.100.23")
    assert res["is_private"] is False
    assert res["reputation"] == "malicious"
    assert res["threat_score"] >= 90
    assert "Known C2 Server" in res["threat_tags"]


def test_alert_enrichment():
    alert = {
        "rule_id": "TEST_001",
        "alert_type": "test_alert",
        "source_ip": "192.168.1.10",
        "destination_ip": "198.51.100.23",
        "severity": "medium",
    }
    enriched = enrich_alert(alert)
    assert "threat_intel" in enriched
    assert enriched["threat_intel"]["source"]["is_private"] is True
    assert enriched["threat_intel"]["destination"]["is_private"] is False
    # Verified automatic elevation due to known malicious C2 score
    assert enriched["severity"] == "high"
