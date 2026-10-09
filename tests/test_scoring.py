from ronin.investigator import provider_plan, score_report


def test_ip_provider_plan():
    assert provider_plan("ipv4") == ["virustotal", "shodan", "censys", "abuseipdb"]


def test_risk_score():
    report = {"results": {
        "virustotal": {"data": {"last_analysis_stats": {"malicious": 4, "suspicious": 2}}},
        "abuseipdb": {"data": {"abuse_confidence_score": 50}},
    }}
    result = score_report(report)
    assert result["score"] == 46
    assert result["level"] == "MEDIUM"
