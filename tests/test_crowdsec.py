from app.services import crowdsec_payload_to_events


def test_native_crowdsec_alert_list_is_normalized():
    payload = [
        {
            "scenario": "crowdsecurity/ssh-bf",
            "source": {"ip": "203.0.113.10", "cn": "AT"},
            "decisions": [{"type": "ban", "duration": "4h"}],
            "message": "test alert",
        }
    ]

    events = crowdsec_payload_to_events("server", payload)

    assert len(events) == 1
    assert events[0].source == "server"
    assert events[0].scenario == "crowdsecurity/ssh-bf"
    assert events[0].source_ip == "203.0.113.10"
    assert events[0].country == "AT"
    assert events[0].severity == "high"


def test_wrapped_alerts_are_supported():
    payload = {"alerts": [{"scenario": "crowdsecurity/http-probing", "source": {"ip": "198.51.100.5"}}]}
    events = crowdsec_payload_to_events("firewall", payload)
    assert len(events) == 1
    assert events[0].source == "firewall"
    assert events[0].severity == "low"
