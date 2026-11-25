"""Host tier for FR-029 (MQTT test broker): the config the broker is started
with, and the credentials it accepts. Pure logic only — no process, no file."""
import pytest

import mqtt_controller as mc


def test_fr029_open_broker_allows_anonymous():
    lines = mc.config_lines(1883, "/w/log")
    assert "listener 1883" in lines
    assert "allow_anonymous true" in lines
    assert not any(ln.startswith("password_file") for ln in lines)


def test_fr029_auth_broker_refuses_anonymous_and_names_its_password_file():
    lines = mc.config_lines(1883, "/w/log", password_file="/w/passwd")
    assert "allow_anonymous false" in lines
    assert "allow_anonymous true" not in lines
    assert "password_file /w/passwd" in lines


@pytest.mark.parametrize("user,pw", [("dut", "s3cret"), ("pv20a", "x" * 64)])
def test_fr029_accepts_plain_credentials(user, pw):
    mc.validate_credentials(user, pw)


@pytest.mark.parametrize("user,pw", [
    ("", "pw"), ("user", ""), ("a:b", "pw"), ("user\n", "pw"), ("user", "p\nw"),
    (None, "pw"), ("user", None), ("x" * 65, "pw"),
])
def test_fr029_rejects_credentials_the_password_file_cannot_hold(user, pw):
    with pytest.raises(ValueError):
        mc.validate_credentials(user, pw)


# ── FR-041: subscriptions from the broker log ────────────────────────────────

LOG = [
    "1700000000: mosquitto version 2.0.11 starting",
    "1700000001: New connection from 192.168.4.2:50000 on port 1883.",
    "1700000001: New client connected from 192.168.4.2:50000 as ESP32_ABCD (p2, c1, k30, u'dut').",
    "1700000001: Received SUBSCRIBE from ESP32_ABCD",
    "1700000001: \thomeassistant/status (QoS 1)",
    "1700000001: ESP32_ABCD 1 homeassistant/status",
    "1700000001: \tpv20a/aabbccddeeff/cmd/ota (QoS 1)",
    "1700000001: ESP32_ABCD 1 pv20a/aabbccddeeff/cmd/ota",
    "1700000001: Sending SUBACK to ESP32_ABCD",
    "1700000002: Received UNSUBSCRIBE from ESP32_ABCD",
    "1700000002: \thomeassistant/status",
    "1700000003: New client connected from 192.168.0.10:40000 as rec-1 (p2, c1, k60).",
    "1700000004: Received SUBSCRIBE from rec-1",
    "1700000004: \tpv20a/# (QoS 0)",
    "1700000004: Sending SUBACK to rec-1",
    "garbage without a timestamp",
]


def test_fr041_parses_each_topic_filter_with_client_address_and_qos():
    subs = mc.parse_subscriptions(LOG)
    assert [(s["client"], s["address"], s["topic"], s["qos"]) for s in subs] == [
        ("ESP32_ABCD", "192.168.4.2", "homeassistant/status", 1),
        ("ESP32_ABCD", "192.168.4.2", "pv20a/aabbccddeeff/cmd/ota", 1),
        ("rec-1", "192.168.0.10", "pv20a/#", 0),
    ]
    assert subs[0]["ts"] == 1700000001.0


def test_fr041_filters_by_since_and_address():
    assert [s["topic"] for s in mc.parse_subscriptions(LOG, since=1700000002)] == ["pv20a/#"]
    assert [s["client"] for s in mc.parse_subscriptions(LOG, address="192.168.4.2")] == ["ESP32_ABCD"] * 2
    assert mc.parse_subscriptions(LOG, address="192.168.4.9") == []


def test_fr041_unsubscribe_lines_are_not_subscriptions():
    assert all(s["ts"] != 1700000002.0 for s in mc.parse_subscriptions(LOG))


def test_fr041_never_returns_the_username_or_other_log_text():
    for s in mc.parse_subscriptions(LOG):
        assert set(s) == {"ts", "client", "address", "topic", "qos"}
        assert "dut" not in str(s.values())


def test_fr041_reconnect_from_a_new_address_is_attributed_to_it():
    log = LOG[:3] + [
        "1700000010: New client connected from 192.168.4.3:50001 as ESP32_ABCD (p2, c1, k30).",
        "1700000010: Received SUBSCRIBE from ESP32_ABCD",
        "1700000010: \thomeassistant/status (QoS 1)",
    ]
    assert [s["address"] for s in mc.parse_subscriptions(log)] == ["192.168.4.3"]


def test_fr041_topic_line_outside_a_subscribe_is_ignored():
    assert mc.parse_subscriptions(["1700000000: \tstray/topic (QoS 1)"]) == []
