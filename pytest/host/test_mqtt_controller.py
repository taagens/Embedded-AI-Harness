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
