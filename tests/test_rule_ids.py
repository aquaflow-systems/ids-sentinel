import pytest
from scapy.all import IP, TCP, Raw

from src.alert_store import alert_store
from src.rule_ids import inspect_packet, parse_modbus_function_code


@pytest.fixture(autouse=True)
def clear_alerts():
    alert_store.clear()
    yield
    alert_store.clear()


def make_modbus_packet(src_ip: str, function_code: int, extra: bytes = b"\x00\x00"):
    mbap = b"\x00\x01\x00\x00\x00\x06\x01"  # transaction, protocol, length, unit id
    payload = mbap + bytes([function_code]) + extra
    return IP(src=src_ip, dst="10.10.0.12") / TCP(sport=51000, dport=502) / Raw(load=payload)


def test_parse_modbus_function_code_extracts_correct_byte():
    mbap = b"\x00\x01\x00\x00\x00\x06\x01"
    payload = mbap + bytes([0x06]) + b"\x00\x00"
    assert parse_modbus_function_code(payload) == 0x06


def test_parse_modbus_function_code_returns_none_on_short_payload():
    assert parse_modbus_function_code(b"\x00\x01") is None


def test_authorized_write_does_not_raise_alert():
    packet = make_modbus_packet("10.10.0.20", 0x06)

    inspect_packet(packet)

    assert alert_store.list() == []


def test_unauthorized_write_raises_critical_alert():
    packet = make_modbus_packet("10.10.0.99", 0x06)

    inspect_packet(packet)

    alerts = alert_store.list()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["details"]["src_ip"] == "10.10.0.99"


def test_unexpected_function_code_raises_warning_alert():
    packet = make_modbus_packet("10.10.0.20", 0x2B)

    inspect_packet(packet)

    alerts = alert_store.list()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "warning"


def test_authorized_read_does_not_raise_alert():
    packet = make_modbus_packet("10.10.0.99", 0x03)

    inspect_packet(packet)

    assert alert_store.list() == []
