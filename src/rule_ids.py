import logging

from scapy.all import IP, TCP, Packet, sniff
from scapy.packet import Raw

from src.alert_store import alert_store

logger = logging.getLogger(__name__)

DOSING_PORT = 502
DOSING_FILTER = f"tcp port {DOSING_PORT}"

AUTHORIZED_WRITE_SOURCES = {"10.10.0.20"}

READ_FUNCTION_CODES = {0x03}
WRITE_FUNCTION_CODES = {0x06, 0x10}
KNOWN_FUNCTION_CODES = READ_FUNCTION_CODES | WRITE_FUNCTION_CODES

MBAP_HEADER_LEN = 7


def parse_modbus_function_code(payload: bytes) -> int | None:
    """Extract the Modbus function code from a raw Modbus/TCP ADU, or None if
    the payload is too short to contain one.
    """
    if len(payload) < MBAP_HEADER_LEN + 1:
        return None
    return payload[MBAP_HEADER_LEN]


def inspect_packet(packet: Packet) -> None:
    if not packet.haslayer(IP) or not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return

    src_ip = packet[IP].src
    payload = bytes(packet[Raw].load)
    function_code = parse_modbus_function_code(payload)

    if function_code is None:
        return

    if function_code not in KNOWN_FUNCTION_CODES:
        alert_store.add(
            source="rule_ids",
            severity="warning",
            message=f"unexpected Modbus function code 0x{function_code:02x} from {src_ip}",
            src_ip=src_ip,
            function_code=function_code,
        )
        return

    if function_code in WRITE_FUNCTION_CODES and src_ip not in AUTHORIZED_WRITE_SOURCES:
        alert_store.add(
            source="rule_ids",
            severity="critical",
            message=f"unauthorized write (function code 0x{function_code:02x}) from {src_ip}",
            src_ip=src_ip,
            function_code=function_code,
        )


def start_sniffing() -> None:
    logger.info("starting Modbus traffic sniffing on filter '%s'", DOSING_FILTER)
    sniff(filter=DOSING_FILTER, prn=inspect_packet, store=False)
