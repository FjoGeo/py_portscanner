def build_dns_query() -> bytes:
    return (
        b"\x12\x34"  # Transaction ID
        b"\x01\x00"  # Standard query
        b"\x00\x01"  # One question
        b"\x00\x00"  # No answers
        b"\x00\x00"  # No authority RRs
        b"\x00\x00"  # No additional RRs
        b"\x07example"  # Label: example
        b"\x03com"  # Label: com
        b"\x00"  # End of domain name
        b"\x00\x01"  # Type A
        b"\x00\x01"  # Class IN
    )


def build_snmp_get():
    # A basic SNMPv1 GET Request in ASN.1 DER format
    return bytes.fromhex(
        "30"  # SEQUENCE
        "26"  # Length
        "02 01 00"  # SNMP version: 0 = v1
        "04 06 7075626c6963"  # Community: "public"
        "A0 19"  # GET Request
        "02 04 70 75 74 01"  # Request ID
        "02 01 00"  # Error status
        "02 01 00"  # Error index
        "30 0B"  # Variable bindings sequence
        "30 09"
        "06 05 2b 06 01 02 01"  # OID: 1.3.6.1.2.1
        "05 00"  # NULL
    )


def build_ntp_request():
    # 48-byte request: NTP client mode, version 3
    return b"\x1b" + 47 * b"\0"
