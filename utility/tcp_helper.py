from typing import Dict


def get_banner() -> Dict[int, bytes]:
    """
    Returns a default banner request for TCP services.
    This is used to probe services for their banners.
    """
    BANNER_PROBES = {
        21: b"SYST\r\n",  # FTP
        22: b"",  # SSH typically sends banner first
        25: b"EHLO scanner\r\n",  # SMTP
        80: b"HEAD / HTTP/1.0\r\n\r\n",  # HTTP
        110: b"",  # POP3
        143: b"",  # IMAP
        443: b"",  # HTTPS - banner grabbing not useful unless you handle TLS
        3306: b"",  # MySQL
        3389: b"",  # RDP
        8080: b"HEAD / HTTP/1.0\r\n\r\n",  # Alt HTTP
    }

    return BANNER_PROBES
