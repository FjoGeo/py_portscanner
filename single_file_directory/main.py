import argparse
import errno
import queue
import socket
import threading
from typing import Dict, Set


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


# scanner file
class PyScan:
    def __init__(
        self,
        target: str,
        ports: str,
        threads: int,
        verbose: bool = False,
        udp: bool = False,
        ipv6: bool = False,
        scan_delay: float = 0.0,
        skip_dead_hosts: bool = False,
        logging: bool = False,  # TODO: implement logging
    ) -> None:

        self.threads = threads
        self.verbose = verbose
        self.udp = udp
        self.ipv6 = ipv6
        self.scan_delay = scan_delay
        self.skip_dead_hosts = skip_dead_hosts
        self.logging = logging
        self.open_ports: Set[int] = set()
        self.closed_ports: Set[int] = set()
        self.filtered_ports: Set[int] = set()
        self.port_queue = queue.Queue()

        self.resolve_target(target)
        self.parse_port(ports)

    def is_host_up(self, ports=[80, 443], timeout=1) -> bool:
        """
        Check if the host is up by attempting to connect to common ports.
        Returns True if at least one port is open, False otherwise.
        """
        for port in ports:
            try:
                with socket.socket(self.addr_family, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((self.target, port))
                    if result == 0:
                        return True  # Host is up
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error checking port {port}: {e}")
                    continue
        return False

    def parse_port(self, port_input: str) -> None:
        """
        Parse the port input string and populate the ports set.
        """

        if port_input.lower() == "all" or port_input.lower() == "full":
            self.ports = set(range(1, 65536))
            return

        assert port_input, "Error: no port or input invalid"
        self.ports = set()
        for part in port_input.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    start, end = map(int, part.split("-"))
                    if start < 1 or end > 65535 or start > end:
                        raise ValueError(f"Invalid port range: {part}")
                    self.ports.update(range(start, end + 1))
                except ValueError:
                    raise ValueError(f"Invalid port range: {part}")
            else:
                try:
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError(f"Invalid port: {part}")
                    self.ports.add(int(part))
                except ValueError:
                    raise ValueError(f"Invalid port: {part}")

    def resolve_target(self, target: str) -> None:
        """
        Determine address type (IPv4/IPv6) and resolve if hostname.
        Sets self.target and self.addr_family.
        """
        try:
            # IPv4
            socket.inet_pton(socket.AF_INET, target)
            self.target = target
            self.addr_family = socket.AF_INET
        except OSError:
            try:
                # IPv6
                socket.inet_pton(socket.AF_INET6, target)
                self.target = target
                self.addr_family = socket.AF_INET6
            except OSError:
                try:
                    # Resolve hostname
                    info = socket.getaddrinfo(
                        target, None, 0, 0, 0, socket.AI_ADDRCONFIG
                    )
                    if not info:
                        raise ValueError(f"Cannot resolve target: {target}")

                    # Use the first address from the resolved info
                    self.target = str(info[0][4][0])  # IP address
                    self.addr_family = info[0][0]  # Address family
                except Exception as e:
                    raise ValueError(f"Invalid IP or hostname: {target} ({e})")

    def save_results(self) -> None:
        """
        Save scan results to a file.
        This is a placeholder for future implementation.
        """
        if self.logging:
            with open("scan_results.txt", "w") as f:
                f.write(f"Target: {self.target}\n")
                f.write("Open Ports:\n")
                for port in sorted(self.open_ports):
                    f.write(f"{port}\n")
                f.write("Closed Ports:\n")
                for port in sorted(self.closed_ports):
                    f.write(f"{port}\n")
                f.write("Filtered Ports:\n")
                for port in sorted(self.filtered_ports):
                    f.write(f"{port}\n")
            print("[*] Scan results saved to scan_results.txt")

    def scan(self):
        """Scan ports using multiple threads"""

        if self.skip_dead_hosts:
            print(f"[*] Performing host discovery for {self.target}...")
            if not self.is_host_up():
                print(f"[!] Host {self.target} appears to be down. Skipping scan.")
                return
            else:
                print(f"[+] Host {self.target} is up. Starting port scan.")

        for port in self.ports:
            self.port_queue.put(port)

        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()  # wait for finish

        if self.logging:
            self.save_results()

    def scan_tcp_port(self, port: int) -> None:
        """
        Scan a single TCP port
        """
        with socket.socket(self.addr_family, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            addr_info = socket.getaddrinfo(
                self.target, port, self.addr_family, socket.SOCK_STREAM
            )
            result = sock.connect_ex(addr_info[0][4])
            if result == 0:
                print(f"[+] Open TCP Port: {port}")
                self.open_ports.add(port)
                try:
                    BANNER_PROBES = get_banner()
                    probe = BANNER_PROBES.get(port, b"")
                    if probe:
                        sock.sendall(probe)
                    banner = sock.recv(1024)
                    if banner and self.verbose:
                        print(f"    [Banner] {banner.decode(errors='ignore').strip()}")
                except socket.timeout:
                    if self.verbose:
                        print("    [!] Timeout while grabbing banner")
                except Exception as e:
                    if self.verbose:
                        print(f"[!] Error receiving banner on port {port}: {e}")
            elif result == errno.ECONNREFUSED:
                self.closed_ports.add(port)
                if self.verbose:
                    print(f"[-] Closed TCP Port: {port}")
            else:
                self.filtered_ports.add(port)
                if self.verbose:
                    print(f"[?] Filtered TCP Port: {port} (result code: {result})")

    def scan_udp_port(self, port: int) -> None:
        """
        Scan a single UDP port
        """
        UDP_PAYLOADS = {
            53: build_dns_query,
            161: build_snmp_get,
            123: build_ntp_request,
        }
        try:
            with socket.socket(self.addr_family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)

                payload_func = UDP_PAYLOADS.get(port)
                payload = payload_func() if payload_func else b""

                addr_info = socket.getaddrinfo(
                    self.target, port, self.addr_family, socket.SOCK_DGRAM
                )
                sock.sendto(payload, addr_info[0][4])
                try:
                    data, _ = sock.recvfrom(1024)
                    if data:
                        self.open_ports.add(port)
                        if self.verbose:
                            print(f"[+] UDP Port {port} (got response)")
                except socket.timeout:
                    self.filtered_ports.add(port)
                    if self.verbose:
                        print(
                            f"[?] UDP Port {port}: No response (may be open/filtered)"
                        )
                except ConnectionRefusedError:
                    self.closed_ports.add(port)
                    if self.verbose:
                        print(f"[-] Closed UDP Port: {port}")
        except Exception as e:
            print(f"[!] Error scanning UDP port {port}: {e}")

    def worker(self) -> None:
        """Thread worker: scan one port at a time from the queue"""
        while not self.port_queue.empty():
            port = self.port_queue.get()
            if self.udp:
                self.scan_udp_port(port)
            else:
                self.scan_tcp_port(port)

            # Rate limiting
            if self.scan_delay > 0:
                threading.Event().wait(self.scan_delay)

            self.port_queue.task_done()


ASCII_BANNER = r"""
  ____        ____                                
 |  _ \ _   _/ ___|  ___ _ __ ___   ___  _ __ ___ 
 | |_) | | | \___ \ / __| '_ ` _ \ / _ \| '__/ __|
 |  __/| |_| |___) | (__| | | | | | (_) | |  \__ \
 |_|    \__, |____/ \___|_| |_| |_|\___/|_|  |___/
        |___/                                      
         Lightweight Python Port Scanner - PyScanner
         by FjoGeo
"""


def main():
    parser = argparse.ArgumentParser(
        description=ASCII_BANNER,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-ta",
        "--target",
        default="192.168.178.109",
        help="Target IP address or hostname",
    )

    parser.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help="Ports to scan (e.g. '22,80,443', '1-65535', 'all', 'full')",
    )

    parser.add_argument(
        "-t", "--threads", type=int, default=10, help="Number of threads to use"
    )

    parser.add_argument(
        "-u", "--udp", action="store_true", default=False, help="Enable UDP scan"
    )
    parser.add_argument(
        "--ipv6", action="store_true", default=False, help="Use IPv6 scanning"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "-r",
        "--rate",
        type=float,
        default=0,
        help="Rate limit (seconds delay between scans)",
    )
    parser.add_argument(
        "-sdh",
        "--skip_dead_hosts",
        action="store_true",
        help="Skip host discovery",
    )
    parser.add_argument(
        "-l",
        "--logging",
        action="store_true",
        help="Log file to save scan results (default: None, no logging)",
    )

    args = parser.parse_args()

    my_scanner = PyScan(
        target=args.target,
        ports=args.ports,
        threads=args.threads,
        verbose=args.verbose,
        udp=args.udp,
        ipv6=args.ipv6,
        scan_delay=args.rate,
        skip_dead_hosts=args.skip_dead_hosts,
        logging=args.logging,
    )

    my_scanner.scan()


if __name__ == "__main__":
    main()
