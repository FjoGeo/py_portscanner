import errno
import queue
import socket
import threading
from typing import Set

from utility import udp_helper
from utility.tcp_helper import get_banner


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
    ) -> None:

        self.threads = threads
        self.verbose = verbose
        self.udp = udp
        self.ipv6 = ipv6
        self.scan_delay = scan_delay
        self.open_ports: Set[int] = set()
        self.closed_ports: Set[int] = set()
        self.filtered_ports: Set[int] = set()
        self.port_queue = queue.Queue()

        self.resolve_target(target)
        self.parse_port(ports)

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

    def scan(self):
        """Scan ports using multiple threads"""
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
            53: udp_helper.build_dns_query,
            161: udp_helper.build_snmp_get,
            123: udp_helper.build_ntp_request,
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
