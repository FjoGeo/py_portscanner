import queue
import socket
import threading
from typing import Set

from utility import udp_helper


class PyScan:
    def __init__(
        self,
        target: str,
        ports: str,
        threads: int,
        verbose: bool = False,
        udp: bool = False,
        ipv6: bool = False,
    ) -> None:

        self.target = target
        self.threads = threads
        self.verbose = verbose
        self.udp = udp
        self.ipv6 = ipv6

        self.addr_family = socket.AF_INET6 if ipv6 else socket.AF_INET
        self.open_ports: Set[int] = set()
        self.port_queue = queue.Queue()

        self.parse_port(ports)

    def parse_port(self, port_input) -> None:
        """
        sanitize and deduplicate entered ports
        """
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
            else:
                if self.verbose:
                    print(f"[-] Closed TCP Port: {port}")

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
                        if self.verbose:
                            print(f"[+] UDP Port {port} (got response)")
                            self.open_ports.add(port)
                        else:
                            print(f"[+] Open UDP Port {port} (got response)")
                except socket.timeout:
                    if self.verbose:
                        print(
                            f"[?] UDP Port {port}: No response (may be open/filtered)"
                        )
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
            self.port_queue.task_done()

    def scan(self):
        """Scan TCP ports using multiple threads"""
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

        print("Scan complete!")
