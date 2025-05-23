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
        # TODO: IP6 or IP4
    ) -> None:

        self.target = target
        self.threads = threads
        self.verbose = verbose
        self.udp = udp
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
            if "-" in part:
                start, end = map(int, part.split("-"))
                self.ports.update(range(start, end + 1))
            else:
                self.ports.add(int(part))

    def scan_tcp_port(self, port: int) -> None:
        """
        Scan a single TCP port
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                print(f"[+] Open TCP Port: {port}")
                self.open_ports.add(port)
            else:
                if self.verbose:
                    print(f"[-] Closed TCP Port: {port}")

    def scan_udp_port(self, port: int) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                if port == 53:
                    payload = udp_helper.build_dns_query()
                elif port == 161:
                    payload = udp_helper.build_snmp_get()
                elif port == 123:
                    payload = udp_helper.build_ntp_request()
                else:
                    payload = b""  # fallback

                sock.sendto(payload, (self.target, port))
                try:
                    data, _ = sock.recvfrom(1024)
                    print(f"[+] Open UDP Port {port} (got response)")
                    self.open_ports.add(port)
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


if __name__ == "__main__":
    # 192.168.178.109 my KALI VM
    scanner = PyScan(
        target="192.168.178.109",
        ports="22,80,443,8000-8005",
        threads=10,
        verbose=True,
        udp=True,
    )
    scanner.scan()
