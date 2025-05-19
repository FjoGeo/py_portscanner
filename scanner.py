import queue
import socket
import threading
from typing import Set


class PyScan:
    def __init__(
        self,
        target: str,
        ports: str,
        threads: int,
        # TODO: udp: bool = False,
        # TODO: IP6 or IP4
        # TODO: verbose
    ) -> None:

        self.target = target
        self.threads = threads

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

    # TODO:
    def worker(self, protocol: str):
        """Thread worker: scan one port at a time from the queue"""
        # TODO:
        pass

    def scan(self):
        """Scan TCP ports using multiple threads"""
        self.port_queue = queue.Queue()
        for port in self.ports:
            self.port_queue.put(port)

        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker, args=("IPv4"))  # TODO:
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()  # wait for finish

        print("Scan complete!")
