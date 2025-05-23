from utility import scanner

if __name__ == "__main__":
    # 192.168.178.109 my KALI VM
    scanner = scanner.PyScan(
        target="192.168.178.109",
        ports="22,80,443,8000-8005",
        threads=10,
        verbose=False,
        udp=True,
    )
    scanner.scan()
