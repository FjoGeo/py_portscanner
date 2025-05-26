import argparse

from utility import scanner

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
        "--skip_dead_hosts",
        default=False,
        help="Skip host discovery (always scan)",
    )
    parser.add_argument(
        "-l",
        "--logging",
        default=None,
        help="Log file to save scan results (default: None, no logging)",
    )

    args = parser.parse_args()

    my_scanner = scanner.PyScan(
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
