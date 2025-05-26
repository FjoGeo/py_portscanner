# Python Port Scanner

A Python Port Scanner using only the standard library.
Current project is in development and is not yet complete.

---

---

| _ \ _ \_/ **_| _** \_ ** \_** **\_ \_ ** **_
| |_) | | | \_** \ / **| '_ ` _ \ / \_ \| '**/ **|
| **/| |\_| |**\_) | (**| | | | | | (\_) | | \__ \
 |_| \__, |\_**\_/ \_**|_| |_| |_|\_**/|_| |_**/
|\_\_\_/
Lightweight Python Port Scanner - PyScanner
by FjoGeo

options:
-h, --help show this help message and exit
-ta, --target TARGET Target IP address or hostname
-p, --ports PORTS Ports to scan (e.g. '22,80,443', '1-65535', 'all', 'full')
-t, --threads THREADS
Number of threads to use
-u, --udp Enable UDP scan
--ipv6 Use IPv6 scanning
-v, --verbose Enable verbose output
-r, --rate RATE Rate limit (seconds delay between scans)
--skip_dead_hosts SKIP_DEAD_HOSTS
Skip host discovery (always scan)
-l, --logging LOGGING
Log file to save scan results (default: None, no logging)

---

<!-- TODO: -->

## To Do

5. Argparse for CLI
6. Progress Bar
7. Logging / Output File
8. Spoofed Source IP
9. Fragmentation
10. Create alternative version as single file
