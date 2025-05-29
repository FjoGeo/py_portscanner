# Python Port Scanner

A Python Port Scanner using only the standard library.
Intended to be used on a machine without nmap or other port scanning tools installed.

## Features:

- Scans TCP and UDP ports
- Supports IPv4 and IPv6
- Multi-threaded for faster scanning
- Customizable port ranges and specific ports
- Verbose output for detailed results
- Optional logging to a file
- Skips dead hosts to save time
- Rate limiting to control scan speed

## Installation:

Clone the repository and run the script directly:

```bash
git clone https://github.com/FjoGeo/py_portscanner.git
cd py_portscanner
python main.py --help
```

If you want to use the script in a single file, use the script located in the `single_file_directoryi` or copy and paste it from GitHub into your texteditor of choice:

```bash
git clone clone https://github.com/FjoGeo/py_portscanner.git
cd py_portscanner/single_file_directory
python main.py --help
```

---

## Options:

```bash
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
```

## Example Usage:

```bash
python main.py -ta 192.168.178.109 -p 22 -v -l -sdh
```
