import socket
import argparse
import concurrent.futures

def scan_port(target, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                return port, True
    except Exception:
        pass
    return port, False

def main():
    parser = argparse.ArgumentParser(description="Simple Python Port Scanner")
    parser.add_argument("target", type=str, help="Target IP or hostname (required)")
    parser.add_argument(
        "--ports", type=str, default="1-1024",
        help="Port range to scan (default: 1-1024)"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Connection timeout in seconds (default: 1)"
    )
    parser.add_argument(
        "--threads", type=int, default=100,
        help="Number of threads to use (default: 100)"
    )
    args = parser.parse_args()

    # Validate port range
    try:
        start_port, end_port = map(int, args.ports.split("-"))
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError
    except ValueError:
        print("Error: Invalid port range. Example: 20-80")
        return

    if args.threads <= 0:
        print("Error: Threads must be a positive integer.")
        return

    if args.timeout <= 0:
        print("Error: Timeout must be greater than 0.")
        return

    print(f"\nScanning {args.target} on ports {start_port}-{end_port}...\n")

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_port, args.target, port, args.timeout): port
            for port in range(start_port, end_port + 1)
        }
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)

    if open_ports:
        print("Open Ports:")
        for port in sorted(open_ports):
            print(f" - {port}")
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()
