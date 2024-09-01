import sys
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Validate the number of arguments provided
if len(sys.argv) != 2:
    print("Invalid number of arguments.")
    print("Usage: python3 scanner.py <ip>")
    sys.exit(1)

# Resolve the target hostname
try:
    target = socket.gethostbyname(sys.argv[1])
except socket.gaierror:
    print("Error: Hostname could not be resolved.")
    sys.exit(1)

# Display scanning information
print("\n")
print("-" * 50)
print(f"Scanning target: {target}")
print(f"Time started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("-" * 50)

# Function to scan a single port
def scan_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            socket.setdefaulttimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                return port, True
    except Exception as e:
        return port, False
    return port, False

# Main scanning logic with threading
open_ports = []
port_range = range(50, 85)  # Range of ports to scan
max_threads = 10  # Maximum number of concurrent threads

try:
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(scan_port, port): port for port in port_range}
        for future in as_completed(future_to_port):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
                print(f"Port {port} is open")

except KeyboardInterrupt:
    print("\nExiting program.")
    sys.exit(0)
except Exception as e:
    print(f"Error occurred: {e}")
    sys.exit(1)

# Display scan completion message
print("-" * 50)
print("Scan complete.")
if open_ports:
    print(f"Open ports: {', '.join(map(str, open_ports))}")
else:
    print("No open ports found.")
print("-" * 50)
