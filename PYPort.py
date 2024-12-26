import socket
import concurrent.futures
import time

def scan_port(site_url, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((site_url, port)) == 0:
                return port, "Open"
        return port, "Closed"
    except socket.gaierror:
        return port, "Offline"
    except Exception:
        return port, "Error"

def save_results(site_url, results, elapsed_time):
    filename = f"{site_url}_ports.txt"
    with open(filename, 'w') as file:
        file.write(f"Scan Results for {site_url}\n")
        file.write(f"Elapsed Time: {elapsed_time:.2f} seconds\n\n")
        for status, port_list in results.items():
            file.write(f"{status} Ports:\n")
            if port_list:
                file.write(", ".join(str(port) for port in port_list) + "\n")
            else:
                file.write("None\n")
            file.write("\n")
    print(f"[INFO] Results saved to {filename}")


def main():
    site_url = input("Enter the site URL to scan (e.g., example.com): ").strip()

    try:
        ip = socket.gethostbyname(site_url)
        print(f"[INFO] Scanning {site_url} (IP: {ip})...")
    except socket.gaierror:
        print(f"[ERROR] Could not resolve {site_url} to an IP address.")
        return

    common_ports = [
        21,  # FTP
        22,  # SSH
        23,  # Telnet
        25,  # SMTP
        53,  # DNS
        80,  # HTTP
        110,  # POP3
        143,  # IMAP
        443,  # HTTPS
        3306,  # MySQL
        3389  # RDP
    ]

    total_ports = len(common_ports)

    timeout = 1
    max_threads = 100
    estimated_time = (total_ports / max_threads) * timeout
    print(f"[INFO] Estimated Time: ~{estimated_time:.2f} seconds")

    start_time = time.time()

    results = {
        "Open": [],
        "Closed": [],
        "Offline": [],
        "Error": []
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, site_url, port): port for port in common_ports}

        for future in concurrent.futures.as_completed(futures):
            port, status = future.result()
            if status in results:
                results[status].append(port)

    elapsed_time = time.time() - start_time

    save_results(site_url, results, elapsed_time)

    print(f"\n[INFO] Scan complete in {elapsed_time:.2f} seconds.")
    for status, port_list in results.items():
        print(f"{status} Ports: {', '.join(map(str, port_list)) if port_list else 'None'}")

    input("\nPress Enter to exit...")


if __name__ == "__main__":
    main()