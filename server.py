import socket
from scapy.all import DNS

# 15 IPs in the pool
IP_POOL = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

# Time-based routing rules
ROUTING_RULES = {
    "morning": {"start": 4, "end": 11, "pool_start": 0},
    "afternoon": {"start": 12, "end": 19, "pool_start": 5},
    "night": {"start": 20, "end": 23, "pool_start": 10},  # 20–23
    "late_night": {"start": 0, "end": 3, "pool_start": 10}  # 00–03 also night slot
}

def resolve_ip(custom_header: str) -> str:
    """
    Resolve IP address based on custom header using time+ID rules.
    custom_header format = HHMMSSID (8 chars)
    """
    try:
        hour = int(custom_header[:2])
        session_id = int(custom_header[-2:])  # last 2 digits = ID
    except ValueError:
        return "127.0.0.1"  # fallback

    # Determine time period
    if ROUTING_RULES["morning"]["start"] <= hour <= ROUTING_RULES["morning"]["end"]:
        pool_start = ROUTING_RULES["morning"]["pool_start"]
    elif ROUTING_RULES["afternoon"]["start"] <= hour <= ROUTING_RULES["afternoon"]["end"]:
        pool_start = ROUTING_RULES["afternoon"]["pool_start"]
    elif ROUTING_RULES["night"]["start"] <= hour <= ROUTING_RULES["night"]["end"]:
        pool_start = ROUTING_RULES["night"]["pool_start"]
    else:  # 00–03 late night
        pool_start = ROUTING_RULES["late_night"]["pool_start"]

    # Apply hash_mod 5
    offset = session_id % 5
    final_index = pool_start + offset
    return IP_POOL[final_index]

def start_server(host="0.0.0.0", port=9999):
    """
    Start the DNS resolver server with load balancing rules.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    print(f"[+] Server listening on {host}:{port}")

    conn, addr = server.accept()
    print(f"[+] Connection established with {addr}")

    while True:
        data = conn.recv(4096)
        if not data:
            break

        header = data[:8].decode(errors="ignore")
        dns_data = data[8:]

        try:
            dns_pkt = DNS(dns_data)
            qname = dns_pkt[DNS].qd.qname.decode()

            resolved_ip = resolve_ip(header)

            response = f"{header} | {qname} | {resolved_ip}"
            conn.send(response.encode())

            print(f"[QUERY] {qname} -> {resolved_ip} (Header: {header})")

        except Exception as e:
            print(f"[!] Error parsing DNS packet: {e}")
            conn.send(f"ERROR: {str(e)}".encode())

    conn.close()
    server.close()


if __name__ == "__main__":
    start_server()