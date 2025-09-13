import socket
import datetime
from scapy.all import rdpcap, DNS

def make_custom_header(index: int) -> str:
    """
    Create an 8-byte custom header in format HHMMSSID
    """
    now = datetime.datetime.now()
    return f"{now:%H%M%S}{index:02d}"

def parse_dns_queries(pcap_file: str):
    """
    Extract DNS queries from the pcap file.
    """
    packets = rdpcap(pcap_file)
    dns_queries = [p for p in packets if p.haslayer(DNS) and p[DNS].qr == 0]
    return dns_queries

def run_client(pcap_file: str, server_host="127.0.0.1", server_port=9999):
    # Connect to server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_host, server_port))
    print(f"[+] Connected to server at {server_host}:{server_port}")

    dns_queries = parse_dns_queries(pcap_file)
    print(f"[+] Found {len(dns_queries)} DNS queries in {pcap_file}")

    results = []

    for i, pkt in enumerate(dns_queries):
        header = make_custom_header(i)
        raw_dns = bytes(pkt[DNS])
        message = header.encode() + raw_dns

        # Send message
        client.send(message)

        # Receive response
        response = client.recv(1024).decode()
        print(f"[RESPONSE] {response}")
        results.append(response)

    client.close()

    # Save results to a log file
    with open("client_log.txt", "w") as f:
        for line in results:
            f.write(line + "\n")

    print("[+] Results saved in client_log.txt")


if __name__ == "__main__":
    # Example: python client.py X.pcap
    import sys
    if len(sys.argv) < 2:
        print("Usage: python client.py <pcap_file>")
    else:
        run_client(sys.argv[1])