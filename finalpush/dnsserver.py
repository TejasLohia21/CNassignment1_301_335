import socket

# Server configuration
SERVER_IP = '0.0.0.0'  # Listen on all interfaces
SERVER_PORT = 12345
BUFFER_SIZE = 1024
ip_list =[
"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
"192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
"192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

def classify_time(hour):
    if 4 <= hour < 12:
        return 0
    elif 12 <= hour <= 20:
        return 5
    else:
        return 10

def main():
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, SERVER_PORT))

    print(f"UDP server listening on {SERVER_IP}:{SERVER_PORT}")

    while True:
        # Receive message from client
        data, client_addr = sock.recvfrom(BUFFER_SIZE)
        message = data.decode()
        print(f"Received from {client_addr}: {message}")

        uint16_bytes = data[0:2]
        
        hour = int.from_bytes(uint16_bytes, byteorder='little')
        ip_index=classify_time(hour)
        print(ip_index)

        uint16_bytes=data[6:8]
        seq_id=int.from_bytes(uint16_bytes, byteorder='little')%5
        print(seq_id)   
        
        index=ip_index+seq_id
        # Prepare reply 
        reply = ip_list[index]
        print(index," : ",reply)
        #reply = "Message received"
        sock.sendto(reply.encode(), client_addr)
        print(f"Reply sent to {client_addr}\n")

if __name__ == "__main__":
    main()
