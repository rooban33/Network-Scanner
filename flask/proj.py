from scapy.all import ARP, Ether, srp
import socket
from scapy.all import sniff
import speedtest

def get_device_name_from_ip(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return "Unknown"
def send_broadcast_message(message, port):
    # Create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Broadcasting the message to the network
    udp_socket.sendto(message.encode(), ('<broadcast>', port))
    udp_socket.close()

def scan_network(ip_range):
    # Create ARP request packet
    arp = ARP(pdst=ip_range)
    # Create Ethernet frame
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
    # Combine the Ethernet frame and ARP request
    packet = ether / arp

    # Send and receive ARP requests using srp
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    # Extracting information from received responses
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def measure_network_speed():
    st = speedtest.Speedtest()
    st.get_best_server()
    
    download_speed = st.download()
    upload_speed = st.upload()

    return download_speed, upload_speed
def packet_handler(packet):
    # Process packets here
    print(packet.summary())


# Enter the IP range you want to scan
ip_range = "192.168.139.1/24"  # Change this to match your network range

devices_found = scan_network(ip_range)

download, upload = measure_network_speed()

print(f"Download speed: {download / 1024 / 1024:.2f} Mbps")
print(f"Upload speed: {upload / 1024 / 1024:.2f} Mbps")


