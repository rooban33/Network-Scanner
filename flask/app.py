from flask import Flask, jsonify, send_file, request
import os
import time
from scapy.all import ARP, Ether, srp
import socket
import speedtest

app = Flask(__name__)

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

def get_device_name_from_ip(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return "Unknown"
def measure_network_speed():
    st = speedtest.Speedtest()
    st.get_best_server()
    
    download_speed = st.download()
    upload_speed = st.upload()

    return download_speed, upload_speed

@app.route('/scan')
def scan():
    ip_range = "192.168.139.1/24"
    devices_found = scan_network(ip_range)

    formatted_devices = []
    for device in devices_found:
        formatted_devices.append({
            'ip': device['ip'],
            'mac': device['mac'],
            'name': get_device_name_from_ip(device['ip'])
        })

    return jsonify({'devices': formatted_devices})

'''def measure_network_speed():
    # Retry speed measurement up to 3 times in case of failure
    attempts = 3
    for attempt in range(attempts):
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            download_speed = st.download()
            upload_speed = st.upload()
            return download_speed, upload_speed
        except speedtest.ConfigRetrievalError as e:
            if attempt < attempts - 1:
                # Retry after a short delay (e.g., 1 second)
                time.sleep(1)
                continue
            else:
                return None, None'''
            
@app.route('/speed')
def speed():
    st = speedtest.Speedtest() 
    down =st.download()
    up=st.upload()

    if down is None or up is None:
        return jsonify({'error': 'Failed to retrieve network speed'})
    else:
        nspeed = [{'up': up, 'down': down}]
        return jsonify({'devices': nspeed})

@app.route('/send-image', methods=['POST'])
def send_image():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    target_ip = request.headers.get('Target-IP')

    # Create a socket to send the image
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, 12345))  # Port number for communication (change as needed)

    # Read and send the image in chunks
    while True:
        image_chunk = file.read(4096)  # Read 4KB chunks of the image file
        if not image_chunk:
            break
        s.sendall(image_chunk)

    s.close()

    return jsonify({'message': 'Image sent successfully'})

@app.route('/receive-image', methods=['POST'])
def receive_image():
    host = '0.0.0.0'  # Use '0.0.0.0' to listen on all available interfaces
    port = 12345  # Use the same port number used by the server

    # Create a socket to listen for incoming connections
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)  # Listen for one incoming connection

    print(f"Waiting for connection on port {port}...")
    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")

    # Receive and save the image
    received_image = b''  # Initialize an empty byte string to store the image data
    while True:
        image_chunk = client_socket.recv(4096)  # Receive 4KB chunks of the image data
        if not image_chunk:
            break
        received_image += image_chunk

    # Save the received image to a file
    with open('received_image.jpg', 'wb') as file:
        file.write(received_image)

    print("Image received and saved as 'received_image.jpg'")

    # Close the sockets
    client_socket.close()
    server_socket.close()


@app.route('/get-received-image')
def get_received_image():
    # Get the path to the received image based on the sender's IP address
    target_ip = request.remote_addr
    received_image_path = f'received_images/received_image_from_{target_ip}.jpg'

    # Check if the received image file exists
    if os.path.exists(received_image_path):
        return send_file(received_image_path, mimetype='image/jpeg')
    else:
        return jsonify({'error': 'Image not found'})



if __name__ == "__main__":
    app.run(debug=True)
