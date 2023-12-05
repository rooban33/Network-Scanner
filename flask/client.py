import socket

def receive_image():
    # Define the IP address and port to listen on
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

if __name__ == "__main__":
    receive_image()
