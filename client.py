import socket
import ssl

hostname = '192.168.1.154'#'71.255.90.82'
port = 8443
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations('certificate.pem')

with socket.create_connection((hostname,port)) as sock:
    with context.wrap_socket(sock,server_hostname = 'NADGE') as ssock:
        print(ssock.version())
