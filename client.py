import socket
import ssl

#hostname = '192.168.1.157'
hostname = '71.255.90.82'
port = 8443
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations('certificate.pem')

#with s.create_connection((hostname,port)) as sock:
with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.settimeout(10)
    sock.connect((hostname,port))
    with context.wrap_socket(sock,server_hostname = 'NADGE') as ssock:
        print(ssock.server_hostname)
        print(ssock.version())



'''with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        print(ssock.version())'''
