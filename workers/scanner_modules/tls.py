import ssl
import socket

host = "google.com"
port = 443

context = ssl.create_default_context()

sock = socket.create_connection((host, port))
tls_sock = context.wrap_socket(sock, server_hostname=host)

print(tls_sock.version())

tls_sock.close()