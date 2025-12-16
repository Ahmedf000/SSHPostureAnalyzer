import socket

IP = '192.168.5.12'
PRT = 22
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((IP, PRT))
sock.listen(1)

connection, address = sock.accept()
data = connection.recv(1024).decode()


