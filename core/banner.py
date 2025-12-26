import socket

def grab_banner(ip, port=22, timeout=5):
    try:
        s = socket.create_connection((ip, port), timeout)
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner
    except Exception as e:
        return None
