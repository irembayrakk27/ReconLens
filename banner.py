import socket
import time


def grab_banner(ip, port):

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, port))

        # HTTP ports
        if port in [80, 8080, 8000]:

            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            s.send(request.encode())
            
        time.sleep(0.2)

        data = b""

        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass

        s.close()

        return data.decode(errors="ignore") if data else None
        

        banner = s.recv(4096)
        s.close()

        return banner.decode(errors="ignore")

    except Exception:
        return None


def extract_server_header(response):

    if not response:
        return "Unknown"

    lines = response.split("\n")

    for line in lines:
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()

    return "Unknown"