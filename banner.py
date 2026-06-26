import socket



def grab_banner(ip, port):

    try:

        s= socket.socket()    

        s.settimeout(3)

        s.connect((ip,port))

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        s.send(request.encode())    #It is sending an HTTP request 

        banner = s.recv(4096)

        s.close()

        return banner.decode(errors="ignore")

    except Exception as e:
        print("ERROR:", e)
        return None    

def extract_server_header(response):

    lines = response.split("\n")

    for line in lines:

        if line.lower().startswith("server:"):

            return line.replace("Server:", "").strip()

    return "Unknown"