from version_parser import parse_server_info

test_headers = [
    "SimpleHTTP/0.6 Python/3.12.8",
    "Apache/2.4.58",
    "httpd/2.4.58",
    "OpenSSH_9.3",
    "nginx/1.25.3",
    "Redis/7.2.0"
]

for header in test_headers:
    result = parse_server_info(header)

    print("-" * 40)
    print("Header :", header)
    print("Product:", result["product"])
    print("Version:", result["version"])
