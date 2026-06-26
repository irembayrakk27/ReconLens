from version_parser import parse_server_info

tests = [
    "Apache/2.4.49",
    "nginx/1.18.0",
    "Apache",
    "SimpleHTTP/0.6",
    "Microsoft-IIS/10.0"
]

for t in tests:

    print(parse_server_info(t))