import subprocess


def run_nmap(target):
    print(f"[+] Running Nmap scan on {target}...")

    result = subprocess.run(
        ["nmap", "-sS", "-sV", "-T4", target],
        capture_output=True,
        text=True
    )

    return result.stdout


def parse_nmap_output(output):
    ports = []

    for line in output.split("\n"):

        # sadece port satırlarını yakala
        if "/tcp" in line and "open" in line:

            parts = line.split()

            port = int(parts[0].split("/")[0])
            service = parts[2] if len(parts) > 2 else "unknown"

            # default
            product = service
            version = "unknown"
            extra = ""

            

            if len(parts) > 3:
                product = parts[3]

            if len(parts) > 4:
                version = parts[4]
                extra = " ".join(parts[5:])

            ports.append({
                "port": port,
                "service": service,
                "product": product,
                "version": version,
                "extra": extra
            })

    return ports


def scan_target(target):
    raw_output = run_nmap(target)
    ports = parse_nmap_output(raw_output)

    return {
        "target": target,
        "ports": ports,
        "raw_output": raw_output
    }