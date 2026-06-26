def analyze_ports(results):

    analyzed = []

    for item in results:

        analysis = analyze_port(
            item,
            item.get("server", "Unknown")
        )

        item["risk"] = analysis["risk"]
        item["reason"] = analysis["reason"]

        analyzed.append(item)

    return analyzed


def analyze_port(port_info, server="Unknown"):

    service = port_info["service"]

    if service == "ssh":
        return {
            "risk": "MEDIUM",
            "reason": "SSH service exposed"
        }

    elif service == "http":
        return {
            "risk": "LOW",
            "reason": "Web service detected"
        }

    elif service == "http-proxy":

        if "SimpleHTTP" in server:
            return {
                "risk": "LOW",
                "reason": "Python development web server detected"
            }

        return {
            "risk": "LOW",
            "reason": "HTTP proxy service detected"
        }

    
    
    elif service == "ftp":
        return {
            "risk": "HIGH",
            "reason": "FTP transmits credentials in plaintext"
         }

    elif service == "telnet":
        return {
            "risk": "HIGH",
            "reason": "Telnet is insecure and unencrypted"
        }

    elif service == "mysql":
        return {
            "risk": "MEDIUM",
            "reason": "Database service exposed"
        }

    elif service == "https":
        return {
            "risk": "LOW",
            "reason": "Encrypted web service detected"
        }

    else:
        return {
            "risk": "UNKNOWN",
            "reason": "No rule available"
        }
    

if __name__ == "__main__":

    sample = {
        "port": 8080,
        "service": "http-proxy"
    }

    print(analyze_port(sample))