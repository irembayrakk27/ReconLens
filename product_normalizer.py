import re


# modules/product_normalizer.py

NORMALIZATION_MAP = {
    "simplehttp": "python http.server",
    "python http server": "python http.server",
    "python http.server": "python http.server",

    "apache": "apache http server",
    "apache2": "apache http server",
    "httpd": "apache http server",

    "openssh": "openssh",
    "ssh": "openssh",

    "nginx": "nginx",

    "microsoft-iis": "microsoft iis",
    "iis": "microsoft iis",

    "lighttpd": "lighttpd",

    "tomcat": "apache tomcat",
    "apache tomcat": "apache tomcat",

    "jetty": "jetty",

    "mysql": "mysql",

    "mariadb": "mariadb",

    "postgresql": "postgresql",
    "postgres": "postgresql",

    "redis": "redis",

    "mongodb": "mongodb",

    "vsftpd": "vsftpd",

    "proftpd": "proftpd",

    "pure-ftpd": "pure-ftpd",

    "filezilla": "filezilla server",

    "bind": "bind",

    "dnsmasq": "dnsmasq",

    "samba": "samba",

    "docker": "docker",

    "jenkins": "jenkins",

    "grafana": "grafana",

    "elasticsearch": "elasticsearch",

    "kibana": "kibana"
}



def normalize_product(product: str) -> str:
    """
    Normalize product names before CVE search.
    """

    if not product:
        return ""

    product = product.lower().strip()

    # Versiyon bilgisini kaldır
    product = re.sub(r'[_/\-]?\d+(\.\d+)*', '', product)

    # Fazla boşlukları temizle
    product = " ".join(product.split())

    return NORMALIZATION_MAP.get(product, product)