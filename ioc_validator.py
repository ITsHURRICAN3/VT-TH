import re

def validate_ioc(ioc: str) -> bool:
    ioc = ioc.strip()

    # IPv4
    ipv4_re = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.|$)){4}$")
    # Dominio (esempio semplice: almeno un punto, caratteri validi)
    domain_re = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.[A-Za-z]{2,})+$"
    )
    # MD5: 32 esadecimali
    md5_re = re.compile(r"^[A-Fa-f0-9]{32}$")
    # SHA1: 40 esadecimali
    sha1_re = re.compile(r"^[A-Fa-f0-9]{40}$")
    # SHA256: 64 esadecimali
    sha256_re = re.compile(r"^[A-Fa-f0-9]{64}$")

    if ipv4_re.match(ioc):
        return True
    if domain_re.match(ioc):
        return True
    if md5_re.match(ioc):
        return True
    if sha1_re.match(ioc):
        return True
    if sha256_re.match(ioc):
        return True
    return False