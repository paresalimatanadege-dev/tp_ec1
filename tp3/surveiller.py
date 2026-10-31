"""Alerte d'expiration des certificats d'un dossier (TP 3)."""
import sys, pathlib, datetime
from cryptography import x509

SEUILS = (30, 14, 7)

def jours_restants(cert: x509.Certificate) -> int:
    fin = cert.not_valid_after_utc
    return (fin - datetime.datetime.now(datetime.timezone.utc)).days

def main(dossier: str) -> int:
    code = 0
    for f in sorted(pathlib.Path(dossier).glob("*.crt")):
        cert = x509.load_pem_x509_certificate(f.read_bytes())
        j = jours_restants(cert)
        niveau = "OK"
        if j < 0: niveau, code = "EXPIRE", 2
        elif j <= min(SEUILS): niveau, code = "CRITIQUE", max(code, 2)
        elif j <= max(SEUILS): niveau, code = "ALERTE", max(code, 1)
        print(f"{niveau:8} {j:5d} j  {cert.subject.rfc4514_string()}  ({f.name})")
    return code

if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
