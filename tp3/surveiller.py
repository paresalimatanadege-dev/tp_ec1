#!/usr/bin/env python3
"""Supervision des dates d'expiration des certificats d'un dossier.

Usage : python3 surveiller.py [dossier]
Code de sortie : 0 = OK, 1 = au moins une ALERTE, 2 = au moins un CRITIQUE.
"""
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

SEUIL_ALERTE = 30    # jours
SEUIL_CRITIQUE = 7   # jours
NIVEAUX = ["OK", "ALERTE", "CRITIQUE"]
BLOC_PEM = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)


def date_fin(cert):
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # version plus ancienne de cryptography
        return cert.not_valid_after.replace(tzinfo=timezone.utc)


def niveau(jours):
    if jours < SEUIL_CRITIQUE:
        return 2
    if jours < SEUIL_ALERTE:
        return 1
    return 0


def main():
    dossier = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    maintenant = datetime.now(timezone.utc)
    pire = 0
    trouves = 0
    for fichier in sorted(dossier.iterdir()):
        if not fichier.is_file() or fichier.suffix not in (".crt", ".pem"):
            continue
        for bloc in BLOC_PEM.findall(fichier.read_bytes()):
            cert = x509.load_pem_x509_certificate(bloc)
            jours = (date_fin(cert) - maintenant).days
            n = niveau(jours)
            pire = max(pire, n)
            trouves += 1
            sujet = cert.subject.rfc4514_string()
            print(f"{NIVEAUX[n]:<9} {jours:>5} j  {fichier.name}  {sujet}")
    if trouves == 0:
        print(f"Aucun certificat trouvé dans {dossier}", file=sys.stderr)
        return 2
    return pire


if __name__ == "__main__":
    sys.exit(main())
