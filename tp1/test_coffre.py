
import pytest
from cryptography.exceptions import InvalidTag

from coffre import chiffrer, dechiffrer

MDP = "mot-de-passe-de-test"   # fictif, jamais un vrai mot de passe
NOM = "note.txt"
DONNEES = b"contenu secret du fichier de test"

def test_aller_retour():
    blob = chiffrer(MDP, NOM, DONNEES)
    assert dechiffrer(MDP, NOM, blob) == DONNEES

def test_deux_chiffrements_differents():
    blob1 = chiffrer(MDP, NOM, DONNEES)
    blob2 = chiffrer(MDP, NOM, DONNEES)
    assert blob1 != blob2
    assert blob1[16:32] != blob2[16:32]   # sels différents
    assert blob1[32:44] != blob2[32:44]   # nonces différents

def test_mauvais_mot_de_passe():
    blob = chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        dechiffrer("mauvais-mot-de-passe", NOM, blob)


def test_octet_modifie():
    blob = chiffrer(MDP, NOM, DONNEES)
    b = bytearray(blob)
    b[60] ^= 0x01
    corrompu = bytes(b)
    assert corrompu != blob   # garde-fou : on a bien modifié quelque chose
    with pytest.raises(InvalidTag):
        dechiffrer(MDP, NOM, corrompu)


def test_nom_echange():
    blob = chiffrer(MDP, "a.txt", DONNEES)
    # Garde-fou : avec le bon nom, ça marche
    assert dechiffrer(MDP, "a.txt", blob) == DONNEES
    # Avec un autre nom : rejet
    with pytest.raises(InvalidTag):
        dechiffrer(MDP, "b.txt", blob)
