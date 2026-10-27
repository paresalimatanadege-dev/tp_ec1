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
