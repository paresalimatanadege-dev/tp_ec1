import pytest
from cryptography.exceptions import InvalidTag

from coffre import chiffrer, dechiffrer

MDP = "mot-de-passe-de-test"   # fictif, jamais un vrai mot de passe
NOM = "note.txt"
DONNEES = b"contenu secret du fichier de test"

def test_aller_retour():
    blob = chiffrer(MDP, NOM, DONNEES)
    assert dechiffrer(MDP, NOM, blob) == DONNEES


