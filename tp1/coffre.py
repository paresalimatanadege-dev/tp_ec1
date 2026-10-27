from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
 
T, M, P = 12, 64 * 1024, 4  # temps, mémoire (Kio), parallélisme


def cle_maitresse(mot_de_passe: str, sel: bytes,t: int = T, m: int = M, p: int = P) -> bytes:
    """Argon2id -> 32 octets."""
    return hash_secret_raw(
        secret=mot_de_passe.encode("utf-8"),
        salt=sel,
        time_cost=T,
        memory_cost=M,
        parallelism=P,
        hash_len=32,
        type=Type.ID,
    )


def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """HKDF-SHA256 avec info = b"coffre-v1|" + usage -> 32 octets."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"coffre-v1|" + usage,
    )
    return hkdf.derive(maitresse)


MAGIC=b"CFR1"

def construire_entete(t:int, m:int, p:int, sel:bytes, nonce: bytes)-> bytes:
	"""Assemble l'en-tête de 44 octets."""
	return MAGIC + struct.pack(">III",t,m,p) + sel +nonce 


def chiffrer(mot_de_passe: str, nom: str, donnees: bytes) -> bytes:
    sel = os.urandom(16)                      # neuf à chaque appel
    nonce = os.urandom(12)                    # neuf à chaque appel
    maitresse = cle_maitresse(mot_de_passe, sel)
    cle = sous_cle(maitresse, b"chiffrement")
    entete = construire_entete(T, M, P, sel, nonce)
    ad = entete + nom.encode("utf-8")         # données associées
    chiffre = AESGCM(cle).encrypt(nonce, donnees, ad)
    return entete + chiffre

def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    if blob[:4] != MAGIC:
        raise ValueError("format inconnu")
    t, m, p = struct.unpack(">III", blob[4:16])
    sel = blob[16:32]
    nonce = blob[32:44]
    entete = blob[:44]
    chiffre = blob[44:]
    maitresse = cle_maitresse(mot_de_passe, sel, t, m, p)
    cle = sous_cle(maitresse, b"chiffrement")
    ad = entete + nom.encode("utf-8")
    return AESGCM(cle).decrypt(nonce, chiffre, ad)

def rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes) -> bytes:
    donnees = dechiffrer(ancien_mdp, nom, blob)
    return chiffrer(nouveau_mdp, nom, donnees)
