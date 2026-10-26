from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

T, M, P = 12, 64 * 1024, 4  # temps, mémoire (Kio), parallélisme


def cle_maitresse(mot_de_passe: str, sel: bytes) -> bytes:
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
