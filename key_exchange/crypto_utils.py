import os
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from psec.tr31 import Header, KeyBlock

def xor_components(comp1_hex: str, comp2_hex: str) -> bytes:
    b1 = bytes.fromhex(comp1_hex)
    b2 = bytes.fromhex(comp2_hex)
    if len(b1) != len(b2):
        raise ValueError("Componentes de distinta longitud.")
    return bytes(x ^ y for x, y in zip(b1, b2))

def calculate_cmac_kcv(key: bytes) -> str:
    """Calcula el KCV según el algoritmo de la clave.

    - AES-256: CMAC-AES sobre un bloque de 16 bytes cero, toma los 3 bytes iniciales.
    - TDES/3DES: ECB sobre un bloque de 8 bytes cero, toma los 3 bytes iniciales.
    """
    if len(key) == 32:
        c = cmac.CMAC(algorithms.AES(key))
        c.update(bytes(16))
        return c.finalize()[:3].hex().upper()

    if len(key) in {16, 24}:
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
        encryptor = cipher.encryptor()
        return (encryptor.update(b"\x00" * 8) + encryptor.finalize())[:3].hex().upper()

    raise ValueError(f"Longitud de clave no soportada para KCV: {len(key)} bytes")

def validate_cmac_kcv(key: bytes, expected_kcv: str):
    kcv = calculate_cmac_kcv(key)
    if kcv != expected_kcv.upper():
        raise ValueError(f"Error de validacion KCV. Esperado: {expected_kcv}, Calculado: {kcv}")

def generate_aes256_key() -> bytes:
    return os.urandom(32)

def wrap_tr31(key_to_wrap: bytes, kek: bytes, usage: str = 'P') -> str:
    usage_code = usage.upper()
    if len(usage_code) == 1:
        usage_code = f"{usage_code}0"

    header = Header(
        version_id='D',
        key_usage=usage_code,
        algorithm='A',
        mode_of_use='B',
        version_num='00',
        exportability='E',
    )
    kb = KeyBlock(kbpk=kek, header=header)
    return kb.wrap(key_to_wrap)

def unwrap_tr31(tr31_string: str, kek: bytes) -> bytes:
    kb = KeyBlock(kbpk=kek)
    return kb.unwrap(tr31_string)
