from bitstring import BitArray
from Crypto.Cipher import DES, DES3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class LocalDUKPTServer:
    def __init__(self, bdk: bytes):
        if len(bdk) != 16:
            raise ValueError("BDK must be exactly 16 bytes")
        self._bdk = BitArray(bytes=bdk)

    @staticmethod
    def _reset_counter(data):
        if isinstance(data, BitArray):
            data = data.bytes
        if len(data) < 3:
            raise ValueError("KSN must contain at least 3 bytes")

        mask = BitArray(hex="0xe00000")
        ctr = BitArray(bytes=data[-3:])
        return BitArray(bytes=data[:-3] + (mask & ctr).bytes)

    @staticmethod
    def _copy_counter(data):
        mask = BitArray(hex="0x1fffff")
        ctr = BitArray(bytes=data.bytes[-3:]) if len(data.bytes) > 3 else data
        return mask & ctr

    def _generate_ipek(self, ksn):
        ksn = self._reset_counter(ksn)
        tdes_key = self._bdk.bytes + self._bdk.bytes[:8]
        cipher = DES3.new(tdes_key, DES3.MODE_ECB)
        left = BitArray(bytes=cipher.encrypt(ksn.bytes[:8]))

        mask = BitArray(hex="0xc0c0c0c000000000c0c0c0c000000000c0c0c0c000000000")
        key = BitArray(bytes=tdes_key) ^ mask
        cipher2 = DES3.new(key.bytes, DES3.MODE_ECB)
        right = BitArray(bytes=cipher2.encrypt(ksn.bytes[:8]))
        return left.bytes + right.bytes

    def _derive_key(self, ipek, ksn):
        c_mask = BitArray(hex="0xc0c0c0c000000000c0c0c0c000000000")
        ksn_offset = 2
        curkey = BitArray(bytes=ipek)
        ksnr = BitArray(bytes=ksn[ksn_offset:])
        r3 = self._copy_counter(ksnr)
        r8 = self._reset_counter(ksn[ksn_offset:])
        sr = BitArray(hex="0x000100")

        while not (
            sr.bytes[0:1] == b"\x00"
            and sr.bytes[1:2] == b"\x00"
            and sr.bytes[2:3] == b"\x00"
        ):
            tmp = self._copy_counter(sr) & r3
            if not (
                tmp.bytes[0:1] == b"\x00"
                and tmp.bytes[1:2] == b"\x00"
                and tmp.bytes[2:3] == b"\x00"
            ):
                n_ctr = BitArray(bytes=r8.bytes[-3:]) | sr
                r8 = BitArray(bytes=r8.bytes[:-3] + n_ctr.bytes)
                right = BitArray(bytes=curkey.bytes[8:])
                r8a = r8 ^ right
                r8a = BitArray(bytes=DES.new(curkey.bytes[:8], DES.MODE_ECB).encrypt(r8a.bytes))
                r8a = right ^ r8a

                curkey = curkey ^ c_mask
                r8b = BitArray(bytes=curkey.bytes[8:]) ^ r8
                r8b = BitArray(bytes=DES.new(curkey.bytes[:8], DES.MODE_ECB).encrypt(r8b.bytes))
                r8b = BitArray(bytes=curkey.bytes[8:]) ^ r8b
                curkey = BitArray(bytes=r8b.bytes + r8a.bytes)
            sr >>= 1

        return curkey.bytes

    def gen_key(self, ksn):
        if isinstance(ksn, str):
            ksn = bytes.fromhex(ksn)
        elif isinstance(ksn, BitArray):
            ksn = ksn.bytes

        ipek = self._generate_ipek(ksn)
        return self._derive_key(ipek, ksn)


def decrypt_bonus_dukpt(bdk: bytes):
    ksn_hex = "729C77361E9A51E000F2"
    ciphertext_hex = "FCC832A91953151148E86A01BE9420AC"
    future_key = LocalDUKPTServer(bdk).gen_key(ksn_hex)
    cipher = Cipher(algorithms.TripleDES(future_key), modes.ECB())
    decryptor = cipher.decryptor()
    plaintext_bytes = decryptor.update(bytes.fromhex(ciphertext_hex)) + decryptor.finalize()
    return future_key, plaintext_bytes


def run_bonus_dukpt(bdk: bytes):
    try:
        future_key, plaintext_bytes = decrypt_bonus_dukpt(bdk)

        print(f"\n[+] BONUS DUKPT - Mensaje en claro descifrado (Hex): {plaintext_bytes.hex()}")
        try:
            decoded = plaintext_bytes.rstrip(b'\x00').decode('utf-8')
            print(f"[+] BONUS DUKPT - Mensaje decodificado (UTF-8): {decoded}")
        except Exception:
            pass

    except Exception as exc:
        print(f"\n[-] BONUS DUKPT omitido: la biblioteca instalada no soporta esta derivación correctamente ({type(exc).__name__}: {exc})")
