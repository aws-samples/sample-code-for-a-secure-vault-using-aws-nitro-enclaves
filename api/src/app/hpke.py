"""
Implementation of RFC9180 using cryptography.io.

Author: Joseph Birr-Pixton
License: Apache License 2.0
https://github.com/ctz/hpke-py
"""

import struct
import enum
from typing import Any, Tuple, Callable, Type

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding


def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    return bytes([a1 ^ a2 for (a1, a2) in zip(b1, b2)])


class Mode(enum.Enum):
    BASE = 0
    PSK = 1
    AUTH = 2
    AUTH_PSK = 3


class _HKDF:
    ID: int = 0
    HASH: Any = None

    @classmethod
    def _hkdf_extract(cls, salt: bytes, ikm: bytes) -> bytes:
        hctx = hmac.HMAC(salt, cls.HASH, backend=default_backend())
        hctx.update(ikm)
        return hctx.finalize()

    @classmethod
    def _hkdf_expand(cls, prk: bytes, info: bytes, length: int) -> bytes:
        t_n_minus_1 = b""
        n = 1
        data = b""

        assert length <= 255 * cls.HASH.digest_size

        while len(data) < length:
            hctx = hmac.HMAC(prk, cls.HASH, backend=default_backend())
            hctx.update(t_n_minus_1 + info + n.to_bytes(1, byteorder="big"))
            t_n_minus_1 = hctx.finalize()
            data += t_n_minus_1
            n += 1

        return data[:length]

    @classmethod
    def labeled_extract(cls, salt: bytes, label: bytes, ikm: bytes, suite_id: bytes) -> bytes:
        labeled_ikm = b"HPKE-v1" + suite_id + label + ikm
        return cls._hkdf_extract(salt, labeled_ikm)

    @classmethod
    def labeled_expand(cls, prk: bytes, label: bytes, info: bytes, length: int, suite_id: bytes) -> bytes:
        if length == 0:
            return b""

        labeled_info = struct.pack(">H", length) + b"HPKE-v1" + suite_id + label + info
        return cls._hkdf_expand(prk, labeled_info, length)


class HKDF_SHA256(_HKDF):
    ID = 0x0001
    HASH = hashes.SHA256()


class HKDF_SHA384(_HKDF):
    ID = 0x0002
    HASH = hashes.SHA384()


class HKDF_SHA512(_HKDF):
    ID = 0x0003
    HASH = hashes.SHA512()


class _DHKEMWeierstrass:
    ID: int = 0
    KDF: Any = None
    CURVE: Any = None
    NSECRET: int = 0

    @classmethod
    def _encode_public_key(cls, pubkey: ec.EllipticCurvePublicKey) -> bytes:
        return pubkey.public_bytes(encoding=Encoding.X962, format=PublicFormat.UncompressedPoint)

    @classmethod
    def _extract_and_expand(cls, dh: bytes, kem_context: bytes, N: int) -> bytes:
        suite_id = b"KEM" + struct.pack(">H", cls.ID)
        eae_prk = cls.KDF.labeled_extract(b"", b"eae_prk", dh, suite_id=suite_id)
        shared_secret = cls.KDF.labeled_expand(eae_prk, b"shared_secret", kem_context, N, suite_id=suite_id)
        return shared_secret

    @classmethod
    def encap(cls, peer_pubkey: ec.EllipticCurvePublicKey) -> Tuple[bytes, bytes]:
        our_priv = ec.generate_private_key(cls.CURVE, backend=default_backend())
        shared_key = our_priv.exchange(ec.ECDH(), peer_pubkey)

        enc = cls._encode_public_key(our_priv.public_key())

        kem_context = enc + cls._encode_public_key(peer_pubkey)
        shared_secret = cls._extract_and_expand(shared_key, kem_context, cls.NSECRET)
        return shared_secret, enc

    @classmethod
    def decap(cls, enc: bytes, our_privatekey: ec.EllipticCurvePrivateKey) -> bytes:
        peer_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(cls.CURVE, enc)

        shared_key = our_privatekey.exchange(ec.ECDH(), peer_pubkey)
        kem_context = enc + cls._encode_public_key(our_privatekey.public_key())
        shared_secret = cls._extract_and_expand(shared_key, kem_context, cls.NSECRET)
        return shared_secret

    @classmethod
    def auth_encap(
        cls,
        peer_pubkey: ec.EllipticCurvePublicKey,
        our_privatekey: ec.EllipticCurvePrivateKey,
    ) -> Tuple[bytes, bytes]:
        our_ephem = ec.generate_private_key(cls.CURVE, backend=default_backend())
        shared_key = our_ephem.exchange(ec.ECDH(), peer_pubkey) + our_privatekey.exchange(ec.ECDH(), peer_pubkey)

        enc = cls._encode_public_key(our_ephem.public_key())

        kem_context = enc + cls._encode_public_key(peer_pubkey) + cls._encode_public_key(our_privatekey.public_key())
        shared_secret = cls._extract_and_expand(shared_key, kem_context, cls.NSECRET)
        return shared_secret, enc

    @classmethod
    def auth_decap(
        cls,
        enc: bytes,
        our_privatekey: ec.EllipticCurvePrivateKey,
        peer_pubkey_static: ec.EllipticCurvePublicKey,
    ) -> bytes:
        peer_pubkey_ephem = ec.EllipticCurvePublicKey.from_encoded_point(cls.CURVE, enc)
        shared_key = our_privatekey.exchange(ec.ECDH(), peer_pubkey_ephem) + our_privatekey.exchange(
            ec.ECDH(), peer_pubkey_static
        )

        kem_context = (
            enc + cls._encode_public_key(our_privatekey.public_key()) + cls._encode_public_key(peer_pubkey_static)
        )

        shared_secret = cls._extract_and_expand(shared_key, kem_context, cls.NSECRET)
        return shared_secret

    @classmethod
    def decode_private_key(cls, scalar: bytes, public_key_bytes: bytes) -> ec.EllipticCurvePrivateKey:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(cls.CURVE, public_key_bytes)
        private_key = ec.EllipticCurvePrivateNumbers(
            int.from_bytes(scalar, "big"), public_key.public_numbers()
        ).private_key(backend=default_backend())
        return private_key

    @classmethod
    def decode_public_key(cls, public_key: bytes) -> ec.EllipticCurvePublicKey:
        """
        Decodes a public key (encoded in bytes, X9.62 uncompressed format) and
        returns an ec.EllipticCurvePublicKey.
        """
        return ec.EllipticCurvePublicKey.from_encoded_point(cls.CURVE, public_key)

    @classmethod
    def generate_private_key(cls) -> ec.EllipticCurvePrivateKey:
        return ec.generate_private_key(cls.CURVE, backend=default_backend())


class DHKEM_P256_HKDF_SHA256(_DHKEMWeierstrass):
    CURVE = ec.SECP256R1()
    KDF = HKDF_SHA256
    NSECRET = 32
    ID = 0x0010


class DHKEM_P384_HKDF_SHA384(_DHKEMWeierstrass):
    CURVE = ec.SECP384R1()
    KDF = HKDF_SHA384
    NSECRET = 48
    ID = 0x0011


class DHKEM_P521_HKDF_SHA512(_DHKEMWeierstrass):
    CURVE = ec.SECP521R1()
    KDF = HKDF_SHA512
    NSECRET = 64
    ID = 0x0012


class _BaseAEAD:
    NK: int = 0
    NN: int = 0
    ID: int = 0

    def __init__(self, key: bytes, nonce: bytes):
        self.key = key
        self.nonce = nonce
        self.seq = 0
        assert len(self.key) == self.NK
        assert len(self.nonce) == self.NN

    def _next_nonce(self):
        nonce = xor_bytes(self.nonce, self.seq.to_bytes(self.NN, byteorder="big"))
        self.seq += 1
        return nonce

    def seal(self, aad: bytes, message: bytes) -> bytes:
        """abstract"""

    def open(self, aad: bytes, ciphertext: bytes) -> bytes:
        """abstract"""


class _AES_GCM(_BaseAEAD):
    def seal(self, aad: bytes, message: bytes) -> bytes:
        ctx = aead.AESGCM(self.key)
        return ctx.encrypt(self._next_nonce(), message, aad)

    def open(self, aad: bytes, ciphertext: bytes) -> bytes:
        ctx = aead.AESGCM(self.key)
        return ctx.decrypt(self._next_nonce(), ciphertext, aad)


class _AES_128_GCM(_AES_GCM):
    NK = 16
    NN = 12
    ID = 0x0001


class _AES_256_GCM(_AES_GCM):
    NK = 32
    NN = 12
    ID = 0x0002


class _ChaCha20Poly1305(_BaseAEAD):
    NK = 32
    NN = 12
    ID = 0x0003

    def seal(self, aad: bytes, message: bytes) -> bytes:
        return aead.ChaCha20Poly1305(self.key).encrypt(self._next_nonce(), message, aad)

    def open(self, aad: bytes, ciphertext: bytes) -> bytes:
        return aead.ChaCha20Poly1305(self.key).decrypt(self._next_nonce(), ciphertext, aad)


class _ExportOnlyAEAD(_BaseAEAD):
    """
    The export-only AEAD.

    This has the same interface as (eg) AES_128_GCM but refuses
    to seal() or open().
    """

    NK = 0
    NN = 0
    ID = 0xFFFF

    def __init__(self, _key: bytes, _nonce: bytes):
        pass

    def seal(self, aad: bytes, message: bytes) -> bytes:
        raise NotImplementedError()

    def open(self, aad: bytes, ciphertext: bytes) -> bytes:
        raise NotImplementedError()


class Context:
    def __init__(self, aead: Any, export: Callable[[bytes, int], bytes]):
        self.aead = aead
        self.export = export


class _Suite:
    KEM: Any = None
    KDF: Any = None
    AEAD: Type[_BaseAEAD] = _BaseAEAD

    @classmethod
    def _key_schedule(cls, mode: Mode, shared_secret: bytes, info: bytes) -> Context:
        suite_id = b"HPKE" + struct.pack(">HHH", cls.KEM.ID, cls.KDF.ID, cls.AEAD.ID)

        psk_id_hash = cls.KDF.labeled_extract(b"", b"psk_id_hash", b"", suite_id)
        info_hash = cls.KDF.labeled_extract(b"", b"info_hash", info, suite_id)
        key_schedule_context = bytes([mode.value]) + psk_id_hash + info_hash

        secret = cls.KDF.labeled_extract(shared_secret, b"secret", b"", suite_id)

        key = cls.KDF.labeled_expand(secret, b"key", key_schedule_context, cls.AEAD.NK, suite_id)
        base_nonce = cls.KDF.labeled_expand(secret, b"base_nonce", key_schedule_context, cls.AEAD.NN, suite_id)

        exporter_secret = cls.KDF.labeled_expand(
            secret, b"exp", key_schedule_context, cls.KDF.HASH.digest_size, suite_id
        )

        def exporter(exporter_context: bytes, length: int) -> bytes:
            return cls.KDF.labeled_expand(exporter_secret, b"sec", exporter_context, length, suite_id)

        return Context(aead=cls.AEAD(key, base_nonce), export=exporter)

    @classmethod
    def _setup_base_send(cls, peer_pubkey: ec.EllipticCurvePublicKey, info: bytes) -> Tuple[bytes, Context]:
        shared_secret, encap = cls.KEM.encap(peer_pubkey)
        return encap, cls._key_schedule(Mode.BASE, shared_secret, info)

    @classmethod
    def _setup_base_recv(cls, encap: bytes, our_privatekey: ec.EllipticCurvePrivateKey, info: bytes) -> Context:
        shared_secret = cls.KEM.decap(encap, our_privatekey)
        return cls._key_schedule(Mode.BASE, shared_secret, info)

    @classmethod
    def _setup_auth_send(
        cls,
        peer_pubkey: ec.EllipticCurvePublicKey,
        info: bytes,
        our_privatekey: ec.EllipticCurvePrivateKey,
    ) -> Tuple[bytes, Context]:
        shared_secret, encap = cls.KEM.auth_encap(peer_pubkey, our_privatekey)
        return encap, cls._key_schedule(Mode.AUTH, shared_secret, info)

    @classmethod
    def _setup_auth_recv(
        cls,
        encap: bytes,
        our_privatekey: ec.EllipticCurvePrivateKey,
        info: bytes,
        peer_pubkey: ec.EllipticCurvePublicKey,
    ) -> Context:
        shared_secret = cls.KEM.auth_decap(encap, our_privatekey, peer_pubkey)
        return cls._key_schedule(Mode.AUTH, shared_secret, info)

    @classmethod
    def setup_send(cls, peer_pubkey: ec.EllipticCurvePublicKey, info: bytes) -> Tuple[bytes, Context]:
        """
        Streaming encryption API in Base mode.

        `peer_pubkey` is the peer's public key, of type
          `ec.EllipticCurvePublicKey'.
        `info` is any identity information for the receiver, of type `bytes`.

        Returns `(encap, context)`, where `encap` is of type `bytes`,
        and `context` is of type `Context`.
        """
        return cls._setup_base_send(peer_pubkey, info)

    @classmethod
    def setup_recv(cls, encap: bytes, our_privatekey: ec.EllipticCurvePrivateKey, info: bytes) -> Context:
        """
        Streaming decryption API in Base mode.

        `encap` is the encapsulated key from the sender, of type `bytes`.
        `our_privatekey` is the receiver's private key, of type
          `ec.EllipticCurvePrivateKey`.
        `info` is any identity information for the receiver, of type `bytes`.

        Returns `context`, of type `Context`.
        """
        return cls._setup_base_recv(encap, our_privatekey, info)

    @classmethod
    def setup_auth_send(
        cls,
        peer_pubkey: ec.EllipticCurvePublicKey,
        info: bytes,
        our_privatekey: ec.EllipticCurvePrivateKey,
    ) -> Tuple[bytes, Context]:
        """
        Streaming encryption API in Auth mode.

        `peer_pubkey` is the peer's public key, of type
          `ec.EllipticCurvePublicKey'.
        `info` is any identity information for the receiver, of type `bytes`.
        `our_privatekey` is sender's private key, of type
          `ec.EllipticCurvePrivateKey`.

        Returns `(encap, context)`, where `encap` is of type `bytes`,
        and `context` is of type `Context`.
        """
        return cls._setup_auth_send(peer_pubkey, info, our_privatekey)

    @classmethod
    def setup_auth_recv(
        cls,
        encap: bytes,
        our_privatekey: ec.EllipticCurvePrivateKey,
        info: bytes,
        peer_pubkey: ec.EllipticCurvePublicKey,
    ) -> Context:
        """
        Streaming decryption API in Auth mode.

        `encap` is the encapsulated key from the sender, of type `bytes`.
        `our_privatekey` is the receiver's private key, of type
          `ec.EllipticCurvePrivateKey`.
        `info` is any identity information for the receiver, of type `bytes`.
        `peer_pubkey` is the sender's public key, of type
          `ec.EllipticCurvePublicKey`.

        Returns `context`, of type `Context`.
        """
        return cls._setup_auth_recv(encap, our_privatekey, info, peer_pubkey)

    # -- Base mode --
    @classmethod
    def seal(
        cls,
        peer_pubkey: ec.EllipticCurvePublicKey,
        info: bytes,
        aad: bytes,
        message: bytes,
    ) -> Tuple[bytes, bytes]:
        """
        Single-shot encryption API in Base mode.

        `peer_pubkey` is the peer's public key, of type
          `ec.EllipticCurvePublicKey'.
        `info` is any identity information for the receiver.
        `aad` is any additional authenticated data for the AEAD.
        `message` is the message plaintext.

        `info`, `aad`, and `message` arguments are of type `bytes`.

        Returns `(encap, ciphertext)`, both of type `bytes`.
        """
        encap, ctx = cls._setup_base_send(peer_pubkey, info)
        ciphertext = ctx.aead.seal(aad, message)
        return encap, ciphertext

    @classmethod
    def open(
        cls,
        encap: bytes,
        our_privatekey: ec.EllipticCurvePrivateKey,
        info: bytes,
        aad: bytes,
        ciphertext: bytes,
    ) -> bytes:
        """
        Single-shot decryption API in Base mode.

        `encap` is the encapsulated key from the sender.
        `our_privatekey` is the receiver's private key, of type
          `ec.EllipticCurvePrivateKey`.
        `info` is any identity information for the receiver.
        `aad` is any additional authenticated data for the AEAD.
        `ciphertext` is the message ciphertext.

        `encap`, `info`, `aad`, and `ciphertext` arguments are of
        type `bytes`.

        Returns `plaintext` of type `bytes`.

        Raises `cryptography.exceptions.InvalidTag` if any of the
        arguments are corrupt.
        """
        ctx = cls._setup_base_recv(encap, our_privatekey, info)
        return ctx.aead.open(aad, ciphertext)

    # -- Auth mode --
    @classmethod
    def seal_auth(
        cls,
        peer_pubkey: ec.EllipticCurvePublicKey,
        our_privatekey: ec.EllipticCurvePrivateKey,
        info: bytes,
        aad: bytes,
        message: bytes,
    ) -> Tuple[bytes, bytes]:
        """
        Single-shot encryption API in Auth mode.

        `peer_pubkey` is the peer's public key, of type
          `ec.EllipticCurvePublicKey'.
        `our_privatekey` is our (the sender) private key, of type
          `ec.EllipticCurvePrivateKey`.
        `info` is any identity information for the receiver.
        `aad` is any additional authenticated data for the AEAD.
        `message` is the message plaintext.

        `info`, `aad`, and `message` arguments are of type `bytes`.

        Returns `(encap, ciphertext)`, both of type `bytes`.
        """
        encap, ctx = cls._setup_auth_send(peer_pubkey, info, our_privatekey)
        ciphertext = ctx.aead.seal(aad, message)
        return encap, ciphertext

    @classmethod
    def open_auth(
        cls,
        encap: bytes,
        our_privatekey: ec.EllipticCurvePrivateKey,
        peer_pubkey: ec.EllipticCurvePublicKey,
        info: bytes,
        aad: bytes,
        ciphertext: bytes,
    ) -> bytes:
        """
        Single-shot decryption API in Auth mode.

        `encap` is the encapsulated key from the sender.
        `our_privatekey` is the receiver's private key, of type
          `ec.EllipticCurvePrivateKey`.
        `peer_pubkey` is the sender's public key, of type
          `ec.EllipticCurvePublicKey`.
        `info` is any identity information for the receiver.
        `aad` is any additional authenticated data for the AEAD.
        `ciphertext` is the message ciphertext.

        `encap`, `info`, `aad`, and `ciphertext` arguments are of
        type `bytes`.

        Returns `plaintext` of type `bytes`.

        Raises `cryptography.exceptions.InvalidTag` if any of the
        arguments are corrupt.
        """
        ctx = cls._setup_auth_recv(encap, our_privatekey, info, peer_pubkey)
        return ctx.aead.open(aad, ciphertext)


class Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM(_Suite):
    """
    This is DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
    """

    KEM = DHKEM_P256_HKDF_SHA256
    KDF = HKDF_SHA256
    AEAD = _AES_128_GCM


class Suite__DHKEM_P384_HKDF_SHA384__HKDF_SHA384__AES_256_GCM(_Suite):
    """
    This is DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-256-GCM
    """

    KEM = DHKEM_P384_HKDF_SHA384
    KDF = HKDF_SHA384
    AEAD = _AES_256_GCM


class Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA512__AES_128_GCM(_Suite):
    """
    This is DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM
    """

    KEM = DHKEM_P256_HKDF_SHA256
    KDF = HKDF_SHA512
    AEAD = _AES_128_GCM


class Suite__DHKEM_P521_HKDF_SHA512__HKDF_SHA512__AES_256_GCM(_Suite):
    """
    This is DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM
    """

    KEM = DHKEM_P521_HKDF_SHA512
    KDF = HKDF_SHA512
    AEAD = _AES_256_GCM


class Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305(_Suite):
    """
    This is DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
    """

    KEM = DHKEM_P256_HKDF_SHA256
    KDF = HKDF_SHA256
    AEAD = _ChaCha20Poly1305


class Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ExportOnly(_Suite):
    """
    This is DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ExportOnly
    """

    KEM = DHKEM_P256_HKDF_SHA256
    KDF = HKDF_SHA256
    AEAD = _ExportOnlyAEAD


class Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA512__ExportOnly(_Suite):
    """
    This is DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, ExportOnly
    """

    KEM = DHKEM_P256_HKDF_SHA256
    KDF = HKDF_SHA512
    AEAD = _ExportOnlyAEAD
