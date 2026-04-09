"""
PaperPhone E2EE Crypto Module

Implements the stateless per-message encryption protocol used by PaperPhone,
mirroring client/src/crypto/ratchet.js exactly.

Protocol (per message):
  Sender:
    1. Generate ephemeral Curve25519 keypair (EK)
    2. sharedKey = KDF( DH(EK_priv, recipient_IK_pub) )
    3. ciphertext = secretbox(plaintext, nonce, sharedKey)
    4. Send { ciphertext: base64(nonce+ct), header: { ek_pub: base64(EK_pub) } }

  Receiver:
    1. sharedKey = KDF( DH(my_IK_priv, EK_pub_from_header) )
    2. plaintext = open_secretbox(ciphertext, nonce, sharedKey)

Uses PyNaCl which wraps libsodium — same library used by PaperPhone's JS client.
"""

import base64
from typing import Optional

import nacl.bindings
import nacl.utils
from nacl.public import PrivateKey


# ── Helpers ──────────────────────────────────────────────────────────────────


def b64encode(data: bytes) -> str:
    """Encode bytes to base64 string (matching JS btoa)."""
    return base64.b64encode(data).decode("ascii")


def b64decode(s: str) -> bytes:
    """Decode base64 string to bytes (matching JS atob)."""
    if not s or not isinstance(s, str):
        raise TypeError(f"b64decode: expected base64 string, got {type(s)}")
    return base64.b64decode(s)


def _concat(*arrays: bytes) -> bytes:
    """Concatenate multiple byte arrays."""
    return b"".join(arrays)


def _kdf(ikm: bytes) -> bytes:
    """
    Key derivation function matching PaperPhone's kdf():
        info = 'PaperPhone-E2EE-v2'
        salt = 32 zero bytes
        return crypto_generichash(32, concat(ikm, info), salt)

    In libsodium's JS API:
        crypto_generichash(outlen, message, key)
    The third argument 'salt' in the JS code is actually the BLAKE2b **key**.
    So: output_size=32, message=ikm+info, key=32_zero_bytes.

    IMPORTANT: Must use crypto_generichash_blake2b (NOT _salt_personal).
    The JS crypto_generichash does NOT use salt/personalization — the
    _salt_personal variant mixes them into the hash state and produces
    a completely different output even when they are all zeros.
    """
    info = b"PaperPhone-E2EE-v2"
    key = bytes(32)  # 32 zero bytes — used as BLAKE2b key
    message = _concat(ikm, info)
    # Matches JS: na.crypto_generichash(32, concat(ikm, info), salt)
    return nacl.bindings.crypto_generichash_blake2b(
        message,
        digest_size=32,
        key=key,
    )


# ── Main Crypto Class ───────────────────────────────────────────────────────


class PaperPhoneCrypto:
    """
    PaperPhone E2EE implementation in Python.

    Mirrors client/src/crypto/ratchet.js using PyNaCl (libsodium bindings).
    """

    def __init__(self):
        self.ik_private: Optional[bytes] = None   # 32-byte Curve25519 private key
        self.ik_public: Optional[bytes] = None    # 32-byte Curve25519 public key
        self.ik_private_b64: Optional[str] = None
        self.ik_public_b64: Optional[str] = None

    # ── Key Generation ───────────────────────────────────────────────────

    def generate_identity_keypair(self) -> tuple[str, str]:
        """
        Generate a Curve25519 identity key pair.
        Stores internally and returns (public_b64, private_b64).

        Mirrors: generateIdentityKeyPair()
        """
        sk = PrivateKey.generate()
        self.ik_private = bytes(sk)
        self.ik_public = bytes(sk.public_key)
        self.ik_private_b64 = b64encode(self.ik_private)
        self.ik_public_b64 = b64encode(self.ik_public)
        return self.ik_public_b64, self.ik_private_b64

    def load_identity_keypair(self, public_b64: str, private_b64: str):
        """Load an existing identity key pair from base64 strings."""
        self.ik_private = b64decode(private_b64)
        self.ik_public = b64decode(public_b64)
        self.ik_private_b64 = private_b64
        self.ik_public_b64 = public_b64

    def generate_signed_prekey(self) -> tuple[str, str, str]:
        """
        Generate a signed pre-key (SPK).
        Returns (spk_pub_b64, spk_priv_b64, sig_b64).

        Mirrors: generateSignedPreKey(ikPrivateKey)
        The "signature" is actually a BLAKE2b hash of (IK_priv || SPK_pub), not
        a real Ed25519 signature. This matches PaperPhone's implementation.
        """
        if self.ik_private is None:
            raise RuntimeError("Identity keypair must be generated first")

        sk = PrivateKey.generate()
        spk_priv = bytes(sk)
        spk_pub = bytes(sk.public_key)

        # "Signature" = BLAKE2b(IK_priv || SPK_pub, digest=64, no key)
        # In JS: na.crypto_generichash(64, concat(ikPrivBytes, kp.publicKey))
        # No key argument = unkeyed BLAKE2b
        sig = nacl.bindings.crypto_generichash_blake2b(
            _concat(self.ik_private, spk_pub),
            digest_size=64,
        )

        return b64encode(spk_pub), b64encode(spk_priv), b64encode(sig)

    def generate_one_time_prekeys(self, count: int = 10) -> list[dict]:
        """
        Generate one-time pre-keys (OPKs).
        Returns list of { "key_id": <int>, "opk_pub": <base64> }.

        We don't need to keep OPK private keys since the bot uses
        stateless per-message ECDH with the identity key.

        Mirrors: generateOneTimePreKey()
        """
        prekeys = []
        for i in range(count):
            sk = PrivateKey.generate()
            prekeys.append({
                "key_id": i,
                "opk_pub": b64encode(bytes(sk.public_key)),
            })
        return prekeys

    def generate_kem_keypair(self) -> str:
        """
        Generate a KEM public key placeholder.
        PaperPhone's ML-KEM-768 is used for post-quantum protection,
        but for the bot adapter we generate a dummy Curve25519 key
        since the actual message crypto only uses ECDH.
        """
        sk = PrivateKey.generate()
        return b64encode(bytes(sk.public_key))

    # ── Encrypt ──────────────────────────────────────────────────────────

    def encrypt(self, recipient_ik_pub_b64: str, plaintext: str) -> dict:
        """
        Encrypt a message for a recipient.

        Args:
            recipient_ik_pub_b64: Recipient's identity public key (base64)
            plaintext: UTF-8 message text

        Returns:
            { "ciphertext": base64(nonce + ct), "header": { "ek_pub": base64 } }

        Mirrors: encryptMessage(recipientIkPub, plaintext)
        """
        recipient_pub = b64decode(recipient_ik_pub_b64)

        # 1. Ephemeral keypair — fresh for every message
        ek_sk = PrivateKey.generate()
        ek_priv = bytes(ek_sk)
        ek_pub = bytes(ek_sk.public_key)

        # 2. ECDH shared secret
        dh = nacl.bindings.crypto_scalarmult(ek_priv, recipient_pub)
        shared_key = _kdf(dh)

        # 3. Encrypt with XSalsa20-Poly1305
        nonce = nacl.utils.random(24)
        plaintext_bytes = plaintext.encode("utf-8")
        ct = nacl.bindings.crypto_secretbox(plaintext_bytes, nonce, shared_key)

        # 4. Return ciphertext = base64(nonce + ct), header = { ek_pub }
        return {
            "ciphertext": b64encode(_concat(nonce, ct)),
            "header": {"ek_pub": b64encode(ek_pub)},
        }

    def encrypt_dual(
        self, recipient_ik_pub_b64: str, sender_ik_pub_b64: str, plaintext: str
    ) -> dict:
        """
        Encrypt for both recipient and sender (for message history).

        Returns:
            { "ciphertext", "header", "self_ciphertext", "self_header" }

        Mirrors: encryptMessageDual(recipientIkPub, senderIkPub, plaintext)
        """
        for_recipient = self.encrypt(recipient_ik_pub_b64, plaintext)
        for_self = self.encrypt(sender_ik_pub_b64, plaintext)
        return {
            "ciphertext": for_recipient["ciphertext"],
            "header": for_recipient["header"],
            "self_ciphertext": for_self["ciphertext"],
            "self_header": for_self["header"],
        }

    # ── Decrypt ──────────────────────────────────────────────────────────

    def decrypt(self, header: dict, ciphertext_b64: str) -> str:
        """
        Decrypt a message.

        Args:
            header: { "ek_pub": base64 } — ephemeral public key from sender
            ciphertext_b64: base64-encoded nonce + ciphertext

        Returns:
            Decrypted plaintext string

        Mirrors: decryptMessage(myIK, header, ciphertextB64)
        """
        if self.ik_private is None:
            raise RuntimeError("Identity keypair must be loaded first")

        if not header or "ek_pub" not in header:
            raise ValueError("Missing ek_pub in header")

        ek_pub = b64decode(header["ek_pub"])

        # 1. ECDH shared secret (mirrors sender's computation)
        dh = nacl.bindings.crypto_scalarmult(self.ik_private, ek_pub)
        shared_key = _kdf(dh)

        # 2. Split nonce (24 bytes) and ciphertext
        raw = b64decode(ciphertext_b64)
        nonce = raw[:24]
        ct = raw[24:]

        # 3. Decrypt
        plaintext_bytes = nacl.bindings.crypto_secretbox_open(ct, nonce, shared_key)
        if plaintext_bytes is None:
            raise RuntimeError("Decryption failed (authentication error)")

        return plaintext_bytes.decode("utf-8")
