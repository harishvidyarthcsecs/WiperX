# wiperx/core/report_signer.py
"""
Report Signer
-------------
Tamper-evidence for WiperX reports and certificates.

Every machine-readable report (drive wipe, file erase, forensic recovery)
can be wrapped in a signed envelope:

    {
      "payload":   { ... the original report dict ... },
      "signature": {
        "alg":        "Ed25519",
        "value":      "<hex signature over the canonical payload>",
        "public_key": "<hex raw 32-byte Ed25519 public key>",
        "key_id":     "<first 16 hex chars of sha256(public_key)>",
        "signed_at":  "<ISO-8601 UTC>Z"
      }
    }

The canonical form signed and verified is:
    json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

Key material:
  - Private key path comes from env WIPERX_SIGN_KEY, else keys/wiperx_sign_key.pem
  - If the private key file is absent, a new Ed25519 identity is generated,
    written with mode 0600, and its public half is written alongside as
    <name>.pub.pem. A warning is logged - a fresh identity means old
    certificates will not chain to the new key.
  - Verification uses the public key embedded in the envelope. If a trusted
    public key is available (env WIPERX_VERIFY_PUBKEY, else the .pub.pem next
    to the signing key) the embedded key must match it, otherwise the report
    is reported as signed-by-unknown-key.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.exceptions import InvalidSignature

    _CRYPTO_OK = True
except ImportError:  # pragma: no cover - dependency is declared in requirements.txt
    _CRYPTO_OK = False

SIGNATURE_ALG = "Ed25519"
KEYS_DIR = Path(__file__).parent.parent / "keys"
DEFAULT_KEY_PATH = KEYS_DIR / "wiperx_sign_key.pem"


# ---------------------------------------------------------------------------
# Canonicalisation
# ---------------------------------------------------------------------------

def canonical_bytes(payload: dict) -> bytes:
    """
    Deterministically serialise a report payload for signing/verifying.

    Args:
        payload : The report dictionary (JSON-serialisable).

    Returns:
        bytes: Canonical UTF-8 JSON (sorted keys, no whitespace).
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def _require_crypto() -> None:
    if not _CRYPTO_OK:
        raise RuntimeError(
            "The 'cryptography' package is required for report signing. "
            "Install it with: pip install cryptography"
        )


def _private_key_path() -> Path:
    return Path(os.environ.get("WIPERX_SIGN_KEY", str(DEFAULT_KEY_PATH)))


def load_private_key(create_if_missing: bool = True) -> "Ed25519PrivateKey":
    """
    Load the Ed25519 signing key, generating one on first use.

    Args:
        create_if_missing : Generate + persist a new key if the file is absent.

    Returns:
        Ed25519PrivateKey: The loaded (or freshly generated) private key.

    Raises:
        FileNotFoundError : Key absent and create_if_missing is False.
        RuntimeError      : cryptography not installed.
    """
    _require_crypto()
    key_path = _private_key_path()

    if key_path.exists():
        data = key_path.read_bytes()
        return serialization.load_pem_private_key(data, password=None)

    if not create_if_missing:
        raise FileNotFoundError(f"Signing key not found: {key_path}")

    logger.warning(
        "[ReportSigner] No signing key at %s - generating a new Ed25519 identity. "
        "Certificates signed with previous keys will not chain to this one.",
        key_path,
    )
    key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()

    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    # Lock the key to the current user. On POSIX this is chmod 0600; on Windows
    # chmod only flips the read-only bit, so the adapter uses icacls instead.
    try:
        from core.platforms import get_adapter

        get_adapter().protect_key_file(str(key_path))
    except Exception:  # noqa: BLE001 - never fail key generation over perms
        try:
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError:
            pass

    pub_path = key_path.with_suffix(".pub.pem")
    pub_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    logger.info("[ReportSigner] New signing identity written: %s (public: %s)",
                key_path, pub_path)
    return private_key


def _load_trusted_public_key() -> Optional["Ed25519PublicKey"]:
    """Load the operator-trusted public key, if one is configured."""
    candidates = []
    env_pub = os.environ.get("WIPERX_VERIFY_PUBKEY")
    if env_pub:
        candidates.append(Path(env_pub))
    candidates.append(_private_key_path().with_suffix(".pub.pem"))

    for path in candidates:
        if path.exists():
            try:
                return serialization.load_pem_public_key(path.read_bytes())
            except Exception as exc:  # noqa: BLE001 - report and try next candidate
                logger.warning("[ReportSigner] Could not load public key %s: %s", path, exc)
    return None


def _public_key_hex(public_key: "Ed25519PublicKey") -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def key_id(public_key_hex: str) -> str:
    """Short, stable identifier for a public key (first 16 hex of its sha256)."""
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]


def signing_fingerprint() -> str:
    """Return the key_id of the current signing key (generating it if needed)."""
    pub_hex = _public_key_hex(load_private_key().public_key())
    return key_id(pub_hex)


# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------

def sign_payload(payload: dict) -> dict:
    """
    Wrap a report dict in a signed envelope.

    Args:
        payload : The report dictionary to sign.

    Returns:
        dict: {"payload": <payload>, "signature": {...}}
    """
    _require_crypto()
    private_key = load_private_key()
    message = canonical_bytes(payload)
    signature = private_key.sign(message)
    pub_hex = _public_key_hex(private_key.public_key())

    return {
        "payload": payload,
        "signature": {
            "alg": SIGNATURE_ALG,
            "value": signature.hex(),
            "public_key": pub_hex,
            "key_id": key_id(pub_hex),
            "signed_at": datetime.utcnow().isoformat() + "Z",
        },
    }


def write_signed_json(payload: dict, out_path: "os.PathLike | str") -> Path:
    """
    Sign `payload` and write the envelope as indented JSON.

    Args:
        payload  : The report dictionary to sign.
        out_path : Destination file path.

    Returns:
        Path: The written file path.
    """
    envelope = sign_payload(payload)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(envelope, handle, indent=2)
    logger.info("[ReportSigner] Signed report written: %s (key_id=%s)",
                out_path, envelope["signature"]["key_id"])
    return out_path


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

def verify_payload(envelope: dict) -> dict:
    """
    Verify a signed envelope.

    Args:
        envelope : A dict shaped like sign_payload()'s output.

    Returns:
        dict: {
            "valid":      bool,
            "key_id":     str | None,
            "signed_at":  str | None,
            "trusted":    bool,   # embedded key matches the configured trust anchor
            "reason":     str,
        }
    """
    _require_crypto()
    result = {"valid": False, "key_id": None, "signed_at": None,
              "trusted": False, "reason": ""}

    if not isinstance(envelope, dict) or "payload" not in envelope or "signature" not in envelope:
        result["reason"] = "Not a signed envelope (missing 'payload'/'signature')."
        return result

    sig = envelope["signature"]
    result["signed_at"] = sig.get("signed_at")

    if sig.get("alg") != SIGNATURE_ALG:
        result["reason"] = f"Unsupported signature algorithm: {sig.get('alg')!r}"
        return result

    try:
        pub_hex = sig["public_key"]
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        signature = bytes.fromhex(sig["value"])
    except (KeyError, ValueError) as exc:
        result["reason"] = f"Malformed signature fields: {exc}"
        return result

    result["key_id"] = key_id(pub_hex)

    try:
        public_key.verify(signature, canonical_bytes(envelope["payload"]))
    except InvalidSignature:
        result["reason"] = "Signature does not match payload - report was altered."
        return result

    trusted = _load_trusted_public_key()
    if trusted is not None:
        result["trusted"] = _public_key_hex(trusted) == pub_hex
        if not result["trusted"]:
            result["valid"] = True
            result["reason"] = (
                "Signature is valid but was made with a key that is not the "
                "configured trust anchor."
            )
            return result

    result["valid"] = True
    result["reason"] = "Signature valid." + ("" if trusted is None else " Trusted key.")
    return result


def verify_file(path: "os.PathLike | str") -> dict:
    """
    Load a signed JSON report from disk and verify it.

    Args:
        path : Path to a signed-envelope JSON file.

    Returns:
        dict: Same shape as verify_payload(); "reason" carries load errors.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            envelope = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        return {"valid": False, "key_id": None, "signed_at": None,
                "trusted": False, "reason": f"Could not read report: {exc}"}
    return verify_payload(envelope)
