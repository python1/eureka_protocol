"""
TLS that carries the node's existing identity instead of inventing a second one.

The node already has an ed25519 keypair and a trust file keyed by public key.
The obvious way to add TLS -- generate a certificate keypair and distribute
certificates -- would give every node two identities that can drift apart, and
would move peer identity out of the trust file into a CA store that is read
once at startup. Revocation would then have two homes, and the live path in
reload_trust() could not reach the second one.

So this module does the opposite. The certificate is a wrapper around the key
the node already has (RFC 8410 puts ed25519 in X.509), and the client verifies
it by pinning: it checks the raw public key inside the certificate against the
trust list, exactly as it checks the key that signs the handshake. No
certificate authority is trusted, none is needed, and nothing new has to be
distributed -- the trust file already holds the only fact required.

What this covers and what it does not:

  * The channel gets confidentiality and integrity, and the server is
    authenticated by pinning.
  * The *client* is authenticated by the existing three-message ed25519
    handshake, not by a client certificate. A caller can therefore still open
    a connection before being authenticated, exactly as it can today over
    plain HTTP; the body cap and the bounded handshake tables are what limit
    what that caller can cost us.
"""
import datetime
import ssl
from pathlib import Path
from typing import Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from .crypto import EurekaCrypto, resolve_identity_path, write_private_file

# How long a node certificate is valid for. Long, because the certificate is
# not the thing being trusted -- the key inside it is, and that key's lifetime
# is governed by rotation and revocation, not by an expiry date a peer would
# have to notice. A short expiry here would only add an outage mode.
CERT_VALIDITY_DAYS = 3650

# Written next to the identity file by default, so a node's secrets live in
# exactly one directory.
SERVER_CERT_FILENAME = "server-cert.pem"
SERVER_KEY_FILENAME = "server-key.pem"


class TLSError(RuntimeError):
    """Raised when TLS materials cannot be built, read, or verified."""


def build_self_signed_cert(crypto: EurekaCrypto, node_id: str) -> bytes:
    """
    A self-signed certificate wrapping this node's existing ed25519 key.

    The subject name is decorative. Identity is the key inside the
    certificate, never the name printed on it, which is why the client turns
    hostname checking off -- there is nothing in the name worth checking.
    """
    if not isinstance(node_id, str) or not node_id.strip():
        raise TLSError(f"node_id must be a non-empty string, got {node_id!r}")
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id.strip())])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(crypto.private_key.public_key())
        .serial_number(x509.random_serial_number())
        # Backdated by a day so a peer whose clock is slightly behind ours does
        # not reject a freshly generated certificate. The handshake has its own
        # freshness window; this date is not doing security work.
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(node_id.strip())]),
                       critical=False)
        # algorithm=None: ed25519 fixes its own hash, and passing one is an error.
        .sign(private_key=crypto.private_key, algorithm=None)
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def public_key_hex_from_cert(cert_bytes: bytes) -> str:
    """
    The raw ed25519 public key inside a certificate, as lowercase hex.

    This is the whole point of the design: what comes back is directly
    comparable with the keys in the trust file, with no fingerprint, no
    encoding choice, and no second representation to get wrong.
    """
    if not isinstance(cert_bytes, (bytes, bytearray)):
        raise TLSError(
            f"certificate must be bytes, got {type(cert_bytes).__name__}"
        )
    try:
        if cert_bytes.strip().startswith(b"-----BEGIN"):
            certificate = x509.load_pem_x509_certificate(bytes(cert_bytes))
        else:
            certificate = x509.load_der_x509_certificate(bytes(cert_bytes))
    except Exception as exc:
        raise TLSError(f"cannot parse certificate: {exc}") from exc

    public_key = certificate.public_key()
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        # An RSA or EC certificate cannot be checked against this trust file at
        # all, and quietly accepting one would mean a connection nobody pinned.
        raise TLSError(
            f"certificate does not carry an ed25519 key "
            f"(got {type(public_key).__name__})"
        )
    return public_key.public_bytes_raw().hex()


def server_material_paths(directory: Optional[Union[str, Path]] = None) -> Tuple[Path, Path]:
    """Where the certificate and its key live: beside the identity file."""
    if directory is not None:
        base = Path(directory).expanduser()
    else:
        base = resolve_identity_path().parent
    return base / SERVER_CERT_FILENAME, base / SERVER_KEY_FILENAME


def ensure_server_materials(crypto: EurekaCrypto, node_id: str,
                            directory: Optional[Union[str, Path]] = None
                            ) -> Tuple[Path, Path]:
    """
    Write the certificate and key uvicorn needs, and return their paths.

    Regenerated whenever the certificate on disk does not wrap the *current*
    identity key. That is what makes rotation safe: after EurekaCrypto.rotate()
    the old certificate is stale, and serving it would present peers with a key
    the node can no longer prove it holds. Peers would pin a key that is no
    longer ours and every connection would fail in a way that looks like an
    attack.

    The key file is a second copy of the node's private key on disk. It is
    written 0600 through the same atomic writer as the identity file, and it
    lives in the same directory, so there is one place to protect rather than
    two.
    """
    cert_path, key_path = server_material_paths(directory)
    expected = crypto.get_public_key_hex()

    if cert_path.exists() and key_path.exists():
        try:
            if public_key_hex_from_cert(cert_path.read_bytes()) == expected:
                return cert_path, key_path
        except TLSError:
            # Unreadable or wrong-algorithm certificate: replace it rather than
            # serve it. Nothing is lost -- it is derived from the identity.
            pass

    write_private_file(cert_path, build_self_signed_cert(crypto, node_id))
    write_private_file(key_path, crypto.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return cert_path, key_path


def pinning_ssl_context() -> ssl.SSLContext:
    """
    A client context that trusts no certificate authority at all.

    This is not verification turned off. Chain verification is *replaced* by
    pinning the raw key against the trust file, which is strictly narrower:
    the default context accepts any of hundreds of public CAs, while this one
    accepts exactly the keys an operator listed. The pin is not optional --
    the handshake driver refuses any TLS connection whose key is not trusted.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Order matters: verify_mode cannot be lowered while check_hostname is on.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def peer_key_from_response(response) -> Optional[str]:
    """
    The server's ed25519 public key for the connection a response arrived on,
    or None if that connection was not TLS.

    Reaches through httpx into the underlying socket. The awkward part is that
    the object handed back is a raw _SSLSocket rather than an ssl.SSLObject,
    and its getpeercert takes its argument positionally -- calling it by
    keyword raises TypeError. Kept in one place, and pinned by a test, so the
    detail cannot quietly break the pin.
    """
    stream = getattr(response, "extensions", {}).get("network_stream")
    if stream is None:
        return None
    ssl_object = stream.get_extra_info("ssl_object")
    if ssl_object is None:
        return None                      # plain HTTP: not a TLS connection
    der = ssl_object.getpeercert(True)
    if not der:
        return None
    return public_key_hex_from_cert(der)
