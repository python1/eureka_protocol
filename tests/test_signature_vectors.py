"""
The shared signature vectors are the contract with every other implementation.

A second implementation (Knights Circle's browser client is the first) proves
it encodes and signs exactly as this one does by reproducing this file. These
tests pin that the file is what this code produces, so it cannot drift from
the protocol it describes.
"""
import json

from eureka_protocol.src.eureka_daemon import crypto as C
from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto
from eureka_protocol.vectors import make_signature_vectors as M


def load():
    return json.loads(M.PATH.read_text())


def test_the_committed_file_is_exactly_what_the_generator_produces():
    assert M.PATH.read_text() == M.render(M.build())


def test_every_vector_is_this_codes_canonical_bytes_and_a_valid_signature():
    document = load()
    assert len(document["vectors"]) == 30
    for vector in document["vectors"]:
        domain = M.DOMAINS[vector["domain"]]
        assert vector["domain_tag"] == domain.decode("ascii")
        assert C.domain_separated_bytes(domain, vector["payload"]).hex() == vector["signed_bytes_hex"]
        assert EurekaCrypto.verify_json(document["public_key"], vector["signature"],
                                        vector["payload"], domain)


def test_a_vector_signature_does_not_verify_in_another_domain():
    document = load()
    vector = document["vectors"][0]
    assert not EurekaCrypto.verify_json(document["public_key"], vector["signature"],
                                        vector["payload"], C.DOMAIN_AUDIT_LOG)


def test_the_vectors_cover_what_encoders_get_wrong():
    """DEL, astral characters, separators and non-ASCII keys are the cases a JS encoder misses."""
    signed = " ".join(v["signed_bytes_hex"] for v in load()["vectors"])
    for escaped in (b"\\u007f", b"\\ud83d\\ude42", b"\\u2028", b"\\u00e9", b"\\u0000"):
        assert escaped.hex() in signed, escaped
