"""Each test breaks a connection in one specific way and expects the doctor to name that cause."""
import asyncio
import datetime
import json
import pathlib
import shutil
import socket

import pytest
from asyncua import Server, ua
from asyncua.common.utils import ServiceError
from asyncua.crypto import cert_gen
from asyncua.crypto.truststore import TrustStore
from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions
from asyncua.server.user_managers import User, UserManager, UserRole
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from opcua_doctor.__main__ import main, render
from opcua_doctor.checks import EXPLAIN, FAIL, OK, WARN, check_client_files, diagnose

OPEN = "opc.tcp://127.0.0.1:48451/open/"
SECURE = "opc.tcp://127.0.0.1:48452/secure/"
CLIENT_URI = "urn:test:client"
PASSWORD = "correct horse"


class _OneUser(UserManager):
    def get_user(self, iserver, username=None, password=None, certificate=None):
        return User(role=UserRole.User, name=username) if (username, password) == ("operator", PASSWORD) else None


async def open_server(ready, stop):
    server = Server()
    await server.init()
    server.set_endpoint(OPEN)
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    async with server:
        ready.set()
        await stop.wait()


async def secure_server(pki: pathlib.Path, ready, stop):
    """Encrypted sessions only, client certificate must be in pki/trusted, user name login only."""
    (pki / "trusted").mkdir(parents=True, exist_ok=True)
    cert, key = pki / "server.der", pki / "server.pem"
    await cert_gen.setup_self_signed_certificate(key, cert, "urn:test:server", socket.gethostname(),
                                                 [ExtendedKeyUsageOID.SERVER_AUTH], {"commonName": "test server"})
    server = Server(user_manager=_OneUser())
    await server.init()
    server.set_endpoint(SECURE)
    await server.set_application_uri("urn:test:server")
    await server.load_certificate(cert)
    await server.load_private_key(key)
    server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    server.set_identity_tokens([ua.UserNameIdentityToken])
    if any((pki / "trusted").glob("*.der")):
        store = TrustStore([pki / "trusted"], [])
        await store.load()
        server.set_certificate_validator(CertificateValidator(
            CertificateValidatorOptions.TRUSTED | CertificateValidatorOptions.PEER_CLIENT, store))
    else:
        async def reject_all(cert, app_description):
            raise ServiceError(ua.StatusCodes.BadCertificateUntrusted)
        server.set_certificate_validator(reject_all)
    async with server:
        ready.set()
        await stop.wait()


async def _with(server_fn, *args, check):
    ready, stop = asyncio.Event(), asyncio.Event()
    task = asyncio.create_task(server_fn(*args, ready, stop))
    await asyncio.wait_for(ready.wait(), 20)
    try:
        return await check()
    finally:
        stop.set()
        await task


def make_cert(folder: pathlib.Path, uri: str | None = CLIENT_URI, days_from=-1, days_to=365, name="client"):
    """A client certificate with full control over dates and URI (the doctor must judge exactly these)."""
    folder.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now + datetime.timedelta(days=days_from)).not_valid_after(now + datetime.timedelta(days=days_to))
         .add_extension(x509.KeyUsage(True, True, True, True, False, True, False, False, False), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False))
    san = ([x509.UniformResourceIdentifier(uri)] if uri else []) + [x509.DNSName(socket.gethostname())]
    b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
    cert = b.sign(key, hashes.SHA256())
    c, k = folder / f"{name}.der", folder / f"{name}.pem"
    c.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
    return c, k


def fails(findings):
    return [f for f in findings if f.level == FAIL]


def titles(findings):
    return " | ".join(f.title for f in findings)


# ---------------------------------------------------------------- address
def test_not_an_opcua_url():
    f = asyncio.run(diagnose("http://127.0.0.1:4840"))
    assert fails(f) and "not an OPC UA address" in f[0].title


def test_name_does_not_resolve():
    f = asyncio.run(diagnose("opc.tcp://no-such-host.invalid:4840"))
    assert "cannot be resolved" in fails(f)[0].title


def test_nothing_listening():
    f = asyncio.run(diagnose("opc.tcp://127.0.0.1:48459", timeout=2))
    assert "nothing answers" in fails(f)[0].title and "firewall" in fails(f)[0].fix


# ---------------------------------------------------------------- open server
def test_open_server_works():
    f = asyncio.run(_with(open_server, check=lambda: diagnose(OPEN)))
    assert not fails(f), titles(f)
    assert any(x.level == OK and x.step == "session" for x in f)
    assert any("None / None" in x.title for x in f)


def test_asking_for_a_policy_the_server_does_not_offer(tmp_path):
    cert, key = make_cert(tmp_path)
    f = asyncio.run(_with(open_server, check=lambda: diagnose(OPEN, cert=cert, key=key, policy="Basic256Sha256")))
    bad = fails(f)[0]
    assert "does not offer Basic256Sha256" in bad.title and "None/None" in bad.detail


# ---------------------------------------------------------------- secured server
def test_secured_server_without_certificate(tmp_path):
    f = asyncio.run(_with(secure_server, tmp_path / "pki", check=lambda: diagnose(SECURE)))
    bad = fails(f)[0]
    assert "only accepts encrypted connections" in bad.title and "--cert" in bad.fix


def test_secured_server_without_login(tmp_path):
    cert, key = make_cert(tmp_path)
    f = asyncio.run(_with(secure_server, tmp_path / "pki", check=lambda: diagnose(SECURE, cert=cert, key=key)))
    bad = fails(f)[0]
    assert "does not allow anonymous" in bad.title and "UserName" in bad.detail


def test_untrusted_client_certificate(tmp_path):
    cert, key = make_cert(tmp_path)
    f = asyncio.run(_with(secure_server, tmp_path / "pki",
                          check=lambda: diagnose(SECURE, cert=cert, key=key, username="operator", password=PASSWORD)))
    bad = fails(f)[0]
    assert "BadCertificateUntrusted" in bad.title and "trust list" in bad.fix


def _trusted(tmp_path):
    cert, key = make_cert(tmp_path)
    (tmp_path / "pki/trusted").mkdir(parents=True)
    shutil.copy(cert, tmp_path / "pki/trusted/client.der")
    return cert, key


def test_wrong_password(tmp_path):
    cert, key = _trusted(tmp_path)
    f = asyncio.run(_with(secure_server, tmp_path / "pki",
                          check=lambda: diagnose(SECURE, cert=cert, key=key, username="operator", password="wrong")))
    bad = fails(f)[0]
    assert "BadUserAccessDenied" in bad.title and "password" in bad.fix


def test_everything_right_on_secured_server(tmp_path):
    cert, key = _trusted(tmp_path)
    f = asyncio.run(_with(secure_server, tmp_path / "pki",
                          check=lambda: diagnose(SECURE, cert=cert, key=key, username="operator", password=PASSWORD)))
    assert not fails(f), titles(f)
    assert any("trying Basic256Sha256 / SignAndEncrypt" in x.title for x in f)
    assert any(x.title == "connected and read from the server" for x in f)
    # 127.0.0.1 is not in the test server's certificate: the doctor says so, as a warning
    assert any(x.level == WARN and "not listed in the server certificate" in x.title for x in f)


# ---------------------------------------------------------------- client files, no server needed
def test_expired_client_certificate(tmp_path):
    cert, key = make_cert(tmp_path, days_from=-30, days_to=-1)
    f = check_client_files(cert, key, None)
    assert "expired" in fails(f)[0].title


def test_client_certificate_not_valid_yet(tmp_path):
    cert, key = make_cert(tmp_path, days_from=2, days_to=30)
    assert "not valid yet" in fails(check_client_files(cert, key, None))[0].title


def test_client_certificate_without_application_uri(tmp_path):
    cert, key = make_cert(tmp_path, uri=None)
    assert "no application URI" in fails(check_client_files(cert, key, None))[0].title


def test_application_uri_mismatch(tmp_path):
    cert, key = make_cert(tmp_path)
    bad = fails(check_client_files(cert, key, "urn:something:else"))[0]
    assert "does not match the certificate" in bad.title and CLIENT_URI in bad.fix


def test_key_of_another_certificate(tmp_path):
    cert, _ = make_cert(tmp_path / "a")
    _, other_key = make_cert(tmp_path / "b")
    assert "does not belong" in fails(check_client_files(cert, other_key, None))[0].title


def test_certificate_about_to_expire_is_a_warning(tmp_path):
    cert, key = make_cert(tmp_path, days_to=10)
    f = check_client_files(cert, key, None)
    assert not fails(f) and any(x.level == WARN and "valid until" in x.title for x in f)


def test_unreadable_files(tmp_path):
    (tmp_path / "junk.der").write_bytes(b"not a certificate")
    assert "cannot read the client certificate" in fails(check_client_files(tmp_path / "junk.der", tmp_path / "x.pem", None))[0].title


# ---------------------------------------------------------------- command line
def test_command_line_exit_code_and_json(capsys):
    assert main(["opc.tcp://127.0.0.1:48459", "--timeout", "1", "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out[0]["level"] == "fail" and out[0]["step"] == "address"


def test_report_is_readable():
    text = render(asyncio.run(diagnose("opc.tcp://127.0.0.1:48459", timeout=1)))
    assert "[FAIL] nothing answers on 127.0.0.1:48459" in text and "Connection does not work. 1 problem(s)" in text


def test_every_explanation_has_a_meaning_and_a_fix():
    assert len(EXPLAIN) >= 20
    for name, (meaning, fix) in EXPLAIN.items():
        assert name.startswith("Bad") and hasattr(ua.StatusCodes, name), name     # a real OPC UA status code
        assert len(meaning) > 20 and len(fix) > 8, name
