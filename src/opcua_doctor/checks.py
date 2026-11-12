"""Find out why an OPC UA connection fails, step by step, and say what to do about it.

Order of the checks (each one only runs if the earlier ones allow it):
1. address: is the URL an opc.tcp URL, does the name resolve, does the port answer
2. endpoints: what the server offers (security policies, modes, login types), and whether the
   addresses it advertises can be reached from here
3. server certificate: validity period, application URI, host name, key and signature strength
4. client certificate (if given): readable, valid now, has an application URI, matches its key
5. choice: is there an endpoint that fits what the caller has (certificate, login)
6. session: connect for real; on refusal, translate the status code into cause and fix

The tool only reads two standard nodes (server time, namespace table). It never writes.
"""
import asyncio
import datetime
import ipaddress
import pathlib
import socket
import urllib.parse
from dataclasses import asdict, dataclass

from asyncua import Client, ua
from asyncua.crypto import security_policies
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"
# Strongest first. Policies the OPC Foundation has deprecated are listed separately.
CURRENT = ["Aes256_Sha256_RsaPss", "Aes128_Sha256_RsaOaep", "Basic256Sha256"]
DEPRECATED = ["Basic256", "Basic128Rsa15"]
TOKEN_NAMES = {ua.UserTokenType.Anonymous: "Anonymous", ua.UserTokenType.UserName: "UserName",
               ua.UserTokenType.Certificate: "Certificate", ua.UserTokenType.IssuedToken: "IssuedToken"}

# Status code -> (what it means here, what to do). Meanings follow OPC 10000-4 (Services) and OPC 10000-6.
EXPLAIN = {
    "BadSecurityChecksFailed": (
        "The server refused the secure channel without saying why (servers hide the reason on purpose).",
        "Most often the server does not trust the client certificate yet: look in the server's 'rejected' "
        "certificate list and move this client's certificate to 'trusted'. If it is already trusted, compare the "
        "clocks of both machines and the application URI in the client certificate."),
    "BadCertificateUntrusted": (
        "The server does not trust the client certificate.",
        "Add the client certificate (.der) to the server's trust list. On many servers it is waiting in a "
        "'rejected' folder after the first attempt."),
    "BadCertificateUriInvalid": (
        "The application URI the client sends is not the URI written in its certificate.",
        "Use the URI from the certificate (shown above under 'client certificate') as the client's application "
        "URI, or create a new certificate with the URI the client uses."),
    "BadCertificateTimeInvalid": (
        "A certificate is expired or not valid yet, as seen by the other side.",
        "Check the validity dates above and the clocks of both machines; renew the certificate if it is expired."),
    "BadCertificateHostNameInvalid": (
        "The host name used to connect is not listed in the server certificate.",
        "Connect with a name or IP address that is in the certificate, or recreate the server certificate "
        "with the right names."),
    "BadCertificateUseNotAllowed": (
        "The certificate is not allowed for this use (key usage / extended key usage).",
        "Create an application certificate with digitalSignature, keyEncipherment, dataEncipherment and "
        "clientAuth (for a client)."),
    "BadCertificateInvalid": (
        "The other side could not process the certificate.",
        "Check that it is a DER or PEM X.509 certificate with an RSA key of at least 2048 bits."),
    "BadCertificateRevoked": ("The certificate has been revoked.", "Issue a new certificate."),
    "BadCertificateRevocationUnknown": (
        "The server could not check whether the certificate is revoked.",
        "Install the issuer's revocation list (CRL) on the server, or relax that check there."),
    "BadCertificateIssuerRevocationUnknown": (
        "The server could not check the revocation list of the certificate's issuer.",
        "Install the CA's revocation list (CRL) on the server."),
    "BadCertificateChainIncomplete": (
        "The server cannot build the chain to a trusted issuer.",
        "Install the issuing CA certificates on the server."),
    "BadUserAccessDenied": (
        "The login was refused, or the user is not allowed to do this.",
        "Check user name and password, and the user's rights on the server."),
    "BadIdentityTokenRejected": (
        "The server does not accept this kind of login on this endpoint.",
        "Use a login type the endpoint offers (listed above), or pick another endpoint."),
    "BadIdentityTokenInvalid": (
        "The login data could not be read by the server.",
        "Check the login type and the user name; some servers want an encrypted channel for passwords."),
    "BadSecurityPolicyRejected": (
        "The server does not accept this security policy.",
        "Choose one of the policies the server offers (listed above)."),
    "BadSecurityModeRejected": (
        "The server does not accept this message security mode.",
        "Choose a mode the server offers for that policy (listed above)."),
    "BadTooManySessions": (
        "The server has reached its session limit.",
        "Close unused clients; small PLCs often allow only a handful of sessions."),
    "BadServerUriInvalid": (
        "The server URI the client sent does not match the server.",
        "Do not set a server URI by hand; let the client take it from the endpoint."),
    "BadTcpEndpointUrlInvalid": (
        "The server does not know the endpoint URL the client asked for.",
        "Use exactly the URL the server advertises, including the path after the port."),
    "BadSecureChannelIdInvalid": (
        "The secure channel was closed or replaced.",
        "Reconnect; if it repeats, check for a second client using the same certificate and session."),
    "BadSessionIdInvalid": ("The session is gone on the server.", "Reconnect."),
    "BadTimeout": ("The server did not answer in time.", "Check network load and the server's state."),
    "BadNotConnected": ("The connection is not open.", "Check that the server is running."),
}


@dataclass
class Finding:
    level: str          # ok, warn, fail, info
    step: str           # address, endpoints, server certificate, client certificate, choice, session
    title: str
    detail: str = ""
    fix: str = ""


def _short(policy_uri: str) -> str:
    return policy_uri.rsplit("#", 1)[-1]


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _san(cert: x509.Certificate):
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return [], [], []
    return (san.get_values_for_type(x509.UniformResourceIdentifier), san.get_values_for_type(x509.DNSName),
            [str(i) for i in san.get_values_for_type(x509.IPAddress)])


def load_certificate(data_or_path) -> x509.Certificate:
    data = data_or_path if isinstance(data_or_path, bytes) else pathlib.Path(data_or_path).read_bytes()
    if data.lstrip().startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def check_certificate(cert: x509.Certificate, step: str, who: str) -> list[Finding]:
    """Checks that do not depend on the other side: dates, key, signature, application URI."""
    out = []
    now = _now()
    if now < cert.not_valid_before_utc:
        out.append(Finding(FAIL, step, f"{who} certificate is not valid yet",
                           f"valid from {cert.not_valid_before_utc:%Y-%m-%d %H:%M} UTC, now {now:%Y-%m-%d %H:%M} UTC",
                           "Check the clock of this machine and of the machine that created the certificate."))
    elif now > cert.not_valid_after_utc:
        out.append(Finding(FAIL, step, f"{who} certificate expired on {cert.not_valid_after_utc:%Y-%m-%d}",
                           fix="Create a new certificate and have the other side trust it."))
    else:
        days = (cert.not_valid_after_utc - now).days
        out.append(Finding(WARN if days < 30 else OK, step,
                           f"{who} certificate is valid until {cert.not_valid_after_utc:%Y-%m-%d} ({days} days)",
                           fix="Renew it soon." if days < 30 else ""))
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
        out.append(Finding(WARN, step, f"{who} certificate has a {key.key_size}-bit RSA key",
                           fix="Current security policies need at least 2048 bits."))
    algo = cert.signature_hash_algorithm
    if isinstance(algo, (hashes.SHA1, hashes.MD5)):
        out.append(Finding(WARN, step, f"{who} certificate is signed with {algo.name.upper()}",
                           fix="Many servers and clients reject it; create one signed with SHA-256."))
    uris, _, _ = _san(cert)
    if not uris:
        out.append(Finding(FAIL, step, f"{who} certificate has no application URI",
                           "OPC UA needs a URI entry in the subject alternative name.",
                           "Create an OPC UA application instance certificate (it contains the application URI)."))
    else:
        out.append(Finding(INFO, step, f"{who} certificate application URI: {uris[0]}"))
    return out


def check_client_files(cert_path, key_path, app_uri: str | None) -> list[Finding]:
    step = "client certificate"
    try:
        cert = load_certificate(cert_path)
    except (OSError, ValueError) as e:
        return [Finding(FAIL, step, f"cannot read the client certificate {cert_path}", str(e),
                        "Give a DER or PEM X.509 certificate file.")]
    out = check_certificate(cert, step, "client")
    uris, _, _ = _san(cert)
    if uris and app_uri and app_uri != uris[0]:
        out.append(Finding(FAIL, step, "application URI does not match the certificate",
                           f"client uses {app_uri!r}, certificate says {uris[0]!r}",
                           f"Use --app-uri {uris[0]} (servers answer BadCertificateUriInvalid otherwise)."))
    try:
        key = serialization.load_pem_private_key(pathlib.Path(key_path).read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as e:
        return out + [Finding(FAIL, step, f"cannot read the private key {key_path}", str(e),
                              "Give the unencrypted PEM private key that belongs to the certificate.")]
    if key.public_key().public_numbers() != cert.public_key().public_numbers():
        out.append(Finding(FAIL, step, "private key does not belong to the certificate",
                           fix="Use the key file that was created together with this certificate."))
    else:
        out.append(Finding(OK, step, "private key belongs to the certificate"))
    return out


def _resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False


async def check_address(url: str, timeout: float) -> tuple[list[Finding], str, int]:
    step = "address"
    u = urllib.parse.urlparse(url)
    if u.scheme != "opc.tcp" or not u.hostname:
        return [Finding(FAIL, step, f"{url!r} is not an OPC UA address",
                        fix="Use the form opc.tcp://host:4840/path")], "", 0
    host, port = u.hostname, u.port or 4840
    if not await asyncio.to_thread(_resolves, host):
        return [Finding(FAIL, step, f"the name {host!r} cannot be resolved",
                        fix="Use the IP address, or add the name to DNS or the hosts file.")], host, port
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        writer.close()
    except (OSError, asyncio.TimeoutError) as e:
        why = "no answer (timeout)" if isinstance(e, asyncio.TimeoutError) else str(e) or type(e).__name__
        return [Finding(FAIL, step, f"nothing answers on {host}:{port}", why,
                        "Check that the OPC UA server is running and enabled, that the port is right, and that no "
                        "firewall blocks it. On a PLC the OPC UA server usually has to be switched on in the project.")], host, port
    return [Finding(OK, step, f"{host}:{port} is reachable")], host, port


def describe_endpoints(endpoints, host: str) -> list[Finding]:
    step = "endpoints"
    out = []
    policies = set()
    for e in endpoints:
        policy = _short(e.SecurityPolicyUri)
        policies.add(policy)
        tokens = ", ".join(sorted({TOKEN_NAMES.get(t.TokenType, str(t.TokenType)) for t in e.UserIdentityTokens})) or "none listed"
        out.append(Finding(INFO, step, f"{policy} / {e.SecurityMode.name}", f"login: {tokens}; address: {e.EndpointUrl}"))
    advertised = {urllib.parse.urlparse(e.EndpointUrl).hostname for e in endpoints} - {None, host}
    for name in sorted(advertised):
        if not _resolves(name):
            out.append(Finding(WARN, step, f"the server advertises the name {name!r}, which this machine cannot resolve",
                               f"You connected with {host!r}. Clients that follow the advertised address will fail.",
                               f"Add {name} to DNS or the hosts file, or configure the server to advertise an address "
                               "clients can reach."))
    if "None" in policies:
        out.append(Finding(INFO, step, "the server also accepts unencrypted connections"))
    if policies and policies <= set(DEPRECATED):
        out.append(Finding(WARN, step, "the server only offers deprecated security policies",
                           ", ".join(sorted(policies)), "Enable Basic256Sha256 or newer on the server."))
    return out


def check_server_certificate(endpoints, host: str) -> tuple[list[Finding], x509.Certificate | None]:
    step = "server certificate"
    e = next((e for e in endpoints if e.ServerCertificate), None)
    if e is None:
        return [Finding(INFO, step, "the server sends no certificate (it offers no secure endpoint)")], None
    try:
        cert = load_certificate(bytes(e.ServerCertificate))
    except ValueError as err:
        return [Finding(FAIL, step, "the server certificate cannot be read", str(err))], None
    out = check_certificate(cert, step, "server")
    uris, names, ips = _san(cert)
    if uris and e.Server.ApplicationUri and e.Server.ApplicationUri not in uris:
        out.append(Finding(WARN, step, "server application URI does not match its certificate",
                           f"server says {e.Server.ApplicationUri!r}, certificate says {uris[0]!r}",
                           "Strict clients refuse this (BadCertificateUriInvalid); recreate the server certificate."))
    try:
        listed = str(ipaddress.ip_address(host)) in ips
    except ValueError:
        listed = host.lower() in [n.lower() for n in names]
    if not listed:
        out.append(Finding(WARN, step, f"{host!r} is not listed in the server certificate",
                           f"it lists: {', '.join(names + ips) or 'nothing'}",
                           "Strict clients refuse this (BadCertificateHostNameInvalid). Connect with a listed name, "
                           "or recreate the server certificate."))
    return out, cert


def choose_endpoint(endpoints, have_cert: bool, have_login: bool, policy: str | None, mode: str | None):
    """The endpoint to try, or a finding that explains why none fits."""
    step = "choice"
    offered = sorted({f"{_short(e.SecurityPolicyUri)}/{e.SecurityMode.name}" for e in endpoints})

    def fits_login(e):
        types = {t.TokenType for t in e.UserIdentityTokens}
        return not types or (ua.UserTokenType.UserName if have_login else ua.UserTokenType.Anonymous) in types
    if policy:
        mode = mode or ("None_" if policy == "None" else "SignAndEncrypt")
        cands = [e for e in endpoints if _short(e.SecurityPolicyUri) == policy and e.SecurityMode.name.rstrip("_") == mode.rstrip("_")]
        if not cands:
            return None, Finding(FAIL, step, f"the server does not offer {policy} / {mode.rstrip('_')}",
                                 f"it offers: {', '.join(offered)}", "Choose one of the offered combinations.")
    else:
        order = (CURRENT + DEPRECATED if have_cert else []) + ["None"]
        cands = sorted((e for e in endpoints if _short(e.SecurityPolicyUri) in order),
                       key=lambda e: (order.index(_short(e.SecurityPolicyUri)), -int(e.SecurityMode)))
        if not have_cert:
            cands = [e for e in cands if _short(e.SecurityPolicyUri) == "None"]
            if not cands:
                return None, Finding(FAIL, step, "the server only accepts encrypted connections",
                                     f"it offers: {', '.join(offered)}",
                                     "Give a client certificate and key (--cert, --key). The server must trust that certificate.")
    if any(_short(e.SecurityPolicyUri) != "None" for e in cands) and not have_cert:
        return None, Finding(FAIL, step, "this security policy needs a client certificate",
                             fix="Give --cert and --key.")
    fitting = [e for e in cands if fits_login(e)]
    if not fitting:
        e = cands[0]
        tokens = ", ".join(sorted(TOKEN_NAMES.get(t.TokenType, "?") for t in e.UserIdentityTokens))
        if have_login:
            return None, Finding(FAIL, step, "this endpoint does not accept a user name login",
                                 f"it accepts: {tokens}", "Connect without --user, or use another endpoint.")
        return None, Finding(FAIL, step, "the server does not allow anonymous access here",
                             f"it accepts: {tokens}", "Give a user name (--user) and the password.")
    e = fitting[0]
    return e, Finding(OK, step, f"trying {_short(e.SecurityPolicyUri)} / {e.SecurityMode.name.rstrip('_')}"
                                f" with {'user name login' if have_login else 'anonymous login'}")


def explain(error: BaseException, secure: bool) -> Finding:
    step = "session"
    name = type(error).__name__
    if isinstance(error, ua.UaStatusCodeError) and name == "UaStatusCodeError":
        try:
            name = ua.status_codes.get_name_and_doc(error.code)[0]
        except Exception:  # unknown code: keep the generic name
            pass
    if name in EXPLAIN:
        meaning, fix = EXPLAIN[name]
        return Finding(FAIL, step, f"refused: {name}", meaning, fix)
    if isinstance(error, (asyncio.TimeoutError, TimeoutError)):
        if secure:
            return Finding(FAIL, step, "no answer to the encrypted request (timeout)",
                           "The server stayed silent after the secure channel request.",
                           "Typical causes: the server silently drops clients it does not trust (check its rejected "
                           "certificates), or the request was encrypted for a certificate the server no longer uses "
                           "(remove a pinned or cached server certificate and try again).")
        return Finding(FAIL, step, "no answer (timeout)", fix="Check network and server load; try a longer --timeout.")
    if isinstance(error, (ConnectionError, OSError)):
        return Finding(FAIL, step, "the server closed the connection", str(error) or name,
                       "Servers do this when they reject the client early. Check the server's log and its rejected certificates.")
    return Finding(FAIL, step, f"failed: {name}", str(error),
                   "Not a case this tool knows. The server's own log usually names the reason.")


async def diagnose(url: str, *, cert=None, key=None, server_cert=None, app_uri: str | None = None,
                   username: str | None = None, password: str | None = None, policy: str | None = None,
                   mode: str | None = None, timeout: float = 5.0) -> list[Finding]:
    findings, host, _ = await check_address(url, timeout)
    if findings[-1].level == FAIL:
        return findings
    try:
        endpoints = await asyncio.wait_for(Client(url, timeout=timeout).connect_and_get_server_endpoints(), timeout * 2)
    except Exception as e:  # anything here means: the port answers, but not as an OPC UA server we can talk to
        findings.append(Finding(FAIL, "endpoints", "the port answers, but the endpoint list could not be read",
                                f"{type(e).__name__}: {e}",
                                "Check that this port is the OPC UA server (not a web server or another service) and "
                                "that the path after the port is right."))
        return findings
    findings += describe_endpoints(endpoints, host)
    cert_findings, _ = check_server_certificate(endpoints, host)
    findings += cert_findings
    have_cert = bool(cert and key)
    if cert or key:
        if not have_cert:
            findings.append(Finding(FAIL, "client certificate", "give both --cert and --key"))
            return findings
        client_findings = check_client_files(cert, key, app_uri)
        findings += client_findings
        if any(f.level == FAIL for f in client_findings):
            return findings
        if not app_uri:
            app_uri = _san(load_certificate(cert))[0][0]
    endpoint, choice = choose_endpoint(endpoints, have_cert, bool(username), policy, mode)
    findings.append(choice)
    if endpoint is None:
        return findings
    secure = _short(endpoint.SecurityPolicyUri) != "None"
    client = Client(url, timeout=timeout)
    try:
        if secure:
            policy_class = getattr(security_policies, f"SecurityPolicy{_short(endpoint.SecurityPolicyUri)}", None)
            if policy_class is None:
                findings.append(Finding(FAIL, "session", f"this tool cannot use {_short(endpoint.SecurityPolicyUri)}",
                                        fix="Pick another policy with --policy."))
                return findings
            client.application_uri = app_uri
            await client.set_security(policy_class, str(cert), str(key),
                                      server_certificate=str(server_cert) if server_cert else bytes(endpoint.ServerCertificate),
                                      mode=endpoint.SecurityMode)
        if username:
            client.set_user(username)
            client.set_password(password or "")
        await asyncio.wait_for(client.connect(), timeout * 3)
    except Exception as e:  # every refusal is a result, not a crash
        findings.append(explain(e, secure))
        try:
            await client.disconnect()
        except Exception:
            pass
        return findings
    try:
        server_time = await client.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_CurrentTime)).read_value()
        namespaces = await client.get_namespace_array()
        findings.append(Finding(OK, "session", "connected and read from the server",
                                f"{len(namespaces)} namespaces: {', '.join(namespaces[1:4])}{' ...' if len(namespaces) > 4 else ''}"))
        skew = abs((server_time.replace(tzinfo=datetime.timezone.utc) - _now()).total_seconds())
        if skew > 300:
            findings.append(Finding(WARN, "session", f"the server clock differs by {skew / 60:.0f} minutes",
                                    fix="Synchronise both clocks (NTP). Large differences break certificate checks "
                                        "and make timestamps useless."))
    except Exception as e:
        findings.append(explain(e, secure))
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass
    return findings


def as_dicts(findings: list[Finding]) -> list[dict]:
    return [asdict(f) for f in findings]
