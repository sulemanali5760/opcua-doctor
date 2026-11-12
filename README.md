# opcua-doctor

[![ci](https://github.com/sulemanali5760/opcua-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/sulemanali5760/opcua-doctor/actions/workflows/ci.yml)

Find out **why an OPC UA connection fails**, and what to do about it.

OPC UA servers refuse connections with codes like `BadSecurityChecksFailed` and, on purpose, do not say more. `opcua-doctor` walks through the connection step by step (address, endpoints, certificates, trust, login) and stops at the first thing that is wrong, with the cause and the fix in plain words.

```
$ opcua-doctor opc.tcp://192.168.0.10:4840 --cert client.der --key client.pem --user operator

address
  [ OK ] 192.168.0.10:4840 is reachable

endpoints
         Basic256Sha256 / SignAndEncrypt
         login: UserName; address: opc.tcp://plant-pc:4840/secure/

server certificate
  [ OK ] server certificate is valid until 2027-11-12 (364 days)
         server certificate application URI: urn:test:server
  [WARN] '192.168.0.10' is not listed in the server certificate
         it lists: plant-pc
         -> Strict clients refuse this (BadCertificateHostNameInvalid). Connect with a listed name, or recreate the server certificate.

client certificate
  [ OK ] client certificate is valid until 2027-11-12 (364 days)
         client certificate application URI: urn:test:client
  [ OK ] private key belongs to the certificate

choice
  [ OK ] trying Basic256Sha256 / SignAndEncrypt with user name login

session
  [FAIL] refused: BadCertificateUntrusted
         The server does not trust the client certificate.
         -> Add the client certificate (.der) to the server's trust list. On many servers it is waiting in a 'rejected' folder after the first attempt.

Connection does not work. 1 problem(s), 1 warning(s).
```

*Output of a real run against the test server in this repo; address and host name changed for the example.*

## Install

With internet:

```bash
pip install https://github.com/sulemanali5760/opcua-doctor/releases/download/v0.1.1/opcua_doctor-0.1.1-py3-none-any.whl
```

Without internet (a plant PC, a commissioning laptop on the machine network): download the offline bundle
for your system from the [latest release](https://github.com/sulemanali5760/opcua-doctor/releases/latest), carry
it over on a USB stick, unzip it and run inside the folder:

```bash
python -m pip install --no-index --find-links . opcua-doctor
```

The bundle holds this tool and every package it needs; nothing is downloaded. Each bundle is installed in a
clean environment and started once before it is published. Python 3.11 or newer. Not on PyPI yet.

## Use

```bash
opcua-doctor opc.tcp://host:4840                                   # what does the server offer, can I get in without security
opcua-doctor opc.tcp://host:4840 --cert c.der --key c.pem          # encrypted, anonymous
opcua-doctor opc.tcp://host:4840 --cert c.der --key c.pem --user operator
opcua-doctor opc.tcp://host:4840 --policy Basic256Sha256 --mode Sign --cert c.der --key c.pem
opcua-doctor opc.tcp://host:4840 --json                            # for scripts and CI
```

The password is read from `OPCUA_PASSWORD` or asked for; it is never an argument. Exit code 1 if the connection does not work.

From Python:

```python
from opcua_doctor import diagnose
findings = await diagnose("opc.tcp://host:4840", cert="c.der", key="c.pem")
```

## What it checks

| Step | Finds |
|---|---|
| address | not an `opc.tcp` URL, name does not resolve, nothing answers on the port |
| endpoints | which security policies, modes and login types the server offers; a server that advertises a host name your machine cannot resolve; only deprecated policies |
| server certificate | expired or not yet valid, application URI mismatch, host name not in the certificate, weak key, SHA-1 signature |
| client certificate | unreadable file, expired or not yet valid, no application URI, URI differs from the one the client uses, key does not belong to the certificate |
| choice | server needs encryption and you gave no certificate, policy or mode not offered, anonymous not allowed, user name login not offered |
| session | connects for real and translates the refusal: 23 status codes (`BadSecurityChecksFailed`, `BadCertificateUntrusted`, `BadCertificateUriInvalid`, `BadUserAccessDenied`, `BadIdentityTokenRejected`, `BadTooManySessions`, …) into cause and fix; clock difference between both machines |

It reads two standard nodes (server time and namespace table) and nothing else. It never writes to the server.

## Tested

Every test breaks a connection in one specific way against a real OPC UA server started in the test, and expects the doctor to name that cause: unreachable port, unresolvable name, server without the requested policy, encrypted-only server without certificate, login required, untrusted client certificate, wrong password. Certificate problems (expired, not yet valid, no URI, URI mismatch, wrong key) are tested with certificates generated for the purpose.

## Limits

- **Tested against one server stack** (the `asyncua` server). Siemens, Beckhoff, B&R, Kepware and others word and order their refusals differently; the status codes are standard, but which one a server picks for a given cause is not. Reports from real controllers are welcome as issues.
- **A server that hides the reason stays hidden.** `BadSecurityChecksFailed` can have several causes; the doctor lists them in order of likelihood, it cannot see into the server.
- **RSA certificates and user name login only.** No ECC policies, no certificate or token-based user identity.
- **It does not change anything.** It will not create certificates or move them into trust lists for you.
- The explanations follow the status-code definitions in OPC 10000-4 and OPC 10000-6; the "most often" hints are the author's reading of public issue trackers and forums, not a statistic.

## Why

`BadSecurityChecksFailed` alone appears in over a hundred GitHub issues across OPC UA projects, and the Python OPC UA library `asyncua` has about 95 issues on security and 79 on certificates (counted 12 Nov 2026). The answers are almost always one of the checks above.

## Licence

MIT
