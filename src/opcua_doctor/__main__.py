"""opcua-doctor opc.tcp://host:4840 [--cert client.der --key client.pem] [--user name]"""
import argparse
import asyncio
import getpass
import json
import os
import sys

from opcua_doctor.checks import FAIL, WARN, as_dicts, diagnose

MARK = {"ok": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]", "info": "      "}


def render(findings) -> str:
    lines, step = [], None
    for f in findings:
        if f.step != step:
            step = f.step
            lines.append(f"\n{step}")
        lines.append(f"  {MARK[f.level]} {f.title}")
        if f.detail:
            lines.append(f"         {f.detail}")
        if f.fix:
            lines.append(f"         -> {f.fix}")
    fails = sum(f.level == FAIL for f in findings)
    warns = sum(f.level == WARN for f in findings)
    lines.append(f"\n{'Connection works.' if not fails else 'Connection does not work.'}"
                 f" {fails} problem(s), {warns} warning(s).")
    return "\n".join(lines).lstrip("\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="opcua-doctor",
                                 description="Find out why an OPC UA connection fails, and what to do about it.")
    ap.add_argument("url", help="opc.tcp://host:port/path")
    ap.add_argument("--cert", help="client certificate (DER or PEM)")
    ap.add_argument("--key", help="client private key (PEM, unencrypted)")
    ap.add_argument("--server-cert", help="expect exactly this server certificate (optional)")
    ap.add_argument("--app-uri", help="application URI the client uses (default: the one in --cert)")
    ap.add_argument("--user", help="user name; the password is read from OPCUA_PASSWORD or asked for")
    ap.add_argument("--policy", help="security policy to test, e.g. Basic256Sha256 (default: strongest that fits)")
    ap.add_argument("--mode", choices=["Sign", "SignAndEncrypt", "None"], help="message security mode to test")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args(argv)
    password = None
    if a.user:
        password = os.environ.get("OPCUA_PASSWORD")
        if password is None:
            password = getpass.getpass(f"password for {a.user}: ")
    findings = asyncio.run(diagnose(a.url, cert=a.cert, key=a.key, server_cert=a.server_cert, app_uri=a.app_uri,
                                    username=a.user, password=password, policy=a.policy, mode=a.mode,
                                    timeout=a.timeout))
    print(json.dumps(as_dicts(findings), indent=2) if a.json else render(findings))
    return 1 if any(f.level == FAIL for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
