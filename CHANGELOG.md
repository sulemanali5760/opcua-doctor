# Changelog

All notable changes to this project are listed here. Versions follow [Semantic Versioning](https://semver.org).

## 0.1.1 - 2026-11-12

- Releases carry a wheel and offline bundles (tool plus all dependencies) for Linux and Windows.

## 0.1.0 - 2026-11-12

First public version.

- Step-by-step diagnosis: address, endpoints, server certificate, client certificate, endpoint choice, session.
- 23 OPC UA status codes translated into cause and fix.
- Command line `opcua-doctor` with `--json`; exit code 1 when the connection does not work.
- Python API: `diagnose()`.
