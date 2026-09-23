> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# C7 — Wire Protocol Cryptography Analyzer

Stdlib-only wire-protocol analysis: Protocol Buffer parsing, gRPC frame decoding, custom binary protocol specs, field extraction, and static traffic scanning for replay, cleartext and malformed frames.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/c7-wire-proto.svg)](https://github.com/5h4d0wn1k/c7-wire-proto)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/c7-wire-proto.svg)](https://github.com/5h4d0wn1k/c7-wire-proto)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/c7-wire-proto.svg)](https://github.com/5h4d0wn1k/c7-wire-proto)

## Why

Protocol flaws hide in bytes, not in docs. C7 decodes the common wire dialects — protobuf varints, gRPC length-prefixed frames, and user-defined binary specs — so captured traffic can be inspected structurally instead of guessed at. Its static scanner flags replay groups, cleartext fields, and truncated/malformed frames, and fuzzes untrusted payloads to prove parse robustness. Pure standard library: no third-party packages, fully offline, ideal for protocol-crypto education on traffic you have lawful access to.

## Features

- **Protobuf parsing** — varint + zigzag decoding, wire-type detection, field extraction, message builder
- **gRPC decoding** — frame parsing, stream decoding, message creation
- **Custom binary specs** — user-defined protocol definitions, auto-detection, pattern matching
- **Field extraction** — named-field mapping and data normalization
- **Traffic scanner** — replay detection, cleartext-field spotting, malformed/truncated frame checks
- **Fuzz robustness** — mutation rounds on untrusted payloads must never raise

## Quickstart

```bash
# Full offline analysis demo (exit 0)
python3 wire_proto_analyzer.py

# JSON report to file
python3 wire_proto_analyzer.py --json --output reports/traffic.json

# Classic decode demos (varint / protobuf / gRPC / binary)
python3 wire_proto_analyzer.py --run

# Use as a library
from wire_proto_analyzer import WireProtocolAnalyzer, WireProtocolScanner
analyzer = WireProtocolAnalyzer()
pb = analyzer.create_sample_protobuf()
result = analyzer.analyze_protobuf(pb)

# Unit tests (27)
python3 -m unittest discover -s tests
```

## Project structure

- `wire_proto_analyzer.py` — varint/protobuf/gRPC/binary decoders, scanner, CLI
- `tests/` — 27 unit tests covering decoding, scanning and fuzz robustness

## Documentation

- [ETHICS.md](ETHICS.md) — educational purpose and authorized use only
- [SCOPE.md](SCOPE.md) — authorized-testing scope checklist
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — safe contribution guidelines

## Contributing

New wire dialects, scanner rules and fuzz cases are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md); analyze only traffic you own or are authorized to inspect.

## License

MIT — see [LICENSE](LICENSE). Provided **AS IS**, without warranty, for education and authorized protocol analysis only.