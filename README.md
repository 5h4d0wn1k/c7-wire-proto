# C7 — Wire Protocol Analyzer

Protocol buffer parsing, gRPC decoding, custom binary protocol analysis, and field extraction.

## Overview

This project implements a wire protocol analysis toolkit that:
- Parses Protocol Buffer messages with varint decoding
- Decodes gRPC length-prefixed message frames
- Analyzes custom binary protocols with user-defined specs
- Extracts and maps fields from parsed protocol data

## Features

- **Varint decoding**: Full variable-length integer support with zigzag
- **Protobuf parsing**: Wire type detection, field extraction, nested messages
- **gRPC decoding**: Frame parsing, stream decoding, message creation
- **Binary analysis**: Custom protocol specs, auto-detection, pattern matching
- **Field extraction**: Named field mapping and data normalization

## Installation

```bash
# No external dependencies required
# Uses only Python standard library
```

## Usage

```bash
# Run the analyzer
python3 wire_proto_analyzer.py

# Use in code
from wire_proto_analyzer import WireProtocolAnalyzer

analyzer = WireProtocolAnalyzer()
pb_data = analyzer.create_sample_protobuf()
result = analyzer.analyze_protobuf(pb_data)
print(result)
```

## Example Output

```
=== Wire Protocol Analyzer ===

--- Protobuf Analysis ---
{
  "fields": {
    "1": {"wire_type": "varint", "value": 42},
    "2": {"wire_type": "length-delimited", "value": "68656c6c6f"},
    "3": {"wire_type": "varint", "value": 29}
  },
  "raw_hex": "082a120568656c6c6f181d"
}

--- gRPC Analysis ---
[{
  "frame_idx": 0,
  "compressed": false,
  "length": 11,
  "data_preview": "082a120568656c6c6f181d"
}]

--- Binary Auto-Detection ---
{
  "patterns": [
    {"type": "uint16_le", "offset": 0, "value": 13370, "hex": "0x3444"},
    {"type": "uint32_le", "offset": 0, "value": 2018915346, "hex": "0x78563412"}
  ],
  "raw_hex": "3444000100",
  "length": 5
}

--- Varint Encoding ---
  0 -> 00 -> 0
  127 -> 7f -> 127
  128 -> 8001 -> 128
  300 -> ac02 -> 300
  16384 -> 808001 -> 16384
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
