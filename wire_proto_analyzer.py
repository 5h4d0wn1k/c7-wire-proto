#!/usr/bin/env python3
"""Wire Protocol Analyzer - Protocol buffer parsing, gRPC decoding, binary analysis."""

import struct
import json
from typing import Any, Dict, List, Optional, Tuple, Union


class VarintDecoder:
    """Decode variable-length integers (varint) used in protobuf."""

    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple[int, int]:
        """Decode varint from data. Returns (value, new_offset)."""
        result = 0
        shift = 0
        while offset < len(data):
            byte = data[offset]
            result |= (byte & 0x7F) << shift
            offset += 1
            if (byte & 0x80) == 0:
                return result, offset
            shift += 7
            if shift > 63:
                raise ValueError("Varint too long")
        raise ValueError("Incomplete varint")

    @staticmethod
    def encode(value: int) -> bytes:
        """Encode integer as varint."""
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    @staticmethod
    def decode_signed(value: int) -> int:
        """Decode zigzag-encoded signed integer."""
        return (value >> 1) ^ -(value & 1)

    @staticmethod
    def encode_signed(value: int) -> int:
        """Encode signed integer as zigzag."""
        return (value << 1) ^ (value >> 63)


WIRE_TYPES = {
    0: 'varint',
    1: 'fixed64',
    2: 'length-delimited',
    3: 'start-group',
    4: 'end-group',
    5: 'fixed32',
}


class ProtocolBufferParser:
    """Parse Protocol Buffer messages."""

    def __init__(self):
        self.fields: Dict[int, Dict] = {}
        self.raw_data = b''
        self.decoded: Dict[int, Any] = {}

    def parse(self, data: bytes) -> Dict[int, Any]:
        """Parse protobuf message data."""
        self.raw_data = data
        self.decoded = {}
        offset = 0

        while offset < len(data):
            try:
                tag, offset = VarintDecoder.decode(data, offset)
                field_num = tag >> 3
                wire_type = tag & 0x07

                if wire_type == 0:
                    value, offset = VarintDecoder.decode(data, offset)
                    self.decoded[field_num] = {
                        'wire_type': 'varint',
                        'value': value,
                        'decoded_signed': VarintDecoder.decode_signed(value)
                    }
                elif wire_type == 1:
                    if offset + 8 > len(data):
                        break
                    value = struct.unpack_from('<Q', data, offset)[0]
                    offset += 8
                    self.decoded[field_num] = {
                        'wire_type': 'fixed64',
                        'value': value
                    }
                elif wire_type == 2:
                    length, offset = VarintDecoder.decode(data, offset)
                    value = data[offset:offset + length]
                    offset += length
                    self.decoded[field_num] = {
                        'wire_type': 'length-delimited',
                        'value': value.hex(),
                        'raw': value,
                        'as_string': self._try_string(value)
                    }
                elif wire_type == 5:
                    if offset + 4 > len(data):
                        break
                    value = struct.unpack_from('<I', data, offset)[0]
                    offset += 4
                    self.decoded[field_num] = {
                        'wire_type': 'fixed32',
                        'value': value
                    }
                else:
                    break
            except (ValueError, struct.error):
                break

        return self.decoded

    def _try_string(self, data: bytes) -> Optional[str]:
        """Try to decode bytes as UTF-8 string."""
        try:
            decoded = data.decode('utf-8')
            if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in decoded):
                return decoded
        except UnicodeDecodeError:
            pass
        return None

    def get_fields(self) -> Dict[int, Any]:
        """Get parsed fields."""
        return {
            num: info['value'] if 'raw' not in info else info.get('as_string', info['value'])
            for num, info in self.decoded.items()
        }

    def get_field(self, field_num: int) -> Optional[Any]:
        info = self.decoded.get(field_num)
        if info:
            return info['value']
        return None

    def to_dict(self) -> Dict:
        return {
            'fields': {
                str(k): {
                    'wire_type': v['wire_type'],
                    'value': v['value']
                }
                for k, v in self.decoded.items()
            },
            'raw_hex': self.raw_data.hex()
        }


class GRPCDecoder:
    """Decode gRPC frames (Length-Prefixed Message framing)."""

    GRPC_HEADER_SIZE = 5
    GRPC_COMPRESSED = 0x01
    GRPC_MESSAGE = 0x00

    def __init__(self):
        self.frames: List[Dict] = []
        self.decompressed_frames: List[bytes] = []

    def decode_frame(self, data: bytes) -> Optional[Dict]:
        """Decode a single gRPC frame."""
        if len(data) < self.GRPC_HEADER_SIZE:
            return None

        compressed = data[0]
        msg_type = struct.unpack_from('>I', data, 1)[0]

        if compressed & self.GRPC_COMPRESSED:
            raise ValueError("Compressed frames not supported without decompressor")

        frame = {
            'compressed': bool(compressed & self.GRPC_COMPRESSED),
            'message_length': msg_type,
            'data': data[self.GRPC_HEADER_SIZE:self.GRPC_HEADER_SIZE + msg_type],
            'total_size': self.GRPC_HEADER_SIZE + msg_type
        }
        frame['data_hex'] = frame['data'].hex()
        self.frames.append(frame)
        return frame

    def decode_stream(self, data: bytes) -> List[Dict]:
        """Decode multiple gRPC frames from a stream."""
        frames = []
        offset = 0

        while offset < len(data):
            if offset + self.GRPC_HEADER_SIZE > len(data):
                break

            compressed = data[offset]
            msg_length = struct.unpack_from('>I', data, offset + 1)[0]
            offset += self.GRPC_HEADER_SIZE

            if offset + msg_length > len(data):
                break

            frame = {
                'compressed': bool(compressed & self.GRPC_COMPRESSED),
                'message_length': msg_length,
                'data': data[offset:offset + msg_length],
                'offset': offset - self.GRPC_HEADER_SIZE
            }
            frame['data_hex'] = frame['data'].hex()
            frames.append(frame)
            offset += msg_length

        self.frames.extend(frames)
        return frames

    @staticmethod
    def create_frame(data: bytes, compressed: bool = False) -> bytes:
        """Create a gRPC frame."""
        flag = 0x01 if compressed else 0x00
        header = struct.pack('>BI', flag, len(data))
        return header + data

    def get_summaries(self) -> List[Dict]:
        return [
            {
                'frame_idx': i,
                'compressed': f['compressed'],
                'length': f['message_length'],
                'data_preview': f.get('data_hex', '')[:64]
            }
            for i, f in enumerate(self.frames)
        ]


class BinaryProtocolAnalyzer:
    """Analyze custom binary protocols."""

    def __init__(self):
        self.specs: Dict[str, Dict] = {}
        self.parsed_messages: List[Dict] = []

    def define_spec(self, name: str, fields: List[Dict]) -> None:
        """Define a protocol specification.

        fields: [{'name': 'type', 'format': 'B', 'offset': 0}, ...]
        """
        self.specs[name] = {
            'fields': fields,
            'total_size': sum(
                struct.calcsize(f['format']) for f in fields
            )
        }

    def parse(self, data: bytes, spec_name: str) -> Dict:
        """Parse data according to spec."""
        if spec_name not in self.specs:
            raise ValueError(f"Unknown spec: {spec_name}")

        spec = self.specs[spec_name]
        result = {'spec': spec_name, 'fields': {}}

        sorted_fields = sorted(spec['fields'], key=lambda f: f['offset'])

        for field in sorted_fields:
            offset = field['offset']
            fmt = field['format']
            size = struct.calcsize(fmt)

            if offset + size <= len(data):
                value = struct.unpack_from(fmt, data, offset)[0]
                result['fields'][field['name']] = {
                    'value': value,
                    'offset': offset,
                    'format': fmt,
                    'hex': hex(value) if isinstance(value, int) else str(value)
                }

        result['raw_hex'] = data.hex()
        self.parsed_messages.append(result)
        return result

    def create_message(self, spec_name: str, values: Dict[str, Any]) -> bytes:
        """Create a binary message from spec and values."""
        if spec_name not in self.specs:
            raise ValueError(f"Unknown spec: {spec_name}")

        spec = self.specs[spec_name]
        buffer = bytearray(spec['total_size'])

        for field in spec['fields']:
            if field['name'] in values:
                struct.pack_into(
                    field['format'],
                    buffer,
                    field['offset'],
                    values[field['name']]
                )

        return bytes(buffer)

    def auto_detect(self, data: bytes) -> List[Dict]:
        """Auto-detect common patterns in binary data."""
        patterns = []

        if len(data) >= 2:
            val16 = struct.unpack_from('<H', data, 0)[0]
            patterns.append({
                'type': 'uint16_le',
                'offset': 0,
                'value': val16,
                'hex': hex(val16)
            })

        if len(data) >= 4:
            val32 = struct.unpack_from('<I', data, 0)[0]
            patterns.append({
                'type': 'uint32_le',
                'offset': 0,
                'value': val32,
                'hex': hex(val32)
            })

        if len(data) >= 4:
            val32be = struct.unpack_from('>I', data, 0)[0]
            patterns.append({
                'type': 'uint32_be',
                'offset': 0,
                'value': val32be,
                'hex': hex(val32be)
            })

        return patterns


class FieldExtractor:
    """Extract and map fields from parsed protocol data."""

    def __init__(self):
        self.mappings: Dict[str, Dict] = {}
        self.extracted: List[Dict] = []

    def add_mapping(self, name: str, field_map: Dict[int, str]) -> None:
        """Add field mapping (field_number -> name)."""
        self.mappings[name] = field_map

    def extract_protobuf(self, parsed: Dict[int, Any],
                         mapping_name: str = None) -> Dict:
        """Extract named fields from parsed protobuf."""
        mapping = self.mappings.get(mapping_name, {}) if mapping_name else {}
        result = {}

        for field_num, info in parsed.items():
            name = mapping.get(field_num, f'field_{field_num}')
            if isinstance(info, dict):
                result[name] = info.get('value', info)
            else:
                result[name] = info

        self.extracted.append(result)
        return result

    def extract_binary(self, parsed: Dict,
                       mapping_name: str = None) -> Dict:
        """Extract named fields from parsed binary message."""
        mapping = self.mappings.get(mapping_name, {}) if mapping_name else {}
        result = {}

        fields = parsed.get('fields', {})
        for fname, finfo in fields.items():
            mapped_name = mapping.get(fname, fname)
            result[mapped_name] = finfo.get('value', finfo)

        self.extracted.append(result)
        return result

    def extract_grpc_payload(self, frame: Dict,
                             parser: ProtocolBufferParser = None) -> Dict:
        """Extract fields from gRPC frame data."""
        result = {
            'compressed': frame.get('compressed', False),
            'message_length': frame.get('message_length', 0),
        }

        if parser and 'data' in frame:
            fields = parser.parse(frame['data'])
            result['protobuf_fields'] = {
                str(k): v.get('value', v) for k, v in fields.items()
            }

        return result

    def get_all_extracted(self) -> List[Dict]:
        return self.extracted


class WireProtocolAnalyzer:
    """Main wire protocol analyzer combining all components."""

    def __init__(self):
        self.varint = VarintDecoder()
        self.protobuf = ProtocolBufferParser()
        self.grpc = GRPCDecoder()
        self.binary = BinaryProtocolAnalyzer()
        self.extractor = FieldExtractor()

    def analyze_protobuf(self, data: bytes) -> Dict:
        parsed = self.protobuf.parse(data)
        return self.protobuf.to_dict()

    def analyze_grpc(self, data: bytes) -> List[Dict]:
        frames = self.grpc.decode_stream(data)
        return self.grpc.get_summaries()

    def analyze_binary(self, data: bytes, spec_name: str = None) -> Dict:
        if spec_name and spec_name in self.binary.specs:
            return self.binary.parse(data, spec_name)
        return {
            'patterns': self.binary.auto_detect(data),
            'raw_hex': data.hex(),
            'length': len(data)
        }

    def create_sample_protobuf(self) -> bytes:
        """Create sample protobuf message for testing."""
        msg = bytearray()
        msg.extend(VarintDecoder.encode(1 << 3 | 0))
        msg.extend(VarintDecoder.encode(42))
        msg.extend(VarintDecoder.encode(2 << 3 | 2))
        msg.extend(VarintDecoder.encode(5))
        msg.extend(b'hello')
        msg.extend(VarintDecoder.encode(3 << 3 | 0))
        msg.extend(VarintDecoder.encode(VarintDecoder.encode_signed(-15)))
        return bytes(msg)

    def create_sample_grpc_frame(self) -> bytes:
        """Create sample gRPC frame for testing."""
        payload = self.create_sample_protobuf()
        return GRPCDecoder.create_frame(payload)

    def define_custom_protocol(self) -> None:
        """Define a sample custom protocol."""
        self.binary.define_spec('custom_header', [
            {'name': 'magic', 'format': 'H', 'offset': 0},
            {'name': 'version', 'format': 'B', 'offset': 2},
            {'name': 'msg_type', 'format': 'B', 'offset': 3},
            {'name': 'length', 'format': '<H', 'offset': 4},
        ])


if __name__ == "__main__":
    print("=== Wire Protocol Analyzer ===")
    analyzer = WireProtocolAnalyzer()

    pb_data = analyzer.create_sample_protobuf()
    print("\n--- Protobuf Analysis ---")
    result = analyzer.analyze_protobuf(pb_data)
    print(json.dumps(result, indent=2, default=str))

    grpc_frame = analyzer.create_sample_grpc_frame()
    print("\n--- gRPC Analysis ---")
    frames = analyzer.analyze_grpc(grpc_frame)
    print(json.dumps(frames, indent=2, default=str))

    print("\n--- Binary Auto-Detection ---")
    sample = struct.pack('<HH', 0x1234, 0x5678) + b'\x00\x01'
    result = analyzer.analyze_binary(sample)
    print(json.dumps(result, indent=2, default=str))

    print("\n--- Varint Encoding ---")
    for val in [0, 127, 128, 300, 16384]:
        encoded = VarintDecoder.encode(val)
        decoded, _ = VarintDecoder.decode(encoded)
        print(f"  {val} -> {encoded.hex()} -> {decoded}")
