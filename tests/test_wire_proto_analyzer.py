import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wire_proto_analyzer import (
    BinaryProtocolAnalyzer,
    FieldExtractor,
    GRPCDecoder,
    ProtocolBufferParser,
    VarintDecoder,
    WireProtocolAnalyzer,
    WireProtocolScanner,
    _grpc_payloads,
    build_fixtures,
    run_demo,
)


class VarintTests(unittest.TestCase):
    def test_roundtrip_values(self):
        for value in [0, 1, 127, 128, 300, 16384, 0xFFFFFFFF]:
            encoded = VarintDecoder.encode(value)
            decoded, offset = VarintDecoder.decode(encoded)
            self.assertEqual(decoded, value)
            self.assertEqual(offset, len(encoded))

    def test_known_encodings(self):
        self.assertEqual(VarintDecoder.encode(0).hex(), '00')
        self.assertEqual(VarintDecoder.encode(1).hex(), '01')
        self.assertEqual(VarintDecoder.encode(300).hex(), 'ac02')

    def test_zigzag(self):
        self.assertEqual(VarintDecoder.decode_signed(0), 0)
        self.assertEqual(VarintDecoder.decode_signed(1), -1)
        self.assertEqual(VarintDecoder.decode_signed(2), 1)
        for value in range(-1000, 1000):
            encoded = VarintDecoder.encode_signed(value)
            self.assertEqual(VarintDecoder.decode_signed(encoded), value)

    def test_incomplete_varint_raises(self):
        with self.assertRaises(ValueError):
            VarintDecoder.decode(b'\x80')

    def test_oversized_varint_raises(self):
        with self.assertRaises(ValueError):
            VarintDecoder.decode(b'\x81' * 12)


class ProtocolBufferTests(unittest.TestCase):
    def test_parse_known_message(self):
        # field 1 varint 42; field 2 len 'hello'; field 3 varint -15 zigzag
        parser = ProtocolBufferParser()
        msg = (b'\x08\x2a'
               b'\x12\x05hello'
               b'\x18\x1d')
        parsed = parser.parse(msg)
        self.assertEqual(parsed[1]['value'], 42)
        self.assertEqual(parsed[2]['as_string'], 'hello')
        self.assertEqual(parsed[3]['decoded_signed'], -15)

    def test_build_and_parse_roundtrip(self):
        original = ProtocolBufferParser.build([
            (1, 0, 42), (2, 2, 'hello'), (3, 0, -15), (4, 2, b'\x00\x01\x02'),
        ])
        self.assertEqual(original, b'\x08\x2a\x12\x05hello\x18\x1d'
                         + b'\x22\x03\x00\x01\x02')
        parser = ProtocolBufferParser()
        parsed = parser.parse(original)
        self.assertEqual(parsed[1]['value'], 42)
        self.assertEqual(parsed[2]['as_string'], 'hello')
        self.assertEqual(parsed[3]['decoded_signed'], -15)
        self.assertEqual(parsed[4]['raw'], b'\x00\x01\x02')

    def test_malformed_data_never_raises(self):
        parser = ProtocolBufferParser()
        for blob in [b'', b'\x80', b'\x80\x80\x80', b'\xff' * 8,
                     b'\x0a\xff\xff\xff\xff\xff\x00']:
            result = parser.parse(blob)
            self.assertIsInstance(result, dict)

    def test_wire_type_unknown_stops(self):
        parser = ProtocolBufferParser()
        parsed = parser.parse(b'\x0e\x00')
        self.assertNotIn(1, parsed)


class GRPCTests(unittest.TestCase):
    def test_create_and_decode_frame(self):
        payload = b'hello world'
        frame = GRPCDecoder.create_frame(payload)
        self.assertEqual(frame[0], 0x00)
        self.assertEqual(struct.unpack_from('>I', frame, 1)[0], len(payload))
        decoder = GRPCDecoder()
        decoded = decoder.decode_frame(frame)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded['data'], payload)
        self.assertFalse(decoded['compressed'])

    def test_stream_multiple_frames(self):
        frame_a = GRPCDecoder.create_frame(b'\x01\x02\x03')
        frame_b = GRPCDecoder.create_frame(b'abc')
        stream = frame_a + frame_b
        decoder = GRPCDecoder()
        frames = decoder.decode_stream(stream)
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0]['data'], b'\x01\x02\x03')
        self.assertEqual(frames[1]['data'], b'abc')

    def test_truncated_stream_ignored(self):
        decoder = GRPCDecoder()
        frames = decoder.decode_stream(b'\x00\x00\x00\x00\x0a\x01')
        self.assertEqual(frames, [])


class BinaryProtocolTests(unittest.TestCase):
    def test_spec_parse(self):
        analyzer = BinaryProtocolAnalyzer()
        analyzer.define_spec('header', [
            {'name': 'magic', 'format': 'H', 'offset': 0},
            {'name': 'version', 'format': 'B', 'offset': 2},
            {'name': 'type', 'format': 'B', 'offset': 3},
        ])
        result = analyzer.parse(b'\x34\x12\x01\x02', 'header')
        self.assertEqual(result['fields']['magic']['value'], 0x1234)
        self.assertEqual(result['fields']['version']['value'], 1)

    def test_spec_create_roundtrip(self):
        analyzer = BinaryProtocolAnalyzer()
        analyzer.define_spec('header', [
            {'name': 'magic', 'format': 'H', 'offset': 0},
            {'name': 'length', 'format': '<H', 'offset': 2},
        ])
        msg = analyzer.create_message('header', {'magic': 0xBEAF, 'length': 7})
        parsed = analyzer.parse(msg, 'header')
        self.assertEqual(parsed['fields']['magic']['value'], 0xBEAF)
        self.assertEqual(parsed['fields']['length']['value'], 7)

    def test_unknown_spec_raises(self):
        analyzer = BinaryProtocolAnalyzer()
        with self.assertRaises(ValueError):
            analyzer.parse(b'\x00\x01', 'nope')
        with self.assertRaises(ValueError):
            analyzer.create_message('nope', {})

    def test_auto_detect(self):
        analyzer = BinaryProtocolAnalyzer()
        patterns = analyzer.auto_detect(struct.pack('<I', 0xDEADBEEF))
        types = {p['type'] for p in patterns}
        self.assertIn('uint32_le', types)
        self.assertIn('uint16_le', types)


class FieldExtractorTests(unittest.TestCase):
    def test_protobuf_mapping(self):
        parser = ProtocolBufferParser()
        parsed = parser.parse(b'\x08\x2a\x12\x05hello')
        extractor = FieldExtractor()
        extractor.add_mapping('login', {1: 'user_id', 2: 'username'})
        result = extractor.extract_protobuf(parsed, 'login')
        self.assertEqual(result['user_id'], 42)
        self.assertEqual(result['username'], 'hello')

    def test_binary_mapping(self):
        binary = BinaryProtocolAnalyzer()
        binary.define_spec('h', [{'name': 'id', 'format': 'B', 'offset': 0}])
        parsed = binary.parse(b'\x2a', 'h')
        extractor = FieldExtractor()
        extractor.add_mapping('h', {'id': 'request_id'})
        result = extractor.extract_binary(parsed, 'h')
        self.assertEqual(result['request_id'], 42)


class ScannerTests(unittest.TestCase):
    def test_find_replays(self):
        scanner = WireProtocolScanner()
        groups = scanner.find_replays([b'abc', b'def', b'abc', b'abc'])
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]['indexes'], [0, 2, 3])

    def test_cleartext_and_replay_findings(self):
        scanner = WireProtocolScanner()
        entry, traffic = _grpc_payloads()
        frames = GRPCDecoder().decode_stream(traffic)
        findings = scanner.scan_traffic(frames)
        rules = {f['rule'] for f in findings}
        self.assertIn('cleartext_field', rules)
        self.assertIn('replayed_frame', rules)

    def test_length_overrun_finding(self):
        scanner = WireProtocolScanner()
        findings = scanner.scan_traffic([{
            'data': b'\x01\x02', 'message_length': 5,
            'offset': 0, 'compressed': False,
        }])
        self.assertEqual(findings[0]['rule'], 'length_overrun')
        self.assertEqual(findings[0]['severity'], 'high')

    def test_truncated_frame_finding(self):
        scanner = WireProtocolScanner()
        entry, traffic = _grpc_payloads()
        findings = scanner.scan_stream(traffic)
        rules = {f['rule'] for f in findings}
        self.assertIn('truncated_frame', rules)
        truncated = [f for f in findings if f['rule'] == 'truncated_frame']
        self.assertEqual(truncated[0]['severity'], 'high')

    def test_fuzz_robustness_no_crash(self):
        scanner = WireProtocolScanner()
        _, traffic = _grpc_payloads()
        frames = GRPCDecoder().decode_stream(traffic)
        report = scanner.fuzz_robustness(frames[0]['data'], bits=8, seed=7)
        self.assertEqual(report['crash_rounds'], 0)
        self.assertIn('parsed_ok', report)


class DemoAndFixtureTests(unittest.TestCase):
    def test_demo_report(self):
        report = run_demo()
        self.assertEqual(report['totals']['frames'], 6)
        self.assertGreaterEqual(report['totals']['findings'], 10)
        self.assertEqual(report['frame_count'], 6)

    def test_fixtures_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsInstance(build_fixtures(force=True), dict)

    def test_cli_demo_subprocess(self):
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.dirname(here)
        result = subprocess.run(
            [sys.executable, os.path.join(root, 'wire_proto_analyzer.py')],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('replayed_frame', result.stdout)

    def test_cli_demo_roundtrip_json(self):
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.dirname(here)
        with tempfile.TemporaryDirectory() as tmp:
            report_path = os.path.join(tmp, 'report.json')
            result = subprocess.run(
                [sys.executable,
                 os.path.join(root, 'wire_proto_analyzer.py'),
                 '--json', '--output', report_path],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(report_path) as f:
                report = json.load(f)
            self.assertIn('findings', report)
            self.assertIn('totals', report)


if __name__ == '__main__':
    unittest.main()