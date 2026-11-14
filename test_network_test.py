import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import network_test as nt


class SamplingTests(unittest.TestCase):
    def sample(self, system, output, code=0):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(nt.socket, 'getaddrinfo', return_value=[(None, None, None, None, ('127.0.0.1', 0))]):
                with patch.object(nt, 'run', return_value=(code, output)):
                    return nt.sample_target('TEST', 'example.test', Namespace(count=1, timeout=1), system, Path(directory))

    def test_windows_chinese_upper_bound(self):
        result = self.sample('win', '来自 127.0.0.1 的回复: 字节=32 时间<1ms TTL=128')
        self.assertEqual(result['received'], 1)
        self.assertEqual(result['avg_ms'], 1)
        self.assertEqual(result['latency_upper_bound_samples'], 1)

    def test_windows_unreachable_is_not_success(self):
        result = self.sample('win', 'Reply from 10.0.0.1: Destination host unreachable.')
        self.assertEqual(result['received'], 0)
        self.assertEqual(result['loss_percent'], 100)

    def test_unix_latency(self):
        for system in ('linux', 'mac'):
            with self.subTest(system=system):
                result = self.sample(system, '64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.123 ms')
                self.assertEqual(result['avg_ms'], 0.123)
                self.assertEqual(result['status'], 'completed')

    def test_missing_latency_not_invented(self):
        result = self.sample('win', 'Reply from 127.0.0.1: bytes=32 TTL=128')
        self.assertEqual(result['received'], 1)
        self.assertIsNone(result['avg_ms'])

    def test_permission_error_not_packet_loss(self):
        result = self.sample('linux', 'ping: socket: Operation not permitted', 2)
        self.assertEqual(result['status'], 'command_error')
        self.assertIsNone(result['loss_percent'])

    def test_empty_command_error_not_packet_loss(self):
        result = self.sample('linux', '', 2)
        self.assertEqual(result['status'], 'command_error')
        self.assertIsNone(result['loss_percent'])

    def test_mac_no_reply_exit_two(self):
        result = self.sample('mac', '1 packets transmitted, 0 packets received, 100.0% packet loss', 2)
        self.assertEqual(result['status'], 'no_echo_reply')
        self.assertEqual(result['attempted'], 1)
        self.assertEqual(result['loss_percent'], 100)

    def test_mac_error_exit_one(self):
        result = self.sample('mac', 'ping: invalid option -- x', 1)
        self.assertEqual(result['status'], 'command_error')
        self.assertEqual(result['attempted'], 0)
        self.assertIsNone(result['loss_percent'])

    def test_linux_no_reply_exit_one(self):
        result = self.sample('linux', '1 packets transmitted, 0 received, 100% packet loss', 1)
        self.assertEqual(result['status'], 'no_echo_reply')
        self.assertEqual(result['loss_percent'], 100)

    def test_dns_failure_not_packet_loss(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(nt.socket, 'getaddrinfo', side_effect=nt.socket.gaierror('not found')):
                result = nt.sample_target('TEST', 'invalid.test', Namespace(count=1, timeout=1), 'linux', Path(directory))
        self.assertEqual(result['status'], 'dns_error')
        self.assertIsNone(result['loss_percent'])


if __name__ == '__main__':
    unittest.main()
