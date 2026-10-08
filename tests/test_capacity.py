"""Pure stdlib tests: python -m unittest discover -s tests -p test_capacity.py."""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import os
import unittest
from unittest.mock import patch

from nodelab.capacity import CapacityInputError, simulate
from nodelab.types import PROBE_GATE_OPEN

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


class CapacityTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / 'examples/capacity_synthetic.json').read_text())

    def run_case(self):
        return simulate(self.data, now=NOW)

    def test_example_units_reserve_cost_unknown(self):
        result = self.run_case()
        self.assertEqual(result['available_bytes'], 100 * 2**30 - 10 * 10**9)
        self.assertEqual(result['allocatable_bytes'], 77899345920)
        self.assertEqual(result['demand_bytes'], 41474836480)
        self.assertTrue(result['capacity_sufficient'])
        self.assertEqual(result['known_cost_subtotals'], {'CNY': '25'})
        self.assertEqual(result['missing_cost_groups'], ['G0001'])
        self.assertEqual(result['missing_service_hours_groups'], ['G0001'])
        self.assertFalse(result['profitability_assessed'])

    def test_shared_group_not_multiplied(self):
        r = copy.deepcopy(self.data['resources'][0]); r['id'] = 'R0003'
        self.data['resources'].append(r)
        self.assertEqual(self.run_case()['available_bytes'], 100 * 2**30 - 10 * 10**9)

    def test_duplicate_group_rejected(self):
        self.data['groups'].append(copy.deepcopy(self.data['groups'][0]))
        with self.assertRaises(CapacityInputError): self.run_case()

    def test_expiry_and_unknowns_fail_closed(self):
        for field, value in [('expires_at', '2030-01-31T23:59:59Z'), ('expires_at', None),
                             ('use_authorization', 'unknown'), ('supply_authorization', 'denied'),
                             ('authorization_evidence', None), ('source_evidence', None),
                             ('source', 'unknown'), ('verified', 'unknown')]:
            with self.subTest(field=field, value=value):
                old = self.data['resources'][0][field]
                self.data['resources'][0][field] = value
                self.assertEqual(self.run_case()['allocatable_bytes'], 0)
                self.data['resources'][0][field] = old

    def test_missing_or_misaligned_quota(self):
        for field, value in [('quota', None), ('used', None), ('quota_evidence', None),
                             ('verified', 'unknown'), ('window_end', '2030-03-01T00:00:00Z')]:
            with self.subTest(field=field):
                old = self.data['groups'][0][field]
                self.data['groups'][0][field] = value
                self.assertEqual(self.run_case()['allocatable_bytes'], 0)
                self.data['groups'][0][field] = old

    def test_invalid_numbers(self):
        for value in [-1, 'NaN', float('nan'), float('inf'), '-Infinity', True, '1e999', '0.0000000001']:
            with self.subTest(value=value):
                self.data['free']['per_person']['amount'] = value
                with self.assertRaises(CapacityInputError): self.run_case()

    def test_huge_native_integer_uses_fixed_error(self):
        self.data["free"]["per_person"]["amount"] = 10**5000
        with self.assertRaises(CapacityInputError) as caught:
            self.run_case()
        self.assertEqual(str(caught.exception), "INVALID_NUMBER")

    def test_negative_count_and_reserve(self):
        self.data['free']['people'] = -1
        with self.assertRaises(CapacityInputError): self.run_case()
        self.data['free']['people'] = 1
        for value in [-1, 'NaN', '1.1', True]:
            self.data['reserve_ratio'] = value
            with self.assertRaises(CapacityInputError): self.run_case()

    def test_over_quota_and_demand(self):
        self.data['groups'][0]['used'] = {'amount': 101, 'unit': 'GiB'}
        with self.assertRaises(CapacityInputError): self.run_case()
        self.data['groups'][0]['used'] = {'amount': 100, 'unit': 'GiB'}
        result = self.run_case()
        self.assertFalse(result['capacity_sufficient'])
        self.assertEqual(result['shortfall_bytes'], result['demand_bytes'])

    def test_costs_include_excluded_groups_separate_currencies(self):
        g = copy.deepcopy(self.data['groups'][0]); g.update(id='G0002', cost='3', currency='USD')
        self.data['groups'].append(g)
        result = self.run_case()
        self.assertEqual(result['known_cost_subtotals'], {'CNY': '25', 'USD': '3'})
        self.assertEqual(result['counted_groups'], ['G0001'])
        self.data['groups'][0]['cost'] = None
        self.assertNotIn('CNY', self.run_case()['known_cost_subtotals'])

    def test_invalid_schema_and_private_fields(self):
        self.data['resources'][0]['ip'] = 'private-input'
        with self.assertRaises(CapacityInputError): self.run_case()

    def test_fixed_clock_and_naive_rejection(self):
        self.assertEqual(self.run_case(), self.run_case())
        with self.assertRaises(CapacityInputError): simulate(self.data, now=datetime(2030, 1, 1))
        with self.assertRaises(CapacityInputError): simulate(self.data, now=datetime(2031, 1, 1, tzinfo=timezone.utc))

    def test_network_tripwire_and_gate(self):
        with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')), \
             patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('process forbidden')):
            self.assertFalse(self.run_case()['network_used'])
            self.assertIs(PROBE_GATE_OPEN, False)

    def test_unknown_shared_group_and_no_real_commitment(self):
        self.data['resources'][0]['group'] = None
        result = self.run_case()
        self.assertEqual(result['available_bytes'], 0)
        self.assertEqual(result['committable_capacity_bytes'], 0)
        self.assertFalse(result['service_ready'])
        self.assertFalse(result['reliability_assessed'])
        self.assertIn('SHARED_GROUP_UNKNOWN', result['excluded_resources'][0]['reasons'])

    def test_zero_cost_keeps_unknown_labor(self):
        self.data['groups'][0].update(cost=0, cost_complete=True)
        result = self.run_case()
        self.assertEqual(result['known_cost_subtotals'], {'CNY': '0'})
        self.assertEqual(result['missing_service_hours_groups'], ['G0001'])
        self.assertFalse(result['profitability_assessed'])

    def test_unchanged_input_and_exact_boundary(self):
        before = copy.deepcopy(self.data)
        self.assertEqual(self.run_case()['counted_groups'], ['G0001'])
        self.assertEqual(self.data, before)
        self.data['reserve_ratio'] = 1
        self.assertEqual(self.run_case()['allocatable_bytes'], 0)
        self.data['free']['people'] = self.data['advanced']['people'] = 0
        self.assertTrue(self.run_case()['capacity_sufficient'])

    def test_row_limit_duplicate_resource_and_unknown_group(self):
        self.data['groups'] *= 1001
        with self.assertRaises(CapacityInputError): self.run_case()
        self.setUp()
        self.data['resources'].append(copy.deepcopy(self.data['resources'][0]))
        with self.assertRaises(CapacityInputError): self.run_case()
        self.setUp()
        self.data['resources'][0]['group'] = 'G9999'
        with self.assertRaises(CapacityInputError): self.run_case()

    def test_cli_rejects_invalid_and_unsafe_input(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'scenario.json'
            def reject():
                r = subprocess.run([sys.executable, '-m', 'nodelab.capacity', str(p),
                                    '--now', '2030-01-01T00:00:00Z'],
                                   capture_output=True, text=True, timeout=3)
                self.assertEqual(r.returncode, 2)
                self.assertEqual(r.stdout, '')
                self.assertEqual(json.loads(r.stderr)['error'], 'CAPACITY_INPUT_REJECTED')
                self.assertNotIn(str(p), r.stderr)
            for raw in [b'{"schema_version":1,"schema_version":1}', b'\xff',
                        b'{}' * 300000, b'[' * 2000]:
                p.write_bytes(raw)
                reject()
            p.unlink()
            if hasattr(os, 'mkfifo'):
                os.mkfifo(p)
                reject()
                p.unlink()
            if hasattr(os, 'symlink'):
                p.symlink_to(ROOT / 'examples/capacity_synthetic.json')
                reject()

    def test_cli_arguments_never_echo_private_values(self):
        base = [sys.executable, '-m', 'nodelab.capacity']
        scenario = str(ROOT / 'examples/capacity_synthetic.json')
        for args in [[scenario, '--secret=CANARY_PRIVATE'],
                     [scenario, 'CANARY_PRIVATE'], []]:
            with self.subTest(args=args):
                result = subprocess.run(base + args, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
                self.assertEqual(json.loads(result.stderr),
                                 {'error': 'CAPACITY_INPUT_REJECTED', 'network_used': False})
                self.assertNotIn('CANARY_PRIVATE', result.stderr)
        result = subprocess.run(base + ['--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('--now', result.stdout)
        self.assertEqual(result.stderr, '')

    def test_cli_reproducible(self):
        cmd = [sys.executable, '-m', 'nodelab.capacity', str(ROOT / 'examples/capacity_synthetic.json'), '--now', '2030-01-01T00:00:00Z']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout), self.run_case())


if __name__ == '__main__':
    unittest.main()
