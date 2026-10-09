import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('demo_entrypoint',Path(__file__).resolve().parents[1]/'docker/entrypoint.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)


class DemoFenceTests(unittest.TestCase):
    def test_pending_fails_closed_and_explicit_reset_phases_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker=Path(tmp)/'reset-pending.json'
            marker.write_text(json.dumps({'deployment':'vaultcontext-demo','generation':'2026-10-09','phase':'pending'}));marker.chmod(0o600)
            env={'VAULTCONTEXT_DEMO_MODE':'true','VAULTCONTEXT_DEMO_GENERATION':'2026-10-09','VAULTCONTEXT_DEMO_RESET_FENCE':str(marker)}
            with patch.dict(os.environ,env,clear=True):
                for mode in ('start','init','serve','verify'):
                    with self.assertRaises(runtime.StartupError):runtime.demo_fence(mode)
                marker.write_text(json.dumps({'deployment':'vaultcontext-demo','generation':'2026-10-09','phase':'purged'}))
                with patch.dict(os.environ,{'VAULTCONTEXT_DEMO_RESET_PHASE':'initialize'}):runtime.demo_fence('init')
                with self.assertRaises(runtime.StartupError):runtime.demo_fence('init')
                marker.unlink();runtime.demo_fence('start')

    def test_fence_must_live_outside_disposable_database(self):
        with patch.dict(os.environ,{'VAULTCONTEXT_DEMO_MODE':'true','VAULTCONTEXT_DEMO_RESET_FENCE':str(runtime.DATA/'fence')},clear=True), self.assertRaises(runtime.StartupError):
            runtime.demo_fence('start')
