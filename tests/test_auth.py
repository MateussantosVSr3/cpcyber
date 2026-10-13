import asyncio
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from sast import auth, storage
from tests.test_api import request


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'DATABASE_URL': 'sqlite:///' + str(Path(self.directory.name) / 'auth.db'),
            'SAST_USERNAME': 'test.operator', 'SAST_PASSWORD_HASH': auth.hash_password('fixture-only-password')})
        self.env.start()
        storage.init()

    def tearDown(self):
        self.env.stop()
        self.directory.cleanup()

    def test_private_routes_require_login(self):
        for route in ['/api/scans', '/api/metrics', '/api/codex/status', '/api/scans/example/report.pdf']:
            self.assertEqual(asyncio.run(request('GET', route))[0], 401)
        self.assertEqual(asyncio.run(request('GET', '/'))[0], 303)
        self.assertEqual(asyncio.run(request('GET', '/health'))[0], 200)
        self.assertEqual(asyncio.run(request('GET', '/login'))[0], 200)

    def test_login_and_logout_revoke_session(self):
        payload = {'username': 'test.operator', 'password': 'fixture-only-password'}
        status, _, headers = asyncio.run(request('POST', '/api/auth/login', payload, {'x-sast-client': 'dashboard'}, True))
        self.assertEqual(status, 200)
        cookie = headers[b'set-cookie'].decode()
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=strict', cookie)
        token = cookie.split(';')[0].split('=', 1)[1]
        self.assertEqual(auth.user_for_session(token), 'test.operator')
        status, _ = asyncio.run(request('POST', '/api/auth/logout', {}, {'x-sast-client': 'dashboard', 'cookie': cookie.split(';')[0]}))
        self.assertEqual(status, 200)
        self.assertIsNone(auth.user_for_session(token))

    def test_wrong_password_and_cross_origin_denied(self):
        payload = {'username': 'test.operator', 'password': 'wrong-fixture'}
        self.assertEqual(asyncio.run(request('POST', '/api/auth/login', payload, {'x-sast-client': 'dashboard'}))[0], 401)
        self.assertEqual(asyncio.run(request('POST', '/api/auth/login', payload, {'x-sast-client': 'dashboard', 'origin': 'https://evil.example'}))[0], 403)

    def test_session_expiry_and_identity_rotation(self):
        token = auth.issue_session()
        with patch('sast.auth.time.time', return_value=time.time() + auth.TTL + 1):
            self.assertIsNone(auth.user_for_session(token))
        with patch.dict(os.environ, {'SAST_PASSWORD_HASH': auth.hash_password('rotated-fixture-only')}):
            self.assertIsNone(auth.user_for_session(token))
        self.assertIsNone(auth.user_for_session('invalid'))

    def test_sessions_store_only_token_digests(self):
        token = auth.issue_session()
        with storage.connection() as conn:
            row = storage.run(conn, 'SELECT digest FROM sessions').fetchone()
        self.assertNotEqual(row[0], token)
        self.assertEqual(len(row[0]), 64)
