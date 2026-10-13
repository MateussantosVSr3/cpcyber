"""Single-operator authentication: scrypt hashes and revocable opaque sessions."""
import hashlib
import hmac
import os
import secrets
import time

from sast import storage

COOKIE = 'sast_session'
TTL = 8 * 60 * 60


def hash_password(value):
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(value.encode(), salt=salt, n=16384, r=8, p=1)
    return 'scrypt:' + salt.hex() + ':' + derived.hex()


def configured():
    return bool(os.getenv('SAST_USERNAME') and os.getenv('SAST_PASSWORD_HASH'))


def verify(username, password):
    encoded = os.getenv('SAST_PASSWORD_HASH', '')
    try:
        algorithm, salt, expected = encoded.split(':')
        if algorithm != 'scrypt':
            return False
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
        valid_password = hmac.compare_digest(actual, expected)
        return hmac.compare_digest(username.encode(), os.getenv('SAST_USERNAME', '').encode()) and valid_password
    except (ValueError, TypeError):
        return False


def identity_version():
    return hashlib.sha256((os.getenv('SAST_USERNAME', '') + os.getenv('SAST_PASSWORD_HASH', '')).encode()).hexdigest()


def issue_session():
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    with storage.connection() as conn:
        storage.run(conn, 'DELETE FROM sessions WHERE expires < ?', (int(time.time()),))
        storage.run(conn, 'INSERT INTO sessions (digest, expires, identity_version) VALUES (?, ?, ?)',
                    (digest, int(time.time()) + TTL, identity_version()))
    return token


def user_for_session(token):
    if not configured() or not token or len(token) > 128:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    with storage.connection() as conn:
        row = storage.run(conn, 'SELECT expires, identity_version FROM sessions WHERE digest = ?', (digest,)).fetchone()
    if row and row[0] > time.time() and hmac.compare_digest(row[1], identity_version()):
        return os.environ['SAST_USERNAME']
    return None


def revoke(token):
    if token:
        with storage.connection() as conn:
            storage.run(conn, 'DELETE FROM sessions WHERE digest = ?', (hashlib.sha256(token.encode()).hexdigest(),))
