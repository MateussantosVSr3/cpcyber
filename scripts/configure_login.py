"""Configure a single operator without storing plaintext passwords."""
import argparse
import getpass
import os
import re
import sys
from pathlib import Path

from sast.auth import hash_password


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--username', required=True)
    parser.add_argument('--hash-stdin', action='store_true', help='Receber somente um hash scrypt já calculado')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', args.username):
        raise SystemExit('Nome de usuário inválido.')
    if args.hash_stdin:
        encoded = sys.stdin.read().strip()
        if not re.fullmatch(r'scrypt:[0-9a-f]{32}:[0-9a-f]{128}', encoded):
            raise SystemExit('Hash inválido.')
    else:
        value = getpass.getpass('Nova senha: ')
        if len(value) < 12 or value != getpass.getpass('Repita a senha: '):
            raise SystemExit('Use pelo menos 12 caracteres e confirme a mesma senha.')
        encoded = hash_password(value)
    path = Path('.env')
    lines = path.read_text(encoding='utf-8').splitlines()
    lines = [line for line in lines if not line.startswith(('SAST_USERNAME=', 'SAST_PASSWORD_HASH='))]
    lines += ['SAST_USERNAME=' + args.username, 'SAST_PASSWORD_HASH=' + encoded]
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    if os.name != 'nt':
        path.chmod(0o600)
    print('Credenciais atualizadas no .env. Recrie API/worker para aplicar. Nenhuma senha foi exibida.')


if __name__ == '__main__':
    main()
