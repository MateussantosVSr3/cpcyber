"""Local authenticated demo: reuse login hash, but never production DB/Redis URLs."""
import os
from pathlib import Path

import uvicorn


def main():
    path = Path('.env')
    if not path.exists():
        raise SystemExit('Execute scripts/init_env.py e python -m scripts.configure_login primeiro.')
    for line in path.read_text(encoding='utf-8').splitlines():
        key, separator, value = line.partition('=')
        if separator and key in {'SAST_USERNAME', 'SAST_PASSWORD_HASH'}:
            os.environ[key] = value
    uvicorn.run('sast.api:app', host='127.0.0.1', port=8000)


if __name__ == '__main__':
    main()
