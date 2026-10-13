"""Prove CLI exit status 1/0/2 without executing submitted source."""
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / 'sample.js'
        for source, expected in [('eval(userInput);', 1), ('console.log("ok");', 0), ('function {', 2)]:
            path.write_text(source, encoding='utf-8')
            result = subprocess.run([sys.executable, '-m', 'sast.cli', str(path)], capture_output=True, text=True)
            if result.returncode != expected:
                raise SystemExit(f'Gate incorreto: esperado {expected}, recebido {result.returncode}\n{result.stderr}')
            print(result.stderr.strip())
    print('Contrato de CI confirmado: vulnerável=1, seguro=0, erro=2.')


if __name__ == '__main__':
    main()
