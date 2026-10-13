from pathlib import Path
import secrets
import hashlib


def random_login_hash():
    salt = secrets.token_bytes(16)
    value = hashlib.scrypt(secrets.token_bytes(32), salt=salt, n=16384, r=8, p=1)
    return 'scrypt:' + salt.hex() + ':' + value.hex()

path = Path(__file__).resolve().parent.parent / ".env"
if path.exists():
    print(".env já existe; configuração preservada.")
else:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(
            "POSTGRES_PASSWORD=" + secrets.token_hex(24)
            + "\nBRIDGE_TOKEN=" + secrets.token_hex(32)
            + "\nCODEX_VERSION=0.162.1\n"
            + "SAST_USERNAME=admin\nSAST_PASSWORD_HASH=" + random_login_hash() + "\n"
        )
    print(".env criado com segredos aleatórios. Não versionar.")
    print("Defina uma senha: python -m scripts.configure_login --username SEU_USUARIO")
