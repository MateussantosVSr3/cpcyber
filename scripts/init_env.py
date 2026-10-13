from pathlib import Path
import secrets

path = Path(__file__).resolve().parent.parent / ".env"
if path.exists():
    print(".env já existe; configuração preservada.")
else:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(
            "POSTGRES_PASSWORD=" + secrets.token_hex(24)
            + "\nBRIDGE_TOKEN=" + secrets.token_hex(32)
            + "\nCODEX_VERSION=0.162.1\n"
        )
    print(".env criado com segredos aleatórios. Não versionar.")
