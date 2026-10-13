"""Fixture didática. Nunca execute. Não contém credenciais reais."""
import os
from flask import request

password = "demo-only-password"


def search(cursor):
    term = request.args.get("q")
    query = f"SELECT * FROM users WHERE name = '{term}'"
    cursor.execute(query)
    os.system("echo " + term)
    return eval(term)
