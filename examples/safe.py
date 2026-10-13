"""Exemplo de consulta parametrizada; apenas analisado, nunca executado."""
import os
from flask import request

password = os.environ.get("APP_PASSWORD")


def search(cursor):
    term = request.args.get("q")
    cursor.execute("SELECT * FROM users WHERE name = ?", (term,))
    return cursor.fetchall()
