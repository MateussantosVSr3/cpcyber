"""Structural security checks over Tree-sitter trees. Never executes source."""
from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath

from tree_sitter_language_pack import get_parser

LANGUAGES = {'.js': 'javascript', '.jsx': 'javascript', '.ts': 'typescript',
             '.tsx': 'tsx', '.java': 'java', '.php': 'php', '.go': 'go',
             '.cs': 'csharp', '.rb': 'ruby'}
SUPPORTED = set(LANGUAGES)
RULES = {
    'M001': ('HIGH', 'CWE-798', 'Possível segredo hardcoded', 'Use um cofre de segredos ou variável de ambiente e rotacione o valor.'),
    'M002': ('HIGH', 'CWE-95', 'Execução dinâmica de código', 'Substitua avaliação dinâmica por parsing e validação de tipos.'),
    'M003': ('HIGH', 'CWE-78', 'Execução de comando do sistema', 'Evite shells; use argumentos separados e valide entradas por allowlist.'),
    'M004': ('HIGH', 'CWE-89', 'SQL construído dinamicamente', 'Use consultas parametrizadas, separando dados do comando SQL.'),
    'M005': ('MEDIUM', 'CWE-327', 'Hash criptográfico fraco', 'Use SHA-256 para integridade ou Argon2/bcrypt para senhas.'),
    'M006': ('MEDIUM', 'CWE-295', 'Validação TLS desabilitada', 'Habilite a verificação de certificados e configure a cadeia de confiança.'),
    'M007': ('HIGH', 'CWE-79', 'HTML em sink de DOM', 'Use textContent ou sanitização contextual de HTML; confirme a origem dos dados.'),
}
CALLS = {'call_expression', 'new_expression', 'method_invocation', 'invocation_expression',
         'function_call_expression', 'member_call_expression', 'scoped_call_expression', 'call'}
ASSIGNMENTS = {'variable_declarator', 'assignment_expression', 'assignment', 'short_var_declaration',
               'var_spec', 'pair', 'keyed_element', 'property_initializer', 'jsx_attribute'}
STRINGS = {'string', 'string_literal', 'interpreted_string_literal', 'raw_string_literal',
           'encapsed_string', 'template_string', 'verbatim_string_literal', 'character_literal'}


def walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def content(node, source):
    return source[node.start_byte:node.end_byte].decode('utf-8') if node else ''


def field(node, *names):
    for name in names:
        found = node.child_by_field_name(name)
        if found is not None:
            return found
    return None


def context(node, source):
    """Redact whole literal AST nodes, including multiline and interpolated strings."""
    pieces, position = [], node.start_byte
    for child in walk(node):
        if child.type in STRINGS and child.start_byte >= position:
            pieces.append(source[position:child.start_byte].decode('utf-8'))
            pieces.append('"<literal oculto>"')
            position = child.end_byte
    pieces.append(source[position:node.end_byte].decode('utf-8'))
    return ''.join(pieces)[:6000]


def scan_multilang(files):
    findings, errors, parsers = [], [], {}
    for filename, text in files.items():
        language = LANGUAGES.get(PurePosixPath(filename).suffix.lower())
        if not language:
            errors.append({'file': filename, 'message': 'Linguagem não suportada.'})
            continue
        source = text.encode('utf-8')
        root = get_parser(language).parse(source).root_node
        parsers[filename] = 'tree-sitter:' + language
        if root.has_error:
            invalid = next((n for n in walk(root) if n.is_error or n.is_missing), root)
            errors.append({'file': filename, 'line': invalid.start_point.row + 1,
                           'message': 'Código inválido para o parser ' + language + '. Envie o arquivo completo.'})
            continue
        seen = set()

        def add(rule, node):
            identity = (rule, node.start_byte)
            if identity in seen:
                return
            seen.add(identity)
            severity, cwe, title, fix = RULES[rule]
            line, column = node.start_point.row + 1, node.start_point.column + 1
            findings.append({'rule': rule, 'severity': severity, 'cwe': cwe, 'title': title,
                'remediation': fix, 'file': filename, 'line': line, 'column': column,
                'confidence': 'MEDIUM', 'trace': [f'L{line}: nó {node.type} ({language})'],
                'engine': parsers[filename], 'context': context(node, source),
                'fingerprint': hashlib.sha256(f'{filename}:{line}:{column}:{rule}'.encode()).hexdigest()[:24]})

        for node in walk(root):
            if node.type in CALLS:
                target = field(node, 'function', 'constructor', 'name', 'method')
                receiver = field(node, 'object', 'receiver')
                call = (content(receiver, source) + '.' if receiver else '') + content(target, source)
                call = re.sub(r'\s+', '', call)
                leaf = call.split('.')[-1].lower()
                args = field(node, 'arguments')
                if leaf == 'eval' or (node.type == 'new_expression' and call == 'Function'):
                    add('M002', node)
                if call in {'child_process.exec', 'child_process.execSync', 'Runtime.getRuntime().exec',
                            'Process.Start', 'os.exec', 'Kernel.system'} or leaf in {'system', 'shell_exec', 'passthru'}:
                    add('M003', node)
                if leaf in {'md5', 'sha1'} or (call == 'MessageDigest.getInstance' and
                        any(content(a, source).strip('\"\'').upper() in {'MD5', 'SHA1', 'SHA-1'} for a in (args.named_children if args else []))):
                    add('M005', node)
                if call == 'document.write':
                    add('M007', node)
                if language == 'php' and call == 'curl_setopt' and args:
                    arguments = [content(a, source).strip() for a in args.named_children]
                    if len(arguments) >= 3 and arguments[1] == 'CURLOPT_SSL_VERIFYPEER' and arguments[2].lower() in {'false', '0'}:
                        add('M006', node)
            if node.type in ASSIGNMENTS:
                left = field(node, 'name', 'left', 'key')
                right = field(node, 'value', 'right')
                if node.type == 'jsx_attribute' and len(node.named_children) >= 2:
                    left, right = node.named_children[:2]
                key = content(left, source).strip('\"\'')
                value = content(right, source).strip()
                if right and re.search(r'password|passwd|secret|api_?key|access_?token', key, re.I):
                    literals = [n for n in walk(right) if n.type in STRINGS]
                    if literals and len(content(literals[0], source).strip('\"\'`')) >= 8:
                        add('M001', node)
                if (key.endswith('rejectUnauthorized') and value == 'false') or (key.endswith('InsecureSkipVerify') and value == 'true'):
                    add('M006', node)
                if key.endswith('.innerHTML') or key == 'dangerouslySetInnerHTML':
                    add('M007', node)
            if node.type in {'binary_expression', 'binary', 'template_string', 'encapsed_string'}:
                dynamic = any(n.type in {'template_substitution', 'interpolation', 'variable_name'} for n in walk(node))
                operator = field(node, 'operator')
                dynamic = dynamic or (content(operator, source) in {'+', '.'} and any(
                    n.type in {'identifier', 'variable_name', 'call_expression', 'method_invocation'} for n in walk(node)))
                if dynamic and any(re.search(r'\b(?:SELECT|INSERT|UPDATE|DELETE)\b', content(n, source), re.I)
                                   for n in walk(node) if n.type in STRINGS | {'string_fragment', 'string_content'}):
                    add('M004', node)
    return {'findings': findings, 'errors': errors, 'parsers': parsers}
