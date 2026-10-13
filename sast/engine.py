"""Python AST rules and conservative, intraprocedural data-flow analysis.
Never imports or executes submitted source.
"""
import ast
import copy
import hashlib
import re
from dataclasses import asdict, dataclass, field

SEVERITIES = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
RULES = {
    "S001": ("HIGH", "CWE-798", "Credencial no código", "Use variável de ambiente ou cofre de segredos; rotacione a credencial."),
    "S002": ("HIGH", "CWE-95", "Execução dinâmica de código", "Substitua eval/exec por parsing explícito e validação de tipos."),
    "S003": ("HIGH", "CWE-78", "Comando de shell", "Use argumentos separados e shell=False; valide entradas com allowlist."),
    "S004": ("HIGH", "CWE-89", "Entrada externa em consulta SQL", "Use placeholders do driver e parâmetros separados da consulta."),
    "S005": ("MEDIUM", "CWE-89", "SQL construído dinamicamente", "Use consultas parametrizadas; confirme manualmente a origem dos dados."),
    "S006": ("HIGH", "CWE-502", "Desserialização insegura", "Prefira JSON validado; para YAML use safe_load."),
    "S007": ("MEDIUM", "CWE-327", "Hash criptográfico fraco", "Use SHA-256 para integridade e Argon2/bcrypt para senhas."),
    "S008": ("MEDIUM", "CWE-295", "Verificação TLS desativada", "Mantenha verify=True e configure certificados confiáveis."),
    "S009": ("HIGH", "CWE-22", "Entrada externa em caminho de arquivo", "Resolva o caminho e verifique contenção em diretório autorizado."),
}

@dataclass
class Finding:
    rule: str
    severity: str
    cwe: str
    title: str
    remediation: str
    file: str
    line: int
    column: int
    confidence: str
    trace: list = field(default_factory=list)
    engine: str = "python-ast"
    fingerprint: str = ""

    def export(self):
        result = asdict(self)
        result["fingerprint"] = hashlib.sha256(f"{self.file}:{self.line}:{self.rule}".encode()).hexdigest()[:24]
        return result


def name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return name(node.value) + "." + node.attr
    return ""


def combine(*traces):
    return list(dict.fromkeys(item for trace in traces for item in trace))[:30]


class Analyzer:
    def __init__(self, filename):
        self.filename = filename
        self.findings = {}
        self.aliases = {}

    def resolve(self, node):
        raw = name(node)
        first, *rest = raw.split(".")
        return ".".join([self.aliases.get(first, first), *rest])

    def add(self, rule, node, trace=None):
        severity, cwe, title, fix = RULES[rule]
        self.findings[(rule, node.lineno)] = Finding(rule, severity, cwe, title, fix,
            self.filename, node.lineno, node.col_offset + 1,
            "MEDIUM" if rule in {"S001", "S005", "S007", "S009"} else "HIGH", trace or [])

    def flow(self, node, env):
        if node is None:
            return []
        if isinstance(node, ast.Name):
            return env.get(node.id, [])
        raw = self.resolve(node)
        if raw.startswith(("request.args", "request.form", "request.values", "request.json", "request.GET", "request.POST", "flask.request.")):
            return [f"L{node.lineno}: entrada HTTP"]
        if isinstance(node, ast.Call):
            call = self.resolve(node.func)
            if call in {"input", "builtins.input"} or call.startswith(("request.", "flask.request.")):
                return [f"L{node.lineno}: fonte {call}"]
            # Numeric conversion removes injection characters in SQL/path/shell strings.
            if call in {"int", "float", "builtins.int", "builtins.float"}:
                return []
        return combine(*(self.flow(child, env) for child in ast.iter_child_nodes(node)))

    def inspect(self, node, env):
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            call = self.resolve(child.func)
            first = child.args[0] if child.args else next((k.value for k in child.keywords if k.arg in {"command", "args", "query", "file", "object"}), None)
            trace = self.flow(first, env)
            sink_trace = combine(trace, [f"L{child.lineno}: sink {call}"]) if trace else []
            if call in {"eval", "exec", "builtins.eval", "builtins.exec"}:
                self.add("S002", child, sink_trace)
            shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in child.keywords)
            if call in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"} or (call.startswith("subprocess.") and shell):
                self.add("S003", child, sink_trace)
            if call.endswith((".execute", ".executemany", ".executescript")):
                if trace:
                    self.add("S004", child, sink_trace)
                elif isinstance(first, (ast.JoinedStr, ast.BinOp)) or (isinstance(first, ast.Call) and name(first.func).endswith(".format")):
                    self.add("S005", child)
            if call in {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads", "yaml.load", "yaml.unsafe_load"}:
                self.add("S006", child, sink_trace)
            if call in {"hashlib.md5", "hashlib.sha1"}:
                self.add("S007", child)
            if any(k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False for k in child.keywords):
                self.add("S008", child)
            if call in {"open", "builtins.open", "pathlib.Path", "Path"} and trace:
                self.add("S009", child, sink_trace)

    def block(self, statements, env):
        env = dict(env)
        for node in statements:
            if isinstance(node, ast.Import):
                for item in node.names:
                    self.aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
            elif isinstance(node, ast.ImportFrom):
                for item in node.names:
                    self.aliases[item.asname or item.name] = f"{node.module}.{item.name}"
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                old_aliases = dict(self.aliases)
                local = dict(env)
                for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
                    local.pop(arg.arg, None)
                self.block(node.body, local)
                self.aliases = old_aliases
            elif isinstance(node, ast.ClassDef):
                self.block(node.body, dict(env))
            elif isinstance(node, ast.If):
                self.inspect(node.test, env)
                left = self.block(node.body, env)
                right = self.block(node.orelse, env)
                env = {key: combine(left.get(key, []), right.get(key, [])) for key in left.keys() | right.keys()}
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                baseline = dict(env)
                if isinstance(node, (ast.For, ast.AsyncFor)):
                    self.inspect(node.iter, env)
                    for target in ast.walk(node.target):
                        if isinstance(target, ast.Name):
                            env[target.id] = self.flow(node.iter, env)
                else:
                    self.inspect(node.test, env)
                # Monotone union reaches a fixed point over the finite local name set.
                for _ in range(64):
                    after = self.block(node.body, env)
                    merged = {key: combine(env.get(key, []), after.get(key, []), baseline.get(key, [])) for key in env.keys() | after.keys() | baseline.keys()}
                    if merged == env:
                        break
                    env = merged
                env = self.block(node.orelse, env)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    self.inspect(item.context_expr, env)
                env = self.block(node.body, env)
            elif isinstance(node, ast.Try):
                branches = [self.block(node.body, env), *(self.block(h.body, env) for h in node.handlers), env]
                env = {key: combine(*(b.get(key, []) for b in branches)) for key in set().union(*(b.keys() for b in branches))}
                env = self.block(node.orelse, env)
                env = self.block(node.finalbody, env)
            else:
                self.inspect(node, env)
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    value = node.value
                    for target in targets:
                        for leaf in ast.walk(target):
                            if not isinstance(leaf, ast.Name):
                                continue
                            trace = self.flow(value, env)
                            if isinstance(node, ast.AugAssign):
                                trace = combine(env.get(leaf.id, []), trace)
                            env[leaf.id] = combine(trace, [f"L{node.lineno}: variável {leaf.id}"]) if trace else []
                            if re.search(r"password|passwd|secret|api_?key|access_?token", leaf.id, re.I) and isinstance(value, ast.Constant) and isinstance(value.value, str) and len(value.value) >= 4:
                                self.add("S001", node)
        return env


def analyze(source, filename="main.py"):
    tree = ast.parse(source, filename=filename)
    engine = Analyzer(filename)
    engine.block(tree.body, {})
    results = [f.export() for f in sorted(engine.findings.values(), key=lambda f: (f.line, f.rule))]
    class Redact(ast.NodeTransformer):
        def visit_Constant(self, node):
            if isinstance(node.value, (str, bytes)):
                return ast.copy_location(ast.Constant(value="<literal oculto>"), node)
            return node
    scopes = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for result in results:
        scope = next((n for n in sorted(scopes, key=lambda n: n.end_lineno - n.lineno) if n.lineno <= result["line"] <= n.end_lineno), tree)
        result["context"] = ast.unparse(Redact().visit(copy.deepcopy(scope)))[:6000]
    return results


def gate(findings, errors=None, threshold="HIGH"):
    return "ERROR" if errors else "BLOCKED" if any(SEVERITIES[f["severity"]] >= SEVERITIES[threshold] for f in findings) else "PASSED"


def scan(files):
    findings, errors = [], []
    for filename, source in sorted(files.items()):
        try:
            findings.extend(analyze(source, filename))
        except (SyntaxError, ValueError, RecursionError) as exc:
            errors.append({"file": filename, "line": getattr(exc, "lineno", None), "message": "Código inválido ou complexo demais para o parser."})
    return {"findings": findings, "errors": errors, "gate": gate(findings, errors), "files_scanned": len(files)}
