from __future__ import annotations

import ast
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .rules import (
    RULE_DANGEROUS_CODE_EXECUTION,
    RULE_PATH_TRAVERSAL_FILE_READ,
    RULE_SQL_STRING_EXECUTION,
    RULE_UNSAFE_TEMPLATE_OUTPUT,
)

SQL_KEYWORDS = (
    'select ',
    'insert ',
    'update ',
    'delete ',
    'from ',
    'where ',
    'values ',
    'join ',
)

USER_INPUT_CALLS = {
    'request.args.get',
    'request.form.get',
    'request.values.get',
    'request.get_json',
    'input',
}

PYTHON_SUFFIXES = {'.py'}
TEMPLATE_SUFFIXES = {'.html', '.jinja', '.j2', '.tpl'}
IGNORED_DIRS = {'venv', '.venv', '__pycache__', '.git', 'node_modules', 'results'}
SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


def scan_directory(source_path: str) -> list[dict[str, Any]]:
    base = Path(source_path)
    if not base.exists():
        raise FileNotFoundError(f'Source path not found: {source_path}')

    findings: list[dict[str, Any]] = []
    for path in _iter_source_files(base):
        findings.extend(scan_file(path))

    findings.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(str(item.get('severity', 'info')).lower(), 99),
            str(item.get('file', '')),
            int(item.get('line', 0)),
            str(item.get('rule_id', '')),
        )
    )
    return findings


def scan_file(file_path: str | Path) -> list[dict[str, Any]]:
    path = Path(file_path)
    suffix = path.suffix.lower()
    if suffix in PYTHON_SUFFIXES:
        return scan_python_file(path)
    if suffix in TEMPLATE_SUFFIXES:
        return scan_template_file(path)
    return []


def save_results(results: list[dict[str, Any]], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as handle:
        json.dump(results, handle, ensure_ascii=False, indent=2)


def build_stats(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_type = Counter(item.get('type', 'unknown') for item in results)
    by_severity = Counter(str(item.get('severity', 'info')).lower() for item in results)
    return {
        'total_findings': len(results),
        'by_type': dict(sorted(by_type.items())),
        'by_severity': dict(sorted(by_severity.items())),
    }


def scan_python_file(file_path: Path) -> list[dict[str, Any]]:
    code = file_path.read_text(encoding='utf-8')
    tree = ast.parse(code, filename=str(file_path))
    lines = code.splitlines()
    visitor = _PythonRuleVisitor(file_path=str(file_path), lines=lines)
    visitor.visit(tree)
    return visitor.findings


def scan_template_file(file_path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    text = file_path.read_text(encoding='utf-8')
    for lineno, line in enumerate(text.splitlines(), start=1):
        if '|safe' in line:
            findings.append(_build_finding(
                rule_id=RULE_UNSAFE_TEMPLATE_OUTPUT.rule_id,
                vuln_type='xss',
                file=str(file_path),
                line=lineno,
                evidence='Template uses |safe and may render untrusted content without escaping.',
                severity=RULE_UNSAFE_TEMPLATE_OUTPUT.severity,
                suggestion=RULE_UNSAFE_TEMPLATE_OUTPUT.suggestion,
                code=line.strip(),
                verified=True,
                param='safe',
            ))
    return findings


class _PythonRuleVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, lines: list[str]) -> None:
        self.file_path = file_path
        self.lines = lines
        self.findings: list[dict[str, Any]] = []
        self.assignments: dict[str, ast.AST] = {}
        self.assignment_lines: dict[str, int] = {}
        self.user_input_vars: set[str] = set()
        self.suspicious_sql_vars: set[str] = set()
        self.path_vars: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> Any:
        value = node.value
        target_names = [name for target in node.targets for name in self._extract_names(target)]

        for name in target_names:
            self.assignments[name] = value
            self.assignment_lines[name] = getattr(node, 'lineno', 0)

            if self._contains_user_input(value):
                self.user_input_vars.add(name)

            if self._is_sql_string(value) and self._references_untrusted(value):
                self.suspicious_sql_vars.add(name)

            if self._is_path_build(value) and self._references_untrusted(value):
                self.path_vars.add(name)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        func_name = self._get_call_name(node.func)

        if func_name in {'eval', 'exec'}:
            self.findings.append(_build_finding(
                rule_id=RULE_DANGEROUS_CODE_EXECUTION.rule_id,
                vuln_type='code_execution',
                file=self.file_path,
                line=getattr(node, 'lineno', 0),
                evidence=f'Dangerous dynamic execution detected via {func_name}().',
                severity=RULE_DANGEROUS_CODE_EXECUTION.severity,
                suggestion=RULE_DANGEROUS_CODE_EXECUTION.suggestion,
                code=self._line(node),
                verified=True,
                param=func_name,
            ))

        if func_name in {'render_template_string', 'Markup', 'markupsafe.Markup'}:
            self.findings.append(_build_finding(
                rule_id=RULE_UNSAFE_TEMPLATE_OUTPUT.rule_id,
                vuln_type='xss',
                file=self.file_path,
                line=getattr(node, 'lineno', 0),
                evidence=f'Potential unsafe template output detected via {func_name}().',
                severity=RULE_UNSAFE_TEMPLATE_OUTPUT.severity,
                suggestion=RULE_UNSAFE_TEMPLATE_OUTPUT.suggestion,
                code=self._line(node),
                verified=True,
                param=func_name,
            ))

        if func_name.endswith('execute') or func_name.endswith('executemany'):
            self._check_sql_execution(node)

        if func_name == 'open':
            self._check_path_traversal(node)

        self.generic_visit(node)

    def _check_sql_execution(self, node: ast.Call) -> None:
        if not node.args:
            return
        sql_arg = node.args[0]
        suspicious = False
        details = ''
        param_name = ''

        if self._is_sql_string(sql_arg) and self._references_untrusted(sql_arg):
            suspicious = True
            details = 'execute() is called with a dynamically built SQL string containing untrusted input.'
        elif isinstance(sql_arg, ast.Name):
            param_name = sql_arg.id
            if sql_arg.id in self.suspicious_sql_vars:
                suspicious = True
                build_line = self.assignment_lines.get(sql_arg.id, 0)
                details = (
                    f"execute() uses variable '{sql_arg.id}' that was built from dynamic SQL "
                    f'near line {build_line}.'
                )
        if suspicious:
            self.findings.append(_build_finding(
                rule_id=RULE_SQL_STRING_EXECUTION.rule_id,
                vuln_type='sqli',
                file=self.file_path,
                line=getattr(node, 'lineno', 0),
                evidence=details,
                severity=RULE_SQL_STRING_EXECUTION.severity,
                suggestion=RULE_SQL_STRING_EXECUTION.suggestion,
                code=self._line(node),
                verified=True,
                param=param_name,
            ))

    def _check_path_traversal(self, node: ast.Call) -> None:
        if not node.args:
            return
        path_arg = node.args[0]
        suspicious = False
        details = ''
        param_name = ''

        if self._is_path_build(path_arg) and self._references_untrusted(path_arg):
            suspicious = True
            details = 'open() is called with a path built from untrusted input.'
        elif isinstance(path_arg, ast.Name):
            param_name = path_arg.id
            if path_arg.id in self.path_vars:
                suspicious = True
                build_line = self.assignment_lines.get(path_arg.id, 0)
                details = (
                    f"open() uses variable '{path_arg.id}' that was built from user-controlled path segments "
                    f'near line {build_line}.'
                )
        if suspicious:
            self.findings.append(_build_finding(
                rule_id=RULE_PATH_TRAVERSAL_FILE_READ.rule_id,
                vuln_type='path_traversal',
                file=self.file_path,
                line=getattr(node, 'lineno', 0),
                evidence=details,
                severity=RULE_PATH_TRAVERSAL_FILE_READ.severity,
                suggestion=RULE_PATH_TRAVERSAL_FILE_READ.suggestion,
                code=self._line(node),
                verified=True,
                param=param_name,
            ))

    def _contains_user_input(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name) and node.id in self.user_input_vars:
            return True
        if isinstance(node, ast.Call):
            call_name = self._get_call_name(node.func)
            if call_name in USER_INPUT_CALLS:
                return True
        for child in ast.iter_child_nodes(node):
            if self._contains_user_input(child):
                return True
        return False

    def _references_untrusted(self, node: ast.AST | None) -> bool:
        return self._contains_user_input(node)

    def _is_sql_string(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.JoinedStr):
            return self._contains_sql_keyword(node)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self._contains_sql_keyword(node)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
            return self._contains_sql_keyword(node)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return self._contains_sql_keyword(node)
        return False

    def _is_path_build(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Call):
            call_name = self._get_call_name(node.func)
            return call_name == 'os.path.join'
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return True
        return False

    def _contains_sql_keyword(self, node: ast.AST) -> bool:
        text = self._node_text(node).lower()
        return any(keyword in text for keyword in SQL_KEYWORDS)

    def _node_text(self, node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return ast.dump(node, include_attributes=False)

    def _get_call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._get_call_name(node.value)
            return f'{base}.{node.attr}' if base else node.attr
        return ''

    def _extract_names(self, node: ast.AST) -> list[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, (ast.Tuple, ast.List)):
            names: list[str] = []
            for item in node.elts:
                names.extend(self._extract_names(item))
            return names
        return []

    def _line(self, node: ast.AST) -> str:
        lineno = getattr(node, 'lineno', 0)
        if lineno <= 0 or lineno > len(self.lines):
            return ''
        return self.lines[lineno - 1].strip()


def _iter_source_files(base: Path):
    for path in base.rglob('*'):
        if path.is_dir():
            continue
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in PYTHON_SUFFIXES.union(TEMPLATE_SUFFIXES):
            yield path


def _build_finding(
    *,
    rule_id: str,
    vuln_type: str,
    file: str,
    line: int,
    evidence: str,
    severity: str,
    suggestion: str,
    code: str = '',
    verified: bool = True,
    param: str = '',
) -> dict[str, Any]:
    return {
        'source': 'sast',
        'rule_id': rule_id,
        'type': vuln_type,
        'file': file,
        'line': line,
        'param': param,
        'payload': '',
        'evidence': evidence,
        'severity': severity,
        'verified': verified,
        'suggestion': suggestion,
        'code': code,
    }
