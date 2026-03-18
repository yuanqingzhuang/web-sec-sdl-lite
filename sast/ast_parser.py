from __future__ import annotations

import ast
from pathlib import Path
from typing import Any


class ASTNodeVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str = '<memory>') -> None:
        self.file_path = file_path
        self.calls: list[dict[str, Any]] = []
        self.assignments: list[dict[str, Any]] = []
        self.returns: list[dict[str, Any]] = []
        self.imports: list[dict[str, Any]] = []

    def visit_Call(self, node: ast.Call) -> Any:
        self.calls.append({
            'type': 'call',
            'func_name': self._get_call_name(node.func),
            'args_repr': [self._safe_dump(arg) for arg in node.args],
            'keywords': [
                {
                    'arg': keyword.arg,
                    'value_repr': self._safe_dump(keyword.value),
                }
                for keyword in node.keywords
            ],
            'lineno': getattr(node, 'lineno', 0),
            'col_offset': getattr(node, 'col_offset', 0),
        })
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        self.assignments.append({
            'type': 'assign',
            'targets': [self._safe_dump(target) for target in node.targets],
            'value_repr': self._safe_dump(node.value),
            'lineno': getattr(node, 'lineno', 0),
            'col_offset': getattr(node, 'col_offset', 0),
        })
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        self.assignments.append({
            'type': 'ann_assign',
            'targets': [self._safe_dump(node.target)],
            'value_repr': self._safe_dump(node.value) if node.value else '',
            'lineno': getattr(node, 'lineno', 0),
            'col_offset': getattr(node, 'col_offset', 0),
        })
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> Any:
        self.returns.append({
            'type': 'return',
            'value_repr': self._safe_dump(node.value) if node.value else '',
            'lineno': getattr(node, 'lineno', 0),
            'col_offset': getattr(node, 'col_offset', 0),
        })
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            self.imports.append({
                'type': 'import',
                'name': alias.name,
                'asname': alias.asname,
                'lineno': getattr(node, 'lineno', 0),
            })

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        module = node.module or ''
        for alias in node.names:
            self.imports.append({
                'type': 'import_from',
                'module': module,
                'name': alias.name,
                'asname': alias.asname,
                'lineno': getattr(node, 'lineno', 0),
            })

    def _get_call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._get_call_name(node.value)
            return f'{base}.{node.attr}' if base else node.attr
        return self._safe_dump(node)

    @staticmethod
    def _safe_dump(node: ast.AST | None) -> str:
        if node is None:
            return ''
        try:
            return ast.dump(node, include_attributes=False)
        except Exception:
            return str(node)


def parse_python_code(code: str, file_path: str = '<memory>') -> dict[str, Any]:
    tree = ast.parse(code, filename=file_path)
    visitor = ASTNodeVisitor(file_path=file_path)
    visitor.visit(tree)
    return {
        'file': file_path,
        'calls': visitor.calls,
        'assignments': visitor.assignments,
        'returns': visitor.returns,
        'imports': visitor.imports,
    }


def parse_python_file(file_path: str) -> dict[str, Any]:
    path = Path(file_path)
    code = path.read_text(encoding='utf-8')
    return parse_python_code(code, file_path=str(path))
