from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class SASTRule:
    rule_id: str
    name: str
    description: str
    severity: str
    sink_patterns: List[str]
    risk: str
    suggestion: str


RULE_SQL_STRING_EXECUTION = SASTRule(
    rule_id='PY001',
    name='SQL string concatenation execution',
    description=(
        'Detect SQL queries built by string concatenation, f-string, format, '
        'or percent-formatting and then executed by database APIs.'
    ),
    severity='high',
    sink_patterns=['execute', 'executemany'],
    risk='User-controlled input may be concatenated into SQL statements, leading to SQL injection.',
    suggestion='Use parameterized queries or prepared statements instead of building SQL strings dynamically.',
)

RULE_DANGEROUS_CODE_EXECUTION = SASTRule(
    rule_id='PY002',
    name='Dangerous code execution',
    description='Detect dangerous dynamic execution functions such as eval or exec.',
    severity='high',
    sink_patterns=['eval', 'exec'],
    risk='Untrusted input reaching eval/exec may lead to arbitrary code execution.',
    suggestion='Avoid eval/exec on untrusted input. Replace with safe parsing or explicit allowlist logic.',
)

RULE_UNSAFE_TEMPLATE_OUTPUT = SASTRule(
    rule_id='PY003',
    name='Unsafe template output or unfiltered input',
    description=(
        'Detect dangerous template rendering patterns such as render_template_string, '
        'Markup, or explicit safe output in template files.'
    ),
    severity='medium',
    sink_patterns=['render_template_string', 'Markup', 'safe'],
    risk='Untrusted input may be rendered into HTML without proper escaping, leading to XSS.',
    suggestion='Keep template autoescaping enabled and avoid marking untrusted content as safe.',
)

RULE_PATH_TRAVERSAL_FILE_READ = SASTRule(
    rule_id='PY004',
    name='Path concatenation file read',
    description=(
        'Detect file read operations where file paths are built from user input '
        'using os.path.join, string concatenation, or similar logic.'
    ),
    severity='high',
    sink_patterns=['open', 'os.path.join'],
    risk='User-controlled path segments may lead to path traversal and arbitrary file read.',
    suggestion='Restrict file access to a fixed base directory and validate file names with an allowlist.',
)

DEFAULT_RULES = [
    RULE_SQL_STRING_EXECUTION,
    RULE_DANGEROUS_CODE_EXECUTION,
    RULE_UNSAFE_TEMPLATE_OUTPUT,
    RULE_PATH_TRAVERSAL_FILE_READ,
]
