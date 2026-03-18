from __future__ import annotations

from pathlib import Path
from typing import Any

from .aggregator import aggregate_from_files

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


def report_from_files(
    dast_path: str | Path,
    sast_path: str | Path,
    output_path: str | Path,
    *,
    aggregated_path: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    aggregate = aggregate_from_files(dast_path, sast_path, aggregated_path)
    return write_report(aggregate, output_path, metadata=metadata)


def write_report(aggregate: dict[str, Any], output_path: str | Path, metadata: dict[str, Any] | None = None) -> str:
    report_text = generate_report(aggregate, metadata=metadata)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report_text, encoding='utf-8')
    return report_text


def generate_report(aggregate: dict[str, Any], metadata: dict[str, Any] | None = None) -> str:
    metadata = metadata or {}
    summary = aggregate.get('summary', {})
    findings = list(aggregate.get('findings', []))
    findings.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(str(item.get('severity', 'info')).lower(), 99),
            item.get('type', ''),
            item.get('location', ''),
            int(item.get('line', 0) or 0),
        )
    )

    lines: list[str] = []
    lines.append('# Scan Report')
    lines.append('')
    lines.append('## Project Overview')
    lines.append('')
    lines.append('- Project: web-sec-sdl-lite')
    lines.append('- Description: lightweight demo scanner combining crawler, DAST, SAST, aggregation, and reporting.')
    lines.append(f"- Scan target: {metadata.get('target', 'N/A')}")
    lines.append(f"- Source path: {metadata.get('source', 'N/A')}")
    lines.append('')
    lines.append('## Summary')
    lines.append('')
    lines.append(f"- Total raw findings: {summary.get('total_raw_findings', 0)}")
    lines.append(f"- Total unique findings: {summary.get('total_unique_findings', 0)}")
    lines.append(f"- By source: {_format_summary_map(summary.get('by_source', {}))}")
    lines.append(f"- By type: {_format_summary_map(summary.get('by_type', {}))}")
    lines.append(f"- By severity: {_format_summary_map(summary.get('by_severity', {}))}")
    lines.append('')
    lines.append('## Findings')
    lines.append('')

    if not findings:
        lines.append('No findings were available in the aggregated result set.')
        return '\n'.join(lines) + '\n'

    for index, finding in enumerate(findings, start=1):
        lines.extend(_format_finding(index, finding))

    lines.append('## Remediation Overview')
    lines.append('')
    for vuln_type, group in aggregate.get('grouped_by_type', {}).items():
        suggestion = _first_nonempty(group, 'suggestion') or 'Review the affected code path and apply secure coding controls.'
        lines.append(f'- **{vuln_type}**: {suggestion}')
    lines.append('')
    return '\n'.join(lines) + '\n'


def _format_finding(index: int, finding: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    lines.append(f"### {index}. {finding.get('type', 'unknown')} [{str(finding.get('severity', 'info')).upper()}]")
    lines.append('')
    lines.append(f"- Source: {finding.get('source', 'unknown')}")
    if finding.get('file'):
        lines.append(f"- File: `{finding.get('file')}`")
        lines.append(f"- Line: {finding.get('line', 0)}")
    if finding.get('url'):
        lines.append(f"- URL: `{finding.get('url')}`")
    if finding.get('param'):
        lines.append(f"- Param: `{finding.get('param')}`")
    if finding.get('rule_id'):
        lines.append(f"- Rule ID: `{finding.get('rule_id')}`")
    if finding.get('payload'):
        lines.append(f"- Payload: `{finding.get('payload')}`")
    lines.append(f"- Verified: {finding.get('verified', False)}")
    lines.append(f"- Evidence: {finding.get('evidence', '')}")
    if finding.get('code'):
        lines.append('- Code:')
        lines.append('')
        lines.append('```python')
        lines.append(str(finding.get('code')))
        lines.append('```')
    lines.append(f"- Fix suggestion: {finding.get('suggestion', '')}")
    lines.append('')
    return lines


def _format_summary_map(data: dict[str, Any]) -> str:
    if not data:
        return 'none'
    return ', '.join(f'{key}={value}' for key, value in data.items())


def _first_nonempty(items: list[dict[str, Any]], key: str) -> str:
    for item in items:
        value = str(item.get(key, '')).strip()
        if value:
            return value
    return ''
