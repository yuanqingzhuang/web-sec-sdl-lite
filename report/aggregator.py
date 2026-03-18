from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


def load_results(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    with p.open('r', encoding='utf-8') as handle:
        return json.load(handle)


def save_aggregate(data: dict[str, Any], path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('w', encoding='utf-8') as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)


def aggregate_from_files(
    dast_path: str | Path,
    sast_path: str | Path,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    dast_results = load_results(dast_path)
    sast_results = load_results(sast_path)
    aggregate = aggregate_results(dast_results=dast_results, sast_results=sast_results)
    if output_path is not None:
        save_aggregate(aggregate, output_path)
    return aggregate


def aggregate_results(
    dast_results: list[dict[str, Any]] | None = None,
    sast_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    merged = []
    merged.extend(_normalize_results(dast_results or [], source='dast'))
    merged.extend(_normalize_results(sast_results or [], source='sast'))

    unique_findings = _dedupe_findings(merged)
    unique_findings.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(str(item.get('severity', 'info')).lower(), 99),
            item.get('type', ''),
            item.get('location', ''),
            str(item.get('line', 0)),
        )
    )

    by_type = Counter(item.get('type', 'unknown') for item in unique_findings)
    by_severity = Counter(str(item.get('severity', 'info')).lower() for item in unique_findings)
    by_source = Counter(item.get('source', 'unknown') for item in unique_findings)

    grouped_by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    grouped_by_severity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in unique_findings:
        grouped_by_type[finding.get('type', 'unknown')].append(finding)
        grouped_by_severity[str(finding.get('severity', 'info')).lower()].append(finding)

    return {
        'summary': {
            'total_raw_findings': len(merged),
            'total_unique_findings': len(unique_findings),
            'by_type': dict(sorted(by_type.items())),
            'by_severity': dict(sorted(by_severity.items())),
            'by_source': dict(sorted(by_source.items())),
        },
        'findings': unique_findings,
        'grouped_by_type': dict(sorted(grouped_by_type.items())),
        'grouped_by_severity': dict(sorted(grouped_by_severity.items())),
    }


def _normalize_results(results: list[dict[str, Any]], source: str) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in results:
        record = dict(item)
        record.setdefault('source', source)
        record.setdefault('severity', 'info')
        record.setdefault('verified', False)
        record.setdefault('suggestion', '')
        record.setdefault('evidence', '')
        record.setdefault('payload', '')
        record.setdefault('param', '')
        record.setdefault('rule_id', '')
        if 'file' in record:
            record['location'] = f"{record.get('file', '')}:{record.get('line', 0)}"
        else:
            record['location'] = record.get('url', '')
        normalized.append(record)
    return normalized


def _dedupe_findings(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    deduped: list[dict[str, Any]] = []
    for item in results:
        key = (
            item.get('source', ''),
            item.get('type', ''),
            item.get('rule_id', ''),
            item.get('file', ''),
            item.get('line', 0),
            item.get('url', ''),
            item.get('param', ''),
            item.get('payload', ''),
            item.get('evidence', ''),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped
