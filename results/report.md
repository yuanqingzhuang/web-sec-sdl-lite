# Scan Report

## Project Overview

- Project: web-sec-sdl-lite
- Description: lightweight demo scanner combining crawler, DAST, SAST, aggregation, and reporting.
- Scan target: http://192.168.23.132/dvwa
- Source path: N/A

## Summary

- Total raw findings: 9
- Total unique findings: 9
- By source: dast=4, sast=5
- By type: code_execution=1, path_traversal=1, sqli=3, xss=4
- By severity: high=5, medium=4

## Findings

### 1. code_execution [HIGH]

- Source: sast
- File: `targets\demo_flask_app\app.py`
- Line: 114
- Param: `eval`
- Rule ID: `PY002`
- Verified: True
- Evidence: Dangerous dynamic execution detected via eval().
- Code:

```python
result = str(eval(code))
```
- Fix suggestion: Avoid eval/exec on untrusted input. Replace with safe parsing or explicit allowlist logic.

### 2. path_traversal [HIGH]

- Source: sast
- File: `targets\demo_flask_app\app.py`
- Line: 98
- Param: `file_path`
- Rule ID: `PY004`
- Verified: True
- Evidence: open() uses variable 'file_path' that was built from user-controlled path segments near line 95.
- Code:

```python
with open(file_path, "r", encoding="utf-8") as f:
```
- Fix suggestion: Restrict file access to a fixed base directory and validate file names with an allowlist.

### 3. sqli [HIGH]

- Source: dast
- URL: `http://192.168.23.132/dvwa/vulnerabilities/brute/`
- Param: `username`
- Payload: `1'`
- Verified: True
- Evidence: SQL error keyword detected only after payload: you have an error in your sql syntax
- Fix suggestion: use parameterized queries / prepared statements instead of string concatenation

### 4. sqli [HIGH]

- Source: dast
- URL: `http://192.168.23.132/dvwa/vulnerabilities/sqli/`
- Param: `id`
- Payload: `1'`
- Verified: True
- Evidence: SQL error keyword detected only after payload: you have an error in your sql syntax
- Fix suggestion: use parameterized queries / prepared statements instead of string concatenation

### 5. sqli [HIGH]

- Source: sast
- File: `targets\demo_flask_app\app.py`
- Line: 48
- Param: `query`
- Rule ID: `PY001`
- Verified: True
- Evidence: execute() uses variable 'query' that was built from dynamic SQL near line 43.
- Code:

```python
cur.execute(query)
```
- Fix suggestion: Use parameterized queries or prepared statements instead of building SQL strings dynamically.

### 6. xss [MEDIUM]

- Source: dast
- URL: `http://192.168.23.132/dvwa/vulnerabilities/csp/`
- Param: `include`
- Payload: `<script>alert(1)</script>`
- Verified: True
- Evidence: payload reflected in HTML response at offset 2653: s="vulnerable_code_area">
	<script src='<script>alert(1)</script>'></script>

<form name="csp" method="PO
- Fix suggestion: escape untrusted output before rendering HTML; use template autoescaping and input validation

### 7. xss [MEDIUM]

- Source: dast
- URL: `http://192.168.23.132/dvwa/vulnerabilities/xss_r/`
- Param: `name`
- Payload: `<script>alert(1)</script>`
- Verified: True
- Evidence: payload reflected in HTML response at offset 2834: it">
			</p>

		</form>
		<pre>Hello <script>alert(1)</script></pre>
	</div>

	<h2>More Information
- Fix suggestion: escape untrusted output before rendering HTML; use template autoescaping and input validation

### 8. xss [MEDIUM]

- Source: sast
- File: `targets\demo_flask_app\templates\comments.html`
- Line: 7
- Param: `safe`
- Rule ID: `PY003`
- Verified: True
- Evidence: Template uses |safe and may render untrusted content without escaping.
- Code:

```python
<div>{{ item.content|safe }}</div>
```
- Fix suggestion: Keep template autoescaping enabled and avoid marking untrusted content as safe.

### 9. xss [MEDIUM]

- Source: sast
- File: `targets\demo_flask_app\templates\search.html`
- Line: 10
- Param: `safe`
- Rule ID: `PY003`
- Verified: True
- Evidence: Template uses |safe and may render untrusted content without escaping.
- Code:

```python
<div>{{ q|safe }}</div>
```
- Fix suggestion: Keep template autoescaping enabled and avoid marking untrusted content as safe.

## Remediation Overview

- **code_execution**: Avoid eval/exec on untrusted input. Replace with safe parsing or explicit allowlist logic.
- **path_traversal**: Restrict file access to a fixed base directory and validate file names with an allowlist.
- **sqli**: use parameterized queries / prepared statements instead of string concatenation
- **xss**: escape untrusted output before rendering HTML; use template autoescaping and input validation

