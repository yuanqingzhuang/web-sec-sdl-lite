# Lightweight SDL Security Testing Platform for Web Applications

基于规则引擎与 AI 辅助分析的 Web 应用轻量级 SDL 安全测试平台

## Project Background
本项目聚焦于中小型 Web 应用的安全测试场景，尝试以轻量级工程原型的方式实现 SDL 中常见的安全测试环节，包括资产采集、静态规则扫描、动态漏洞探测、结果聚合与修复建议输出。项目目标不是替代成熟商业扫描产品，而是验证对 Web 应用安全测试流程和工程化实现方式的理解。

## Project Goals
- 实现基础页面与表单采集能力
- 实现 SQL 注入、XSS、路径遍历等常见漏洞的 DAST 检测
- 实现针对 Flask 应用的简易 AST 静态扫描
- 聚合检测结果并导出结构化报告
- 通过 AI 辅助模块生成修复建议与优先级提示

## Core Features
- Asset Collection
- DAST for common Web vulnerabilities
- AST-based SAST for Flask apps
- AI-assisted remediation suggestions
- Structured report generation

## Tech Stack
- Python 3
- requests / BeautifulSoup
- Flask
- Python AST
- Markdown / HTML reporting

## Scope
### Included
- Lightweight page and parameter collection
- Basic DAST for common Web vulnerabilities
- Basic SAST for Flask applications
- Result aggregation and reporting
- AI-assisted explanation module

### Excluded
- Full-scale asset mapping
- Multi-language static analysis
- Complete IAST support
- Advanced logic vulnerability automation
- Enterprise-grade distributed scanning

## Current Progress
- [x] Project topic defined
- [x] Repository initialized
- [x] Basic directory structure created
- [x] README first version completed
- [ ] Demo Flask vulnerable application
- [ ] Asset collection module
- [ ] DAST engine
- [ ] SAST scanner
- [ ] AI advisory module
- [ ] Report generator
