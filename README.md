<div align="center">

# 🚀 QuantumAI

Audit Python repositories with AST analysis and OpenAI, then generate the README.[span_1](start_span)[span_1](end_span)

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/OpenAI-GPT--4o--mini-green?style=for-the-badge&logo=openai&logoColor=white" alt="OpenAI">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge" alt="License: MIT">
  <img src="https://img.shields.io/badge/status-alpha-orange?style=for-the-badge" alt="Status">
</p>

</div>

---

QuantumAI parses your project with Python's built-in ast module, flags risky patterns locally, and sends structured metadata (never whole files) to OpenAI for a deeper security and performance review[span_2](start_span)[span_2](end_span). The same project summary can then be turned into a complete, professional README.md[span_3](start_span)[span_3](end_span).

`text
$ quantumai audit ./shop-api
Parsed 42 files, 187 functions, 23 classes
high    app/db.py:58      SQL query built from a string
high    app/config.py:4   Hardcoded secret in 'SECRET_KEY'
medium  app/jobs.py:102   subprocess call with shell=True
5 findings: 2 high, 2 medium, 1 low
