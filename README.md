# AWS IAM Policy Analyzer

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Python CLI tool to scan IAM policies for over-privileges (e.g., wildcards). Supports mock or file input for secure audits.

## Features
- Detects risky 'Allow *' statements.
- Error handling and detailed flags.
- Aligns with zero-trust principles (e.g., reduces risks in high-stakes environments).

## Installation
```bash
git clone https://github.com/AyrtonBayer25/AWS-IAM-Policy-Analyzer.git
cd AWS-IAM-Policy-Analyzer
