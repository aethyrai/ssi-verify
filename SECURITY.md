# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email **contact@aethyrresearch.com** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 48 hours and aim to provide a fix within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | Yes       |

## Scope

This library handles cryptographic signature verification. Security issues of particular interest include:

- Signature verification bypasses
- Capability matching logic flaws
- Timing attacks in verification routines
- Dependency vulnerabilities in `@noble/post-quantum` or `@noble/hashes`
