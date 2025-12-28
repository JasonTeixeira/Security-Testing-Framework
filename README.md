# Security Testing Framework

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-OWASP-red.svg)](https://owasp.org/)

> Automated security testing for web applications

I built this to find common security vulnerabilities before attackers do. Security testing is different from functional testing - you're actively trying to break things and find weaknesses.

---

## What This Does

Scans web applications for:
- **SQL Injection** - Can attackers manipulate your database?
- **Cross-Site Scripting (XSS)** - Can malicious scripts be injected?
- **Security Headers** - Are you missing important HTTP headers?
- **Open Redirects** - Can attackers redirect users to malicious sites?

This isn't a replacement for professional security audits, but it catches the low-hanging fruit that causes most breaches.

---

## Quick Start

### Install

```bash
# Clone
git clone https://github.com/JasonTeixeira/Security-Testing-Framework.git
cd Security-Testing-Framework

# Virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Dependencies
pip install -r requirements.txt
```

### Run a Scan

```python
from scanners.vulnerability_scanner import VulnerabilityScanner

# Scan a website
scanner = VulnerabilityScanner("https://example.com")
vulnerabilities = scanner.scan_all()

# Get summary
summary = scanner.get_summary()
print(f"Found {summary['high']} high severity issues")
```

---

## How It Works

### Vulnerability Scanner

The core scanner tests for common OWASP Top 10 vulnerabilities:

**SQL Injection Testing:**
- Sends common SQL payloads (`' OR '1'='1`, etc.)
- Checks for database error messages in responses
- Tests multiple parameters

**XSS Testing:**
- Injects script tags and JavaScript
- Checks if input is reflected unescaped
- Tests common input fields

**Security Headers:**
- Checks for missing headers like CSP, HSTS, X-Frame-Options
- Flags missing protections

**Open Redirects:**
- Tests redirect parameters
- Checks if site redirects to external URLs

---

## Project Structure

```
Security-Testing-Framework/
├── scanners/
│   └── vulnerability_scanner.py   # Core scanner
├── tests/
│   ├── vulnerabilities/           # Vulnerability tests
│   └── owasp/                    # OWASP Top 10 tests
├── utils/                        # Helper utilities
├── config/                       # Configuration
├── reports/                      # Scan results
└── requirements.txt             # Dependencies
```

---

## Usage Examples

### Basic Scan

```python
scanner = VulnerabilityScanner("https://yoursite.com")
results = scanner.scan_all()

for vuln in results:
    print(f"{vuln['severity']}: {vuln['type']}")
    print(f"  URL: {vuln['url']}")
    print(f"  {vuln['description']}\n")
```

### Test Specific Vulnerabilities

```python
scanner = VulnerabilityScanner("https://yoursite.com")

# Just test SQL injection
scanner.test_sql_injection()

# Just check headers
scanner.test_security_headers()

# Get results
vulnerabilities = scanner.vulnerabilities
```

---

## Important Warnings

### ⚠️ Legal & Ethical

**ONLY scan sites you own or have permission to test.**

Unauthorized security testing is illegal. Even with good intentions, scanning someone else's site without permission can:
- Be prosecuted under computer fraud laws
- Get you banned from services
- Cause legal trouble

Always get written permission first.

### ⚠️ Production Systems

Be careful testing production:
- Scans can trigger rate limits
- May cause performance issues
- Could flag security monitoring
- SQL injection tests might corrupt data

Test on staging/dev environments when possible.

---

## Common Findings

### Missing Security Headers

**Impact:** Makes site vulnerable to clickjacking, XSS, MITM attacks

**Fix:**
```python
# Add to your web server config
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000
```

### SQL Injection

**Impact:** Attackers can read/modify/delete database data

**Fix:**
- Use parameterized queries
- Never concatenate user input into SQL
- Use ORMs that handle escaping

```python
# Bad
query = f"SELECT * FROM users WHERE id = {user_input}"

# Good
cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
```

### XSS

**Impact:** Attackers can steal sessions, deface pages, phish users

**Fix:**
- Escape all user input before displaying
- Use Content-Security-Policy headers
- Validate input server-side

```python
# Escape output
from html import escape
safe_output = escape(user_input)
```

---

## What I Learned

Building this taught me:

**About Security Testing:**
- False positives are common - verification matters
- Context is everything - not all "issues" are exploitable
- Automated tools catch obvious stuff, but miss subtle bugs
- Security is layers - no single test catches everything

**About Vulnerabilities:**
- Most breaches use simple, known exploits
- Security headers are often forgotten
- Input validation is harder than it looks
- Even small sites need security testing

**About Responsible Disclosure:**
- Always get permission first
- Be respectful when reporting issues
- Give time to fix before public disclosure
- Security researchers help, not hurt

---

## Limitations

This framework:
- **Doesn't replace** professional pen testing
- **Won't find** complex logic flaws
- **Can't detect** business logic vulnerabilities
- **Misses** issues requiring authentication
- **Generates** false positives

Use it as a first line of defense, not the only one.

---

## Next Steps

Want to improve this?

**Add More Scans:**
- CSRF testing
- Authentication bypass attempts
- File inclusion tests
- Command injection tests

**Better Reporting:**
- HTML reports with screenshots
- Severity scoring (CVSS)
- Remediation recommendations
- Integration with bug trackers

**OWASP ZAP Integration:**
- Use professional scanner
- Automated spidering
- Passive scanning
- Active attack testing

---

## Resources

Learning security testing:

- **OWASP Top 10** - Most critical web vulnerabilities
- **PortSwigger Web Security Academy** - Free hands-on training
- **HackTheBox / TryHackMe** - Practice environments
- **Bug Bounty Programs** - Learn by finding real bugs (legally!)

---

## Contributing

Found bugs or want to add scans? Open an issue or PR!

---

## Author

**Jason Teixeira**
- GitHub: [@JasonTeixeira](https://github.com/JasonTeixeira)
- Email: sage@sageideas.org

---

## License

MIT License - but use responsibly and legally.

---

## Why Security Testing Matters

I built this because:
- **Most breaches use known vulnerabilities** - stuff we could catch
- **Security is often an afterthought** - tested last or not at all
- **Automated testing helps** - catches obvious issues before deployment
- **It's easier than you think** - basic security testing isn't that hard

Security testing should be part of your CI/CD pipeline, not something you do once a year.
