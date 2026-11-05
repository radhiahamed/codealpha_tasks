# Secure Code Review Report

**Target:** `vulnerable_app.py` (Python 3 / Flask, 81 lines, 9 endpoints)
**Author:** Radhia Hamed: CodeAlpha Cyber Security Internship, November 2026
**Methods:** static analysis with [Bandit](https://bandit.readthedocs.io/) 1.9 and manual code inspection.

## 1. Summary
| Result | Before (`vulnerable_app.py`) | After (`secure_app.py`) |
|---|---|---|
| Bandit issues (High / Medium / Low) | 14 (4 / 6 / 4) | 3 (0 / 0 / 3) |
| Issues found by manual review only | 3 | 0 |

The 3 remaining Low results after the fix are informational: the `subprocess` module is
imported, and `ping` is called with a list of arguments after the host name is validated
(no shell). The raw reports are in `bandit_before.txt` and `bandit_after.txt`.

## 2. Findings
| # | Vulnerability | Location | CWE | Severity | Found by |
|---|---|---|---|---|---|
| 1 | SQL injection | line 30 | CWE-89 | High | Bandit B608 + manual |
| 2 | OS command injection | line 44 | CWE-78 | High | Bandit B602 |
| 3 | Code injection with `eval` | line 49 | CWE-95 | High | Bandit B307 |
| 4 | Insecure deserialization (`pickle`) | line 54 | CWE-502 | High | Bandit B301 |
| 5 | Unsafe YAML loading | line 59 | CWE-502 | High | Bandit B506 |
| 6 | Debug mode enabled | line 81 | CWE-489 | High | Bandit B201 |
| 7 | TLS verification disabled | line 72 | CWE-295 | High | Bandit B501 |
| 8 | Server-side request forgery (SSRF) | line 72 | CWE-918 | High | Manual |
| 9 | Path traversal | line 65 | CWE-22 | High | Manual |
| 10 | Reflected cross-site scripting (XSS) | line 38 | CWE-79 | Medium | Manual |
| 11 | Weak password hash (MD5, no salt) | line 29 | CWE-327 | High | Bandit B324 |
| 12 | Hardcoded secret | line 17 | CWE-798 | Medium | Bandit B105 |
| 13 | Predictable reset token (`random`) | line 77 | CWE-338 | Medium | Bandit B311 |
| 14 | Bound to all interfaces | line 81 | CWE-605 | Medium | Bandit B104 |
| 15 | No timeout on outgoing request | line 72 | CWE-400 | Low | Bandit B113 |

Severity is my own rating based on the likely impact, not only Bandit's score.

## 3. Details and remediation

### 1. SQL injection (line 30)
The query is built with string formatting, so input such as `' OR '1'='1' --` changes the query logic and bypasses the login.
```python
# Before
query = "SELECT id FROM users WHERE username = '%s' AND password = '%s'" % (username, pw_hash)
# After
row = get_db().execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()
```
**Fix:** parameterized queries. Never concatenate user input into SQL.

### 2. OS command injection (line 44)
`shell=True` with user input lets an attacker run extra commands (`8.8.8.8; cat /etc/passwd`).
```python
# Before
subprocess.check_output("ping -c 1 " + host, shell=True)
# After
if not HOST_RE.match(host): abort(400)
subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
```
**Fix:** validate input, pass arguments as a list, no shell.

### 3. Code injection with `eval` (line 49)
`eval` runs any Python expression sent by the user (for example `__import__('os').system(...)`).
**Fix:** a small evaluator that walks the syntax tree and only allows numbers and `+ - * /`.

### 4. Insecure deserialization with `pickle` (line 54)
Unpickling untrusted data can execute arbitrary code.
**Fix:** use a data-only format such as JSON (`json.loads`).

### 5. Unsafe YAML loading (line 59)
`yaml.load` with the full loader can instantiate arbitrary Python objects.
**Fix:** `yaml.safe_load`.

### 6 and 14. Debug mode and binding to all interfaces (line 81)
`debug=True` exposes the Werkzeug debugger, which allows code execution. `0.0.0.0` makes the app reachable from the whole network.
**Fix:** `app.run(host="127.0.0.1", debug=False)`; in production use a WSGI server behind a reverse proxy.

### 7, 8 and 15. Outgoing requests (line 72)
The URL is fully controlled by the user (SSRF: reach internal services or cloud metadata), TLS verification is off (man-in-the-middle), and there is no timeout (hanging requests).
**Fix:** allow-list of hosts, HTTPS only, default certificate verification, `timeout=5`.

### 9. Path traversal (line 65)
`name=../../etc/passwd` reads files outside the upload folder.
**Fix:** `send_from_directory(UPLOAD_DIR, name)`, which rejects paths that leave the directory.

### 10. Reflected XSS (line 38)
The `name` parameter is inserted into HTML without escaping, so `<script>` code runs in the victim's browser.
**Fix:** escape output (`markupsafe.escape`) and add a Content-Security-Policy header.

### 11. Weak password hashing (line 29)
MD5 is fast and unsalted, so leaked hashes are cracked easily.
**Fix:** a slow salted hash such as `werkzeug.security` (`generate_password_hash` / `check_password_hash`), or bcrypt / Argon2.

### 12. Hardcoded secret (line 17)
Secrets in source code end up in the repository.
**Fix:** read from an environment variable or a secrets manager, and rotate the exposed value.

### 13. Predictable token (line 77)
`random` is not cryptographically secure, so tokens can be guessed.
**Fix:** `secrets.token_urlsafe(32)`.

## 4. Secure coding best practices
1. **Validate input** (allow-lists) and **encode output** for the context (HTML, SQL, shell).
2. Use **parameterized queries** and safe APIs instead of building commands or queries from strings.
3. Never `eval`, `pickle.loads` or unsafe-load untrusted data.
4. Hash passwords with a slow, salted algorithm; use `secrets` for tokens.
5. Keep **secrets out of source code**; scan repositories for leaks.
6. Turn off debug mode, bind to the minimum interfaces, keep dependencies updated.
7. Run static analysis (Bandit) in CI, and add manual review for logic flaws that tools miss (SSRF, path traversal, XSS were not detected by Bandit).
8. Apply least privilege and log security events.

## 5. Limitations
The review covers one small file. Bandit only finds known patterns, which is why three issues needed manual review. The fixed version was checked with Bandit and compiled, but it was not tested with a full penetration test.
