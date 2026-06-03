# cureforge-task-p
Failure-closed multi-party approval gate assessment implemented in Python.
# CureForge Task P — Failure-Closed Multi-Party Approval Gate

## Overview

This project implements a secure failure-closed multi-party approval gate system in Python.

The system validates multiple approvals against a configurable approval policy before allowing release of a protected action.

The implementation focuses on:

* secure approval validation
* failure-closed behavior
* audit logging
* timeout handling
* adversarial attack prevention
* automated testing

---


## Features

* Multi-party approval validation
* HMAC SHA256 signature verification
* Failure-closed security design
* Duplicate approval prevention
* Replay attack protection
* Stale approval rejection
* Timeout enforcement
* Append-only immutable audit logs
* Structural audit-log immutability protection
* Adversarial security tests
* Pytest-based automated test suite



---

## Project Structure

```text
cureforge-task-p/
│
├── src/
│   ├── models.py
│   ├── policy.py
│   ├── verifier.py
│   ├── audit.py
│   └── gate.py
│
├── tests/
│   ├── test_gate.py
│   ├── test_security.py
│   ├── test_timeout.py
│   └── test_audit.py
│
├── requirements.txt
├── pytest.ini
└── README.md
```

---

## Installation

Create virtual environment:

```bash
python -m venv venv
```

Activate environment:

Windows PowerShell:

```bash
venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Running Tests

Run all tests:

```bash
pytest -v
```

---

## Security Design

The implementation follows a failure-closed architecture.

If any validation fails, the system transitions to a WITHHELD state and never releases the protected action.

Security protections include:

* invalid signature rejection
* duplicate approval rejection
* timeout enforcement
* append-only audit records

---


## Testing

The project includes:

* happy-path validation tests
* invalid signature tests
* replay attack rejection tests
* duplicate approval attack tests
* stale approval rejection tests
* timeout tests
* immutable audit-log tests
* structural audit-log tampering protection tests
* adversarial security validation tests

Total automated tests:
* 22 passing tests


---

## Technologies Used

* Python 3.13
* pytest
* hmac
* hashlib
* dataclasses
* enum
