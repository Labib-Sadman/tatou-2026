# Tatou — Group 20

Flask + MariaDB PDF-watermarking platform (pedagogical, deliberately
vulnerable — do not deploy on an open network). Group 20's hardened fork.

## Configure
    cp sample.env .env
    # set SECRET_KEY=<64-char hex>  (python3 -c "import secrets; print(secrets.token_hex(32))")
    # set FLAG_2 and the MARIADB_* values
SECRET_KEY is mandatory: the server signs auth tokens with it and fails closed
if it is unset or default. .env is git-ignored, never committed.

## Deploy
    docker compose up --build -d
    curl -s localhost:5000/healthz

## Test
    cd server && python3 -m venv .venv && . .venv/bin/activate
    python -m pip install -e ".[dev]"
    python -m pytest --cov=src --cov-report=term-missing
Python 3.13: pip install standard-imghdr first. conftest.py supplies a test key.
Status: 50 passed, 2 failed, 3 skipped, 53% coverage. The 2 failures are a known
zero-page test-fixture issue (pre-existing), not a defect. See common/SPEC_TO_TEST.md.

## Security hardening (see JOURNAL.md)
- SECRET_KEY: was empty/default; now strong + fail-closed.
- load-plugin RCE disabled (410); delete-document SQLi fixed; IDOR fixed;
  bash-bridge command injection fixed; persistent logging + enumeration detection.
Residual: RMAP replay (FPT_RPL.1) not prevented (DoS, not forgery).
