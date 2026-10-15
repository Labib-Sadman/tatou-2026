import os, tempfile
os.environ.setdefault("SECRET_KEY", "test-only-secret-not-for-production")
os.environ.setdefault("LOG_DIR", tempfile.mkdtemp(prefix="tatou-test-logs-"))
