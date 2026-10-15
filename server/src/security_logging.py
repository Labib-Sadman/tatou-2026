"""security_logging.py

Persistent request logging + lightweight enumeration detection for Tatou.

Writes one line per request to $LOG_DIR/security.log (default /app/logs),
bind-mounted to ./logs on the host so logs survive container rebuilds.
Also flags bursts of 4xx responses from one source IP as suspected
enumeration -- the monitoring signal for operational security.

Request bodies are never logged (they can contain passwords or secrets):
only method, path, status, source IP, and the authenticated login if any.
"""
from __future__ import annotations

import os
import time
import logging
from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler

from flask import request, g

_SUSPECT_WINDOW = 60       # seconds
_SUSPECT_THRESHOLD = 20    # 4xx from one IP within the window -> alert
_events = defaultdict(deque)
_last_alert = {}


def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "-"


def init_security_logging(app) -> None:
    log_dir = os.environ.get("LOG_DIR", "/app/logs")
    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception:
        pass

    logger = logging.getLogger("tatou.security")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        h = RotatingFileHandler(
            os.path.join(log_dir, "security.log"),
            maxBytes=5_000_000, backupCount=5, encoding="utf-8",
        )
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(h)
    app.config["_SEC_LOGGER"] = logger

    @app.after_request
    def _log_request(resp):
        try:
            if request.path == "/healthz":
                return resp
            ip = _client_ip()
            user = getattr(g, "user", None)
            who = user.get("login") if isinstance(user, dict) else "-"
            logger.info("ip=%s user=%s %s %s -> %s",
                        ip, who, request.method, request.path, resp.status_code)
            if 400 <= resp.status_code < 500:
                now = time.time()
                dq = _events[ip]
                dq.append(now)
                while dq and now - dq[0] > _SUSPECT_WINDOW:
                    dq.popleft()
                if len(dq) >= _SUSPECT_THRESHOLD and now - _last_alert.get(ip, 0) > _SUSPECT_WINDOW:
                    _last_alert[ip] = now
                    logger.warning("SUSPECTED ENUMERATION ip=%s %d 4xx in %ds (last path=%s)",
                                   ip, len(dq), _SUSPECT_WINDOW, request.path)
        except Exception:
            pass
        return resp
