# SOFTSEC Group 20 — Operations & Incident Journal

## 2026-09-13 — Phase 0 Deployment

- Set up VPN (WireGuard) and SSH access to VM `softsec-group-20`.
- Forked and cloned `tatou-2026` to the VM.
- Installed Docker/Docker Compose (pre-installed on VM image) and git.
- Deployed the stack with `docker compose up --build -d` (server, MariaDB, phpMyAdmin).
- Configured `.env` (DB credentials, `FLAG_2`).
- Confirmed `/healthz` reachable from inside the VM. External access via VPN to
  port 5000 does not work due to VPN routing (confirmed expected by instructor,
  SSH tunneling recommended as a workaround for local testing).
- Fixed a `.env` parsing bug: `MARIADB_PASSWORD` originally contained an `@`
  character, which broke the SQLAlchemy connection URL (the `@` was
  misinterpreted as the user:password/host separator). Removed the volume,
  regenerated the password without reserved URL characters, and rebuilt —
  `db_connected` now reports `true`.
- Generated a GPG keypair (RSA 4096) for the group and submitted the public key.
- Submitted the repository link (public fork).
- Added group members as GitHub collaborators.

## 2026-09-14 — Vulnerability: Command Injection in `add_watermark`

**Found:** `server/src/unsafe_bash_bridge_append_eof.py` (`bash-bridge-eof`
method) built a shell command by directly concatenating the user-supplied
`secret` parameter:

    cmd = "cat " + str(pdf.resolve()) + " &&  printf \"" + secret + "\""
    subprocess.run(cmd, shell=True, check=True, capture_output=True)

Since `secret` is taken verbatim from the `create-watermark` API request and
passed to `shell=True`, an attacker-controlled `secret` value can inject
arbitrary shell commands (e.g. reading `/app/flag`).

**Fix:** Removed the shell call entirely; the method now appends the secret
as raw bytes directly in Python:

    return data + secret.encode("utf-8")

Verified `healthz` and normal operation after rebuild. Committed and pushed
(commit `fa9648c`).

**Also reviewed (no fix needed):** `add_after_eof.py` (`toy-eof` method) uses
HMAC-SHA256 with `hmac.compare_digest` correctly (protects integrity/
authenticity of the watermark), but by design does not encrypt the secret —
it is only base64-encoded, so anyone with the PDF bytes can read the secret
without the key. Documented as a known design limitation, not an
implementation bug.

## 2026-09-25 — Incident: `FLAG_2` Captured by Another Group

**Notification:** Instructor (Nicolas) emailed that our `flag_2` had been
captured by another group and asked us to rotate it, investigate the cause,
fix the vulnerability, and log the incident (this entry).

**Immediate action:** Rotated `FLAG_2` in `.env` to the new value provided
and rebuilt the server container. Confirmed the new flag is present at
`/app/flag` inside the container.

**Investigation:** Queried the `Versions` table in MariaDB for all watermark
records created on our server:

    SELECT id, documentid, link, intended_for, method FROM Versions;

Found 22 records, the large majority using `intended_for` labels such as
`victim`, `victim2`, `flagread2`, `findfl`, `findfl2`, `findfl3`, `flagout` —
clearly an attacker's own working notes while repeatedly probing the server,
all using the `bash-bridge-eof` method (the command-injection method fixed on
2026-09-14).

**Root cause (assessed):** The attacker very likely exploited the same
command-injection vulnerability in `bash-bridge-eof` to read `/app/flag`
directly from the container filesystem via `create-watermark`. We were not
able to establish an exact timestamp for the captured records (Docker
container logs from before 2026-09-25 were lost when the server container
was recreated during same-day remediation work, before we thought to check
historical logs — noted below as a process gap). Git history confirms our
fix was committed 2026-09-14 11:03 CEST; the server had been running
continuously since then without the vulnerable code (`db`/`phpmyadmin`
containers show 11 days uptime as of today, implying the `server` container
built from the patched code has also been running since then). Given this,
it is plausible the flag was captured very early on 2026-09-14, shortly
after Phase 0 deployment and before our fix landed, or via a vector we have
not yet identified. This remains a partially open question; see "Process
gaps" below.

**Process gap identified:** Docker's default logging is tied to the
container instance and is lost on `docker compose up --build` (container
recreation). We do not currently have historical logs pre-dating today. This
limited our ability to pin down the exact capture timestamp during this
investigation. **Action item:** consider configuring persistent/exported
container logging going forward.

## 2026-09-25 — Additional Hardening (same session)

While investigating the flag capture, performed a broader security review
and fixed several additional issues:

1. **Hardcoded default `SECRET_KEY`.** `server.py` fell back to the literal
   default `"dev-secret-change-me"` when `SECRET_KEY` was not set in the
   environment — and it was never set in our `.env`. Since this default is
   publicly visible in the (public) template repository, any attacker who
   read the repo could sign arbitrary auth tokens for any user without
   knowing a password. **Fix:** generated a random 32-byte hex secret,
   added `SECRET_KEY` to `.env` and wired it through `docker-compose.yml`
   (`server.environment`). All previously issued tokens are now invalid.

2. **MariaDB and phpMyAdmin exposed externally.** A teammate (MK3713)
   independently found and fixed this: removed MariaDB's `3306:3306` port
   publishing (the server still reaches the DB over the internal Docker
   network) and restricted phpMyAdmin to a `dev` compose profile, bound to
   `127.0.0.1` only, so it no longer runs — or is reachable — by default.
   Merged this fix and redeployed; confirmed with `docker ps` that neither
   service is externally exposed anymore.

3. **No brute-force protection on `/api/login`.** Added a simple in-memory
   rate limiter: 5 failed attempts per email within a 5-minute window, after
   which the endpoint returns `429`. Verified with 6 consecutive failed
   login attempts (five `401`s, then a `429`).

4. **Path traversal in `/api/upload-document`.** The uploaded file's
   `filename` was used directly (only prefixed with a timestamp) to build
   the storage path, with no sanitization. Confirmed exploitable: a filename
   like `foo/../../../../tmp/pwned.txt` resolved outside the intended
   per-user storage directory. **Fix:** wrapped the filename in Werkzeug's
   `secure_filename()` (already imported but unused) and reject uploads
   where the sanitized name is empty. Re-tested the same payload — the file
   now lands safely inside the user's own directory with a sanitized name.

5. **Remote code execution via `/api/load-plugin`.** This endpoint builds a
   file path directly from an unsanitized, user-supplied `filename` and then
   calls `pickle.load()` (or `dill.load()`) on the resulting file with no
   integrity or type checking. Combined with `/api/upload-document` allowing
   any authenticated user to upload arbitrary byte content under an
   attacker-chosen name, this forms a full exploit chain: upload a malicious
   pickle payload as a "document", then reference it from `load-plugin` via
   a path-traversal `filename` (e.g. `../<own-login>/<stored-filename>`) to
   trigger deserialization and arbitrary code execution — reachable by any
   registered user, not just an admin. Given the severity and the deadline,
   **disabled the endpoint entirely** (returns `410 Gone`) rather than
   attempting a partial fix under time pressure. Flagged for the team as
   needing a proper redesign (avoid `pickle`/`dill` on untrusted input
   entirely, e.g. a signed/whitelisted plugin mechanism) before ever
   re-enabling it.

All fixes committed and pushed to `main` (commits `04c50d9`, `b425af7`,
`976faf6`, plus the merged teammate fix `d954e7f`/`4b525bd`).

## Outstanding / not yet done

- Database password rotation (`MARIADB_ROOT_PASSWORD`, `MARIADB_PASSWORD`)
  as a precaution, in case the attacker had shell-level access via the
  command injection bug during the exploit window. Deferred — the direct
  exploitation paths we could identify (command injection, RCE via
  load-plugin) are now closed.
- Persistent/exportable container logging, to avoid losing forensic
  evidence on future container rebuilds.
- Individual watermarking method implementation (per-member Phase I
  deliverable) — not started.

## 2026-09-28 — Individual Watermarking Method + `read-watermark` Bug Fix

**Individual deliverable (Labib Sadman):** Implemented `encrypted-metadata`,
a new watermarking method in `server/src/encrypted_metadata.py`, registered
in `watermarking_utils.py`'s `METHODS` registry.

- Embeds the secret using **AES-256-GCM** (authenticated encryption —
  provides real confidentiality and integrity in one primitive), unlike
  `add_after_eof` which only base64-encodes the secret with a separate HMAC.
- The AES key is derived from the caller's `key` string via
  PBKDF2-HMAC-SHA256 with a random per-watermark salt.
- The encrypted payload is stored in a custom key (`TatouWM`) of the PDF's
  `/Info` dictionary via PyMuPDF, so it lives in real PDF structure rather
  than being appended as raw bytes after `%%EOF` (as both existing toy
  methods do).
- Added `cryptography>=42.0.0` as a new dependency in `server/pyproject.toml`.

**Testing performed:**
- CLI (`pdfwm embed` / `pdfwm extract`): correct key recovers the secret;
  wrong key is cleanly rejected with an authentication error; verified the
  watermarked PDF still opens correctly and page content is unchanged.
- Live API (`create-watermark` / `read-watermark` via curl): same result,
  end to end, through a real authenticated user session.
- Regression check: re-tested the existing `toy-eof` method through the same
  API flow to confirm no existing functionality broke.
- Web UI: visually confirmed via the "Versions" and "Read watermark" panels
  on `documents.html` — the encrypted secret is correctly recovered with the
  right key through the actual frontend, not just the API directly.

**Bug found and fixed (affects the whole platform, not just this method):**
`/api/read-watermark` was querying the `Documents` table for the file path,
i.e. always reading the **original, unwatermarked** file rather than the
actual watermarked file stored in `Versions.path`. As a result, no
watermarking method's secret could ever be recovered via the API — this
predates tonight's work and would have affected every group using this
template. Fixed by querying `Versions` (most recent row matching
`documentid` + `method`) instead of `Documents`. Verified with both the new
method and the pre-existing `toy-eof` method after the fix.

**Minor hardening:** Trimmed the `get_usage()` string for `encrypted-metadata`
to avoid disclosing the exact algorithm and `/Info` key name in the public
`get-watermarking-methods` response, reducing information available to
other groups probing the API (low-severity — security relies on the AES key,
not on hiding the field name — but a reasonable minimization since the
public method list is essentially free intel for an attacker to browse).

All changes committed and pushed to `main`.

## 2026-10-01 — Individual Watermarking Method: qim-baseline

**Individual deliverable (MK3713):** Implemented `qim-baseline` in `server/src/qim_baseline.py`, registered in the `METHODS` registry, with tests in `server/test/test_qim_baseline.py`. The method hides the secret in the parity of quantized text-line coordinates (Quantization Index Modulation): both the horizontal start position and the baseline of every text line are snapped onto a 0.25pt grid, where an even grid index encodes a 0 and an odd index a 1. Quantizing rather than shifting relative to the original matters because the owner of a leaked document has no original to compare against — extraction just divides by the step, rounds, and reads the parity. The secret is encrypted with a key-derived keystream and authenticated with a 64-bit truncated HMAC-SHA256, and the payload is repeated across all available carriers with a per-bit majority vote on extraction. Tested end to end through the API and with 17 unit tests: extracted text stays byte-identical (max word displacement 0.249pt), output is deterministic, wrong keys and unwatermarked PDFs are rejected, and the mark survives re-saving, metadata stripping and trailing-page loss. Known limitations: any tool that regenerates content streams (Ghostscript, print-to-PDF, rasterisation) destroys it, and removing content from the front of a document shifts repetitions out of phase and defeats extraction.

All changes committed and pushed to `main`.

## 2026-10-01 — RMAP endpoints implemented (Phase I deliverable)

**Implemented by MK3713.** Added `POST /api/rmap-initiate` and `POST /api/rmap-get-link` in `server/src/rmap_routes.py`, wired into `create_app()` in `server.py`. `rmap-initiate` takes Message 1 and returns Response 1; `rmap-get-link` takes Message 2 and, before returning anything, creates a watermarked copy of our assigned document for the authenticated identity and inserts the corresponding `Versions` row — the spec requires that no link be returned unless the version actually exists. The link is the bare 32-hex session link, so the existing `GET /api/get-version/<link>` serves it unchanged. The watermark secret is the identity from the completed handshake, never client-supplied input, so a leaked copy is attributable. Error responses are uniform (`{"error": "rmap handshake failed"}`) to avoid mapping the protocol state machine for an attacker; status codes still differ (403 unknown identity, 409 no matching session, 400 malformed). Keys are mounted read-only from `./keys` and gitignored; the server private key is never committed. With no keys present the routes answer 503 and the rest of the platform still runs.

Verified by 10 automated tests plus a manual end-to-end run against the live stack: handshake completed, `get-version` served the PDF, and the stored watermark read back as the requesting identity. **Two open items for the team:** the assigned PDF is a single mostly-image page offering only 50 QIM carriers, so `qim-baseline` cannot be used for RMAP and we currently fall back to `encrypted-metadata`, which is trivially stripped and a more robust method matters before Phase II attacks. And `RMAP_KEY` in the VM's `.env` is the key our RMAP watermarks are created with; if it is lost or rotated, older watermarked copies become unreadable and leak attribution fails. Someone needs to hold a backup. Also noted: new client public keys are only recognised after a server restart, since the key directory is loaded once and cached.

## 2026-10-01 — Replay and session-handling testing of the RMAP handshake

Tested our own deployment (commit 5598157, single gunicorn worker) against the replay angle of T.RMAP_FORGE, using our `Group_20` keypair. **Finding: the handshake does not detect replay.** A captured Message 2 resent to `rmap-get-link` is accepted and returns the same link again; a captured Message 1 resent to `rmap-initiate` is also accepted and starts a new session that displaces the pending one, so the legitimate client can no longer complete with the nonce it originally received (409). No link is obtainable this way — both responses are encrypted to the client — and no duplicate `Versions` row is created, so the impact is denial of service against one identity's handshake rather than forgery. The underlying cause is that the server keeps a single pending session per identity with no invalidation on use: a session stays answerable until a newer Message 1 displaces it. The same design means two *legitimate* overlapping handshakes collide, with no attacker involved. Sessions are isolated per identity, so one group cannot disturb another's.

**Methodology**: The first test run executed several replay cases in sequence against a shared session. Because a Message 1 replay displaces the pending session, later cases ran against state the earlier ones had already destroyed, returning 409s that looked like replay rejection — a false pass that initially led us to conclude replay *was* rejected. Re-running each case in isolation against a freshly restarted server inverted the result. The measured behaviour is now pinned by 8 regression tests in `server/test/test_rmap_routes.py` (`TestReplayBehaviour`, `TestSessionHandling`), each resetting session state first, so a future change to replay or session handling fails the suite instead of passing silently. **Open:** replay detection is not implemented; rejecting a previously used nonce, and invalidating a session once used, would close both findings.
