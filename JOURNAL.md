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

## 2026-10-11 — Vulnerability: Guessable Watermark Link

**Found:** `/api/get-version/<link>` has no authentication by design — the link
itself is the credential. The `link` token was computed as
`sha1(watermarked_file_name)`, and the file name was built as
`"<original_name>__<intended_for_slug>.pdf"` — both fully derivable from
public information (the document name and the intended recipient). Anyone
who could guess those two strings could compute the link and download our
watermarked PDF without logging in.

**Evidence:** Queried the live `Versions` table and confirmed 8/8 recent
rows matched `sha1(CONCAT(doc_name_stem, "__", intended_for, ".pdf"))`,
confirming the bug was real and currently exploitable, not theoretical.
(This check also resolved an earlier open question: a `flag_3` document
owned by `mr_important@example.com`, user id 52, was Professor Nicolas's legitimate
Phase II flag delivery, not a stray audit artifact — confirmed only one such
account exists, no naming collision.)

**Fix:** In `server/src/server.py`, `create-watermark` now generates
`link_token = secrets.token_hex(20)` first and embeds only the first 8 hex
characters into the file name (`"<name>__<intended>__<token8>.pdf"`), instead
of deriving the link from the file name via `sha1`. The link is now
independent random data, not guessable from any public information.

**Also fixed in the same pass:**
- `RMAP_KEY` was unset in `.env` (startup warning: "defaulting to a blank
  string"), meaning any RMAP watermark created up to this point would have
  been created with a blank key. Generated and added a proper 32-byte
  random key.
- The `phpMyAdmin` container was three weeks stale and still bound to
  `0.0.0.0:8080`, publicly exposed, despite `docker-compose.yml` already
  specifying `127.0.0.1:8080` only — the *running* container predated that
  fix and a plain `docker compose down`/`up` does not touch a profile-gated
  service. Stopped and removed it explicitly; it now only starts when
  requested with `--profile dev`.
- Pulled 13 commits that were on `origin/main` but had never been deployed
  to the VM, including the RMAP implementation (commit `5598157`) and the
  auth regression tests (commit `1e246e8`).

**Verification:** `sha1("linktest__g20-audit.pdf")` does not match a real
issued link, confirming the old guessing formula no longer works; a real
issued link still returns `200` from `get-version`, confirming legitimate
downloads still work.

Committed and pushed to `main` (commit `44423d9`).

## 2026-10-11 — Audit of `rmap_routes.py`

Read the full RMAP routes file end to end. Our own route code is sound:
error messages are deliberately generic (to avoid leaking protocol state to
an attacker), the path-traversal check is reused from the rest of the app,
the watermark secret is hardcoded to the authenticated identity (never
client-supplied), and a duplicate `rmap-get-link` call is deduplicated
against the `Versions` table so no second file or row is ever created.

Traced the previously-found replay weakness (see 2026-10-01 entry, SFR
FPT_RPL.1) to its root cause: it lives in the `rmap` pip package itself
(the course's reference implementation), not in our route code. In
`rmap/server.py`, `receiveMsg2()` never invalidates the session nonce after
a successful handshake, so resending an identical Message 2 just re-derives
the same link and returns 200 again. Severity assessed as low in practice —
`resp2` is PGP-encrypted to the requesting identity's own public key, so a
network observer who replays the captured ciphertext still cannot read the
result without that identity's private key. Decided not to patch this
ourselves (third-party library code that would be overwritten on every
rebuild anyway); Professor Nicolas's 2026-10-11 announcement says he is addressing
RMAP issues this week.

## 2026-10-12/13 — RMAP v2.0.0 Upgrade and First Working Deployment

Professor Nicolas announced the shared test bench's RMAP test is now working, and
published `rmap` v2.0.0, fixing a server crash on a malformed-but-validly-
encrypted message found by another group.

- Updated the `rmap` dependency in `server/pyproject.toml` from the v1.0.2
  git tag to the v2.0.0 release wheel and rebuilt. Confirmed `pip show rmap`
  reports `2.0.0` and `/healthz` is unaffected. Committed and pushed
  (commit `05dbe9b`).
- Checked `RMAP_LINK_PREFIX`: unset in `.env`, defaulting to an empty
  string, so we already return the bare 32-hex nonce concatenation as the
  link rather than a full URL — matching what Professor Nicolas said the test bench
  expects (some other groups fail this check for sending the full URL
  instead).

**Bigger finding: RMAP had never actually been deployed on the shared VM.**
`keys/` (correctly gitignored) was completely empty — no server keypair, no
`keys/clients/` directory — and `.env` had neither `RMAP_DOCUMENT_ID` nor
`RMAP_PASSPHRASE` set. Every real call to `rmap-initiate` or `rmap-get-link`
would have returned `503` ("rmap not configured on this server"). The
2026-10-01 entry's "manual end-to-end run against the live stack" must have
been run against a different, local setup, since the shared VM itself was
never wired up with real keys or an assigned document.

Fixed by following `RMAP_SETUP.md`:
1. Generated a fresh server keypair (`rmap.keygen`, name "Group 20"),
   placed at `keys/server_priv.asc` / `keys/server_pub.asc` on the VM
   (private key `chmod 600`). Not committed — gitignored by design, exists
   only on this VM. **Needs separate backup/handoff if the VM is rebuilt.**
2. Uploaded the assigned `Group_20.pdf` (emailed earlier by Professor Nicolas) via
   the normal upload API under a new dedicated account,
   `rmap-service@softsec.invalid` (user id 70), document id 55.
3. Set `RMAP_DOCUMENT_ID=55` in `.env` and recreated the server container
   so it picked up the new keypair and env var.
4. Registered a throwaway test identity (`TestClient20`) in
   `keys/clients/` to exercise the handshake without touching any real
   group's keys.

**End-to-end verification**, using the `rmap` package's own CLI test
client against our live endpoints: Message 1/Response 1 exchanged nonces
correctly; Message 2/Response 2 returned a link that matched the client's
independently-computed expected value exactly; `GET /api/get-version/<link>`
returned `200` with a genuine watermarked PDF. Cleaned up the test
`Versions` row afterward.

RMAP is now genuinely functional end-to-end on the shared VM, not merely
present in the code.

**Still outstanding:**
- `keys/clients/` only has the throwaway test identity — real client keys
  from the iLearn key directory still need to be added before a real
  cross-group handshake will succeed.
- Our `keys/server_pub.asc` has not yet been published anywhere for other
  groups to use.
- A real cross-group RMAP test (per Professor Nicolas's recommendation) has not been
  done yet.

## 2026-10-13 — Incident: `flag_3` Captured by Another Group

**Notification:** Instructor (Professor Nicolas) emailed that our `flag_3` had
been captured by another group and asked us to rotate it, investigate the
cause, fix the vulnerability, and log the incident (this entry). New value
provided: `f82589697ef0a2b4a7271eb942a073b0801d4918`.

**Background:** `flag_3` is delivered as a PDF (per the project
instructions), uploaded by the instructor's own account
(`mr_important@example.com`, user id 52) as document id 43, containing the
plain text `"Flag 3"` followed by the flag value.

**Investigation:** Queried the `Versions` table for `documentid = 43` and
found four existing watermarked copies of the document that we never
created — two explicitly labelled `intended_for = "g16-audit"`, and two
using disposable-looking email addresses as the `intended_for` value with
the `toy-eof` method. None of these were requested by our own accounts.

**Root cause:** `POST /api/create-watermark` looked up the target document
with:

    SELECT id, name, path FROM Documents WHERE id = :id LIMIT 1

despite an in-code comment claiming ownership was enforced — there was no
`ownerid` filter at all. Any authenticated user (including a throwaway
account self-registered through our own open `create-user` endpoint) could
request a watermark of *any* document by id, including documents owned by
other users, and the response returns the resulting download link directly.
This is almost certainly how `flag_3` was captured: enumerate/guess document
ids, call `create-watermark` on id 43, use the returned link.

**Fix:** Added the missing ownership check, matching the existing pattern in
`get-document`:

    SELECT id, name, path FROM Documents WHERE id = :id AND ownerid = :uid LIMIT 1

Verified with a fresh, unrelated test account: requesting a watermark of
document 43 now returns `404` instead of succeeding.

**Containment:** The four leaked `Versions` rows were independent files
already written to disk, so fixing the query alone would not have revoked
already-issued links. Deleted all four watermarked files and their
`Versions` rows.

**Flag rotation:** Rewrote the flag PDF's text to the new value. Initially
used an incremental save (`doc.saveIncr()`), then discovered the *old* flag
value was still present in the raw file bytes (incremental saves retain
prior revisions) even though normal text extraction showed only the new
value — a residual-disclosure risk if anyone inspected the file at a lower
level. Re-saved with a full rewrite and garbage collection
(`doc.save(..., garbage=4, clean=True)`) and confirmed the old value is no
longer present anywhere in the file. Updated the stored `sha256`/`size` for
document id 43 to match.

Committed and pushed the access-control fix to `main` (commit `d5ab91c`).

**Outstanding:** Should audit other routes for the same "comment claims a
check that the query doesn't actually perform" pattern, since this is now
the second access-control bug found this way (the first being the
guessable-link issue on 2026-10-11, which this incident shows was not
sufficient on its own — the missing `ownerid` check let the link be minted
through the legitimate API regardless of link predictability).

## 2026-10-13 — Addendum: Full Scope of the `create-watermark` Access Control Breach

After fixing and logging the `flag_3` incident above, checked whether the
same missing-ownership-check bug had been exploited against other
documents, not just `flag_3`. It had, extensively.

Queried the whole `Versions` table for any `intended_for` value containing
"audit" and found **39 leaked watermarked copies**, spanning roughly 30
distinct documents belonging to many different users across the server —
essentially a systematic enumeration of document ids 2 through 53. Two
different label patterns were present: `g16-audit` (the large majority,
clearly Group 16) and `group20-audit` (5 earlier entries, despite our own
accounts not having created them — likely the same actor testing under a
different/earlier label, or a different party; not conclusively
attributed).

File names confirmed the exploitation window ran both before and after our
2026-10-11 guessable-link fix: 14 of the 39 used the old, predictable
naming scheme (already overwritten/missing by the time of this check), and
25 used the new random-token naming scheme introduced on 2026-10-11 — i.e.
the broken ownership check alone was sufficient to keep exploiting the
endpoint even after the link-guessing bug was fixed, since `create-watermark`
returns the link directly in its JSON response regardless of how
unguessable it is.

**Containment:** Wrote a one-off script to delete all 39 `Versions` rows
and their corresponding files from disk in one pass. Verified zero
remaining rows matching the pattern, and confirmed `/healthz` still green
afterward. No DB or server restart was required, since this was pure data
cleanup against the already-fixed endpoint.

**Assessment:** The watermarked copies that leaked are of ordinary
user-uploaded test files (`minimal.pdf`, `test.pdf`, `file`, etc. — mostly
small placeholder/test documents from various team members' own testing
sessions) rather than sensitive content, aside from `flag_3` itself
(covered above). No further action identified beyond the access-control
fix and cleanup already done. Not escalated to the instructor, since the
underlying vulnerability is already fixed and the exposed content was not
sensitive beyond the flag already reported and rotated.
