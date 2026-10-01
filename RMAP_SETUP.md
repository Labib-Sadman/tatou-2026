# RMAP endpoints — setup

Implements `POST /api/rmap-initiate` and `POST /api/rmap-get-link` per
section 5 of the project instructions.

## What was added

| File | Change |
|---|---|
| `server/src/rmap_routes.py` | new — both routes and the version-creation logic |
| `server/test/test_rmap_routes.py` | new — 10 tests, full handshake with generated keys |
| `server/src/server.py` | 2 lines — import + `register_rmap_routes(app, get_engine)` |
| `server/pyproject.toml` | 1 line — `rmap @ git+.../RMAP.git@v1.0.2` |
| `docker-compose.yml` | RMAP env vars + read-only `./keys` mount |
| `.gitignore` | never commit `keys/` or `*.asc` (except client public keys) |

## 1. Generate the server keypair

Run once, on the VM. **The private key must never be committed.**

```bash
cd ~/tatou-2026
mkdir -p keys/clients
pip install "rmap @ git+https://github.com/nharrand/RMAP.git@v1.0.2"
rmap-keygen --name "Group 20" --email group20@softsec.invalid \
    --out-private keys/server_priv.asc --out-public keys/server_pub.asc
chmod 600 keys/server_priv.asc
```

Publish `keys/server_pub.asc` wherever the course expects it, so other
groups can encrypt to us.

## 2. Install the client public keys

Download the course key directory (forum resource id 32678) and drop the
`.asc` files into `keys/clients/`. The identity is the file stem, so
`Group_07.asc` registers the identity `Group_07` — the names must match
exactly what the other groups send.

## 3. Upload the assigned document

Upload `Group_20.pdf` (emailed to us) through the normal
`upload-document` API as the account that should own it, then note its
document id:

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:5000/api/list-documents
```

## 4. Configure `.env`

```
RMAP_DOCUMENT_ID=<the id from step 3>
RMAP_METHOD=encrypted-metadata
RMAP_KEY=<a long random string, our watermark key>
RMAP_LINK_PREFIX=http://softsec-group-20.dsv.local.su.se:5000/api/get-version/
# RMAP_PASSPHRASE=   only if the private key is passphrase-protected
```

`RMAP_KEY` is what lets us *read* the watermark later to attribute a
leak. Keep it — if it is lost, the watermarks become unreadable.

## 5. Deploy

```bash
docker compose up --build -d
docker compose logs server --tail 20
```

## How it behaves

- `rmap-initiate` takes Message 1 and returns Response 1, or 403 for an
  unregistered identity, 400 for anything malformed.
- `rmap-get-link` takes Message 2, then **creates the watermarked copy
  and inserts the `Versions` row before returning the link**. If that
  fails the client gets a 500 and no link, as the spec requires.
- The watermark secret is the authenticated identity from the handshake,
  never anything the client supplied — that is what makes a leaked copy
  attributable.
- Each handshake produces a fresh link and its own watermarked file.
- The link is the bare 32-hex session link, so the existing
  `GET /api/get-version/<link>` route serves the document with no extra
  work.
- Error responses are deliberately uniform (`{"error": "rmap handshake
  failed"}`); distinguishable messages would let an attacker map the
  protocol state machine.
- With no keys present the routes answer 503 and the rest of the
  platform still runs, so a laptop without keys can still develop.

## Known gaps for the team to decide on

1. **Watermark choice.** `encrypted-metadata` works on the assigned PDF
   but lives in the `/Info` dictionary, which is trivially stripped.
   The assigned document is one page that is mostly a single image, so
   `qim-baseline` is not applicable (only 50 carriers, 136 bits needed).
   For Phase II an image-domain technique would be far more robust.
2. **No audit log.** Handshake attempts, including rejected ones, are
   not recorded anywhere persistent.
3. **Session state** lives in the `RMAPServer` instance, so it is lost
   on restart and not shared across gunicorn workers. With more than one
   worker, a handshake can land on a different process than the one that
   started it. Currently the deployment runs a single worker.
