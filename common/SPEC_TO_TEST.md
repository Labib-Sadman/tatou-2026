# Spec-to-test mapping — Tatou (Group 20)
pytest --cov=src: 50 passed, 2 pre-existing failures, 3 skipped, 53% total.

## Platform specs
- P2 unwatermarked docs owner-only -> test_auth_regression (401 missing/forged/tampered)
- P3 generate versions -> test_watermarking_all_methods, test_qim_baseline::TestRoundTrip
- P4 hard to remove -> test_qim_baseline::TestRobustness
- P5 secret retrievable by owner -> test_read_secret_roundtrip
- P6 link not guessable -> secrets.token_hex / nonce; test_full_handshake_returns_the_expected_link
- P8-P11 confidentiality/availability/removal -> owner-scoped queries + @require_auth

## CC SFR
- FPT_RPL.1 replay -> test_rmap_routes::TestReplayBehaviour: FAILS by design (replays accepted) = the CC finding.

## Hardening -> test
- unforgeable tokens -> test_auth_regression + effectiveness_check_evidence.txt
- load-plugin 410 -> test_valid_token_passes_auth_and_plugin_endpoint_stays_disabled
- SECRET_KEY fail-closed -> create_app raises; verified printenv=64-hex
- SQLi/IDOR fixes -> manual (401 / 404)

## Coverage: qim 93, bash-bridge 94, rmap_routes 84, security_logging 84,
## encrypted_metadata 81, server.py 29 (routes need DB), cli 0. TOTAL 53%.
