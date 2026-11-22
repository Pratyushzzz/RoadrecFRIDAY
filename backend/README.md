# RoadRec backend (FastAPI)

    cd backend
    pip install -r requirements.txt
    uvicorn app.main:app --reload        # API docs at /docs
    python -m pytest -q                  # 13 tests

## Configuration (environment)

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Default `sqlite:///./roadrec.db`; use Postgres when deployed |
| `SECRET_KEY` | Signs sign-in tokens. **Required** when `ENV=production` |
| `INVITE_CODE` | Needed to register insurer/authority accounts. Unset means those roles cannot register |
| `MAX_UPLOAD_BYTES` | Default 5 MB |
| `CORS_ORIGINS` | Comma-separated; default `*` (tighten before the live demo) |
| `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` | Optional graph sync (untested against a live Neo4j) |

## Roles

- **fleet_manager** (open registration): registers vehicles, uploads events, reads reports, creates and revokes share links. Sees only their own fleet.
- **insurer / authority** (invite code): open a share link's tamper-checked evidence report with a case summary.

## Endpoints

| Endpoint | Who |
|---|---|
| `POST /auth/register`, `POST /auth/login`, `GET /auth/me` | all |
| `POST/GET /vehicles` | fleet manager |
| `POST /events` (multipart: `vehicle_id`, `file`, optional `recorded_at`, `claimed_sha256`) | fleet manager |
| `GET /events`, `GET /events/{id}`, `GET /events/{id}/verify` | fleet manager (own events) |
| `POST /events/{id}/share`, `DELETE /shares/{token}` | fleet manager |
| `GET /shared/{token}` | anyone with the link: read-only report, integrity result, no raw file |
| `GET /shared/{token}/evidence-report` | insurer / authority: report + integrity + case summary |

Errors are `{"detail": {"code", "message"}}`: `file_too_large` (413), `duplicate_upload` (409), `too_little_data`, `bad_header`, `bad_row`, `bad_time`, `not_text`, `empty_file` (422), `share_expired` (410).

The server hashes every file itself; a client-supplied fingerprint is only compared against it (`match`/`mismatch`/`not_provided`).
`/verify` and the evidence report re-hash the stored file each time, so later tampering with the database copy shows up.

## Live tracking (for sharing with an authority)

The tracker pushes positions with a per-vehicle **device key**. The owner can then open a time-limited **live share**.
Viewing needs both the link (`/live/{code}`) and a **6-digit OTP** that the owner passes on through a different channel.

| Endpoint | Who |
|---|---|
| `POST /vehicles/{id}/device-key` | fleet manager. Returns the key once; calling again replaces it |
| `POST /track/position` (header `X-Device-Key`; body `lat`, `lon`, optional `speed_mps`, `heading_deg`, `t`) | tracker |
| `POST /vehicles/{id}/live-share` (`hours` 1-72, `label`) | fleet manager. Returns `code` and `otp` once |
| `GET /live-shares`, `DELETE /live-shares/{code}`, `GET /live-shares/{code}/access-log` | fleet manager |
| `POST /live/{code}/unlock` (`{"otp": "123456"}`) | anyone with the link. Returns a 15-minute viewer token |
| `GET /live/{code}` (Bearer viewer token) | latest position, 30-minute trail, `stale` flag |

Protections: OTP stored as a keyed hash and bound to its share; 5 wrong codes lock the share (owner must create a new one);
the viewer token works for one share and so one vehicle; viewers see only positions recorded after the share was created;
every unlock, failure and view is logged for the owner; positions older than 72 h are deleted.
**Owner live view (login required).** `GET /vehicles/{id}/live` and the SSE feed `GET /vehicles/{id}/live/stream` need the fleet manager's
login token and only work for that user's own vehicles. `PATCH /vehicles/{id}/live-toggle?enabled=false` pauses it. There is no public code.

Try it: run the API, create a share, run `python/simulate_tracker.py --key ...`, open `web/live.html?c=CODE&api=http://localhost:8000`.
Use HTTPS and set `SECRET_KEY` in production. The OTP is shown to the owner, not sent by SMS/email; adding delivery is a next step.
