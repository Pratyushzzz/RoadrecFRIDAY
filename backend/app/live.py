"""Live vehicle tracking: device ingest, owner live view, OTP-protected shares for authorities, audit trail.

Two ways to watch a vehicle, both private:
  1. The owner: log in (POST /auth/login) and open /vehicles/{id}/live. Other users get 404 for vehicles they don't own.
  2. An authority the owner chose: share link (web/live.html?c=CODE) that needs the link code AND a 6-digit OTP the owner gives out separately.
     OTPs are stored hashed, expire with the share, lock after MAX_ATTEMPTS wrong tries, and unlock only returns a
     short-lived viewer token scoped to that one share. Viewers only see positions recorded AFTER the share was made.
Positions are also pushed to open pages in real time over Server-Sent Events (owner view)."""
import asyncio, hashlib, hmac, json, secrets
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, delete
from sqlalchemy.orm import Session

from . import auth, models, schemas
from .db import get_db
from .errors import err

router = APIRouter()
MAX_ATTEMPTS = 5
VIEWER_TOKEN_S = 15 * 60
STALE_S = 120
TRAIL_MINUTES = 30
KEEP_HOURS = 72                      # positions older than this are deleted on ingest
_fleet = auth.require_roles("fleet_manager")
_bearer = HTTPBearer(auto_error=False)

# vehicle_id -> {(loop, queue)}. push_position runs in a worker thread, so it must hand frames to the
# event loop with call_soon_threadsafe rather than touching the asyncio queue directly.
_subscribers: dict[int, set] = {}


def _broadcast(vehicle_id: int, payload: dict):
    subs = _subscribers.get(vehicle_id)
    if not subs:
        return
    msg = json.dumps(payload)

    def put(q):
        if q.full():
            try: q.get_nowait()          # drop the oldest frame if a viewer is slow
            except asyncio.QueueEmpty: pass
        q.put_nowait(msg)

    for loop, q in list(subs):
        try: loop.call_soon_threadsafe(put, q)
        except RuntimeError: subs.discard((loop, q))   # loop already closed


def _h(value: str) -> str:
    """Keyed hash so a leaked database alone cannot be used to brute-force 6-digit OTPs."""
    return hmac.new(auth.secret_key().encode(), value.encode(), hashlib.sha256).hexdigest()


def _aware(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _own_vehicle(db, user, vehicle_id) -> models.Vehicle:
    v = db.get(models.Vehicle, vehicle_id)
    if not v or v.owner_id != user.id:
        raise err(404, "vehicle_not_found", f"Vehicle {vehicle_id} not found in your fleet")
    return v


def _log(db, share, action, request: Request | None):
    ip = request.client.host if request and request.client else ""
    db.add(models.LiveAccessLog(share_id=share.id, action=action, ip=ip))


# ---- device side ---------------------------------------------------------------
@router.post("/vehicles/{vehicle_id}/device-key", response_model=schemas.DeviceKeyOut, status_code=201)
def rotate_device_key(vehicle_id: int, user=Depends(_fleet), db: Session = Depends(get_db)):
    """Create or replace the tracker's key. The old key stops working immediately."""
    v = _own_vehicle(db, user, vehicle_id)
    key = "dk_" + secrets.token_urlsafe(32)
    row = db.scalar(select(models.DeviceKey).where(models.DeviceKey.vehicle_id == v.id))
    if row:
        row.key_hash = _h(key); row.created_at = _now()
    else:
        db.add(models.DeviceKey(vehicle_id=v.id, key_hash=_h(key)))
    db.commit()
    return schemas.DeviceKeyOut(vehicle_id=v.id, device_key=key)


@router.post("/track/position", status_code=202)
def push_position(p: schemas.PositionIn, x_device_key: str | None = Header(None), db: Session = Depends(get_db)):
    if not x_device_key:
        raise err(401, "device_key_required", "Send the device key in the X-Device-Key header")
    row = db.scalar(select(models.DeviceKey).where(models.DeviceKey.key_hash == _h(x_device_key)))
    if not row:
        raise err(401, "bad_device_key", "Unknown or replaced device key")
    now = _now()
    t = _aware(p.t) if p.t else now
    if abs((t - now).total_seconds()) > 300:
        t = now
    db.add(models.Position(vehicle_id=row.vehicle_id, recorded_at=t, lat=p.lat, lon=p.lon,
                           speed_mps=p.speed_mps, heading_deg=p.heading_deg))
    db.execute(delete(models.Position).where(models.Position.vehicle_id == row.vehicle_id,
                                             models.Position.recorded_at < now - timedelta(hours=KEEP_HOURS)))
    db.commit()
    _broadcast(row.vehicle_id, {"lat": p.lat, "lon": p.lon, "speed_mps": p.speed_mps,
                                "heading_deg": p.heading_deg, "recorded_at": t.isoformat()})
    return {"ok": True}


# ---- owner live view (login required) -------------------------------------------
@router.patch("/vehicles/{vehicle_id}/live-toggle")
def toggle_vehicle_live(vehicle_id: int, enabled: bool, user=Depends(_fleet), db: Session = Depends(get_db)):
    """Owner can pause/resume their own live view anytime."""
    v = _own_vehicle(db, user, vehicle_id)
    v.live_enabled = enabled
    db.commit()
    return {"vehicle_id": v.id, "live_enabled": v.live_enabled}


def _recent_positions(db, vehicle_id, since):
    return db.scalars(select(models.Position)
                      .where(models.Position.vehicle_id == vehicle_id, models.Position.recorded_at >= since)
                      .order_by(models.Position.recorded_at.desc()).limit(200)).all()


@router.get("/vehicles/{vehicle_id}/live")
def owner_live_snapshot(vehicle_id: int, user=Depends(_fleet), db: Session = Depends(get_db)):
    """Latest fix and recent trail. Only the logged-in owner of this vehicle gets it (others see 404)."""
    v = _own_vehicle(db, user, vehicle_id)
    if not v.live_enabled:
        raise err(403, "live_disabled", "Live tracking is paused for this vehicle")
    rows = _recent_positions(db, v.id, _now() - timedelta(minutes=TRAIL_MINUTES))
    latest = rows[0] if rows else None
    stale = latest is None or (_now() - _aware(latest.recorded_at)).total_seconds() > STALE_S
    out = lambda r: schemas.PositionOut.model_validate(r).model_dump(mode="json")
    return {"vehicle_reg_no": v.reg_no, "name": v.name, "stale": stale,
            "latest": out(latest) if latest else None, "trail": [out(r) for r in reversed(rows)]}


@router.get("/vehicles/{vehicle_id}/live/stream")
async def owner_live_stream(vehicle_id: int, user=Depends(_fleet), db: Session = Depends(get_db)):
    """Server-Sent Events feed of new positions. Needs the owner's login token (Authorization header)."""
    v = _own_vehicle(db, user, vehicle_id)
    if not v.live_enabled:
        raise err(403, "live_disabled", "Live tracking is paused for this vehicle")
    vid = v.id
    loop = asyncio.get_running_loop()
    q: asyncio.Queue = asyncio.Queue(maxsize=20)
    sub = (loop, q)
    _subscribers.setdefault(vid, set()).add(sub)

    async def event_generator():
        try:
            while True:
                try:
                    yield f"data: {await asyncio.wait_for(q.get(), timeout=15.0)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            _subscribers.get(vid, set()).discard(sub)

    return StreamingResponse(event_generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---- owner side ------------------------------------------------------------------
@router.post("/vehicles/{vehicle_id}/live-share", response_model=schemas.LiveShareOut, status_code=201)
def create_live_share(vehicle_id: int, b: schemas.LiveShareIn = schemas.LiveShareIn(),
                      user=Depends(_fleet), db: Session = Depends(get_db)):
    v = _own_vehicle(db, user, vehicle_id)
    otp = f"{secrets.randbelow(10**6):06d}"
    s = models.LiveShare(code=secrets.token_urlsafe(18), vehicle_id=v.id, created_by=user.id, label=b.label.strip(),
                         otp_hash="", expires_at=_now() + timedelta(hours=b.hours))
    db.add(s); db.flush()
    s.otp_hash = _h(f"{s.code}:{otp}")             # bound to this share, so an OTP is useless anywhere else
    db.commit()
    return schemas.LiveShareOut(code=s.code, otp=otp, path=f"/live/{s.code}", expires_at=s.expires_at,
                                max_attempts=MAX_ATTEMPTS)


@router.get("/live-shares", response_model=list[schemas.LiveShareSummary])
def list_live_shares(user=Depends(_fleet), db: Session = Depends(get_db)):
    rows = db.scalars(select(models.LiveShare).where(models.LiveShare.created_by == user.id)
                      .order_by(models.LiveShare.id.desc())).all()
    return [schemas.LiveShareSummary(code=r.code, vehicle_id=r.vehicle_id, label=r.label, expires_at=r.expires_at,
                                     revoked=r.revoked, locked=r.locked) for r in rows]


def _own_share(db, user, code) -> models.LiveShare:
    s = db.scalar(select(models.LiveShare).where(models.LiveShare.code == code))
    if not s or s.created_by != user.id:
        raise err(404, "share_not_found", "Live share not found")
    return s


@router.delete("/live-shares/{code}", status_code=204)
def revoke_live_share(code: str, request: Request, user=Depends(_fleet), db: Session = Depends(get_db)):
    s = _own_share(db, user, code)
    s.revoked = True
    _log(db, s, "revoked", request)
    db.commit()


@router.get("/live-shares/{code}/access-log", response_model=list[schemas.AccessLogOut])
def access_log(code: str, user=Depends(_fleet), db: Session = Depends(get_db)):
    s = _own_share(db, user, code)
    return db.scalars(select(models.LiveAccessLog).where(models.LiveAccessLog.share_id == s.id)
                      .order_by(models.LiveAccessLog.id.desc()).limit(200)).all()


# ---- viewer side (authority) -----------------------------------------------------
def _usable(db, code) -> models.LiveShare:
    s = db.scalar(select(models.LiveShare).where(models.LiveShare.code == code))
    if not s:
        raise err(404, "share_not_found", "This live-tracking link does not exist")
    if s.revoked or _aware(s.expires_at) < _now():
        raise err(410, "share_expired", "This live-tracking link has expired or was revoked. Ask the owner for a new one")
    return s


@router.post("/live/{code}/unlock", response_model=schemas.ViewerTokenOut)
def unlock(code: str, b: schemas.UnlockIn, request: Request, db: Session = Depends(get_db)):
    s = _usable(db, code)
    if s.locked:
        raise err(423, "share_locked", "Too many wrong codes. The owner must create a new live share")
    if hmac.compare_digest(s.otp_hash, _h(f"{s.code}:{b.otp}")):
        _log(db, s, "unlock_ok", request); db.commit()
        exp = min(_now() + timedelta(seconds=VIEWER_TOKEN_S), _aware(s.expires_at))
        tok = jwt.encode({"typ": "live", "share": s.code, "veh": s.vehicle_id, "exp": exp},
                         auth.secret_key(), algorithm="HS256")
        return schemas.ViewerTokenOut(viewer_token=tok, expires_in_s=int((exp - _now()).total_seconds()))
    s.failed_attempts += 1
    _log(db, s, "unlock_fail", request)
    if s.failed_attempts >= MAX_ATTEMPTS:
        s.locked = True
        _log(db, s, "locked", request)
    db.commit()
    left = max(MAX_ATTEMPTS - s.failed_attempts, 0)
    if s.locked:
        raise err(423, "share_locked", "Too many wrong codes. The owner must create a new live share")
    raise err(403, "bad_otp", f"Wrong code. {left} attempt{'s' if left != 1 else ''} left")


@router.get("/live/{code}", response_model=schemas.LiveView)
def view(code: str, request: Request, cred: HTTPAuthorizationCredentials | None = Depends(_bearer),
         db: Session = Depends(get_db)):
    """Share-link viewer: needs the Bearer viewer token from /unlock. Shows only positions after the share began."""
    if not cred:
        raise err(401, "viewer_token_required", "Unlock this link with the code from the vehicle owner first")
    try:
        claims = jwt.decode(cred.credentials, auth.secret_key(), algorithms=["HS256"])
    except jwt.PyJWTError:
        raise err(401, "bad_viewer_token", "Your access timed out. Enter the code again")
    if claims.get("typ") != "live" or claims.get("share") != code:
        raise err(403, "wrong_share", "This access code is for a different live link")
    s = _usable(db, code)
    v = db.get(models.Vehicle, s.vehicle_id)
    since = max(_aware(s.created_at), _now() - timedelta(minutes=TRAIL_MINUTES))
    rows = _recent_positions(db, v.id, since)
    latest = rows[0] if rows else None
    stale = latest is None or (_now() - _aware(latest.recorded_at)).total_seconds() > STALE_S
    _log(db, s, "view", request); db.commit()
    return schemas.LiveView(vehicle_reg_no=v.reg_no, label=s.label, share_expires_at=s.expires_at,
                            latest=latest, stale=stale, trail=list(reversed(rows)))
