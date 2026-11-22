from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class RegisterIn(BaseModel):
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=254)
    password: str = Field(min_length=8, max_length=128)
    name: str = Field(default="", max_length=120)
    role: str = Field(default="fleet_manager", pattern="^(fleet_manager|insurer|authority)$")
    invite_code: str | None = None


class LoginIn(BaseModel):
    email: str
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str
    name: str
    role: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class VehicleIn(BaseModel):
    reg_no: str = Field(min_length=3, max_length=32)
    name: str = Field(default="", max_length=120)


class VehicleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    reg_no: str
    name: str
    live_enabled: bool
    created_at: datetime


class EventSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    vehicle_id: int
    filename: str
    recorded_at: datetime
    uploaded_at: datetime
    verdict: str
    sha256: str
    hash_status: str


class EventOut(EventSummary):
    size_bytes: int
    claimed_sha256: str | None
    reasons: list
    evidence: dict
    detections: list
    classifier_version: str


class VerifyOut(BaseModel):
    event_id: int
    stored_sha256: str
    recomputed_sha256: str
    intact: bool
    upload_hash_status: str


class ShareIn(BaseModel):
    days: int = Field(default=7, ge=1, le=90)


class ShareOut(BaseModel):
    token: str
    path: str
    expires_at: datetime


class SharedReport(BaseModel):
    vehicle_reg_no: str
    event: EventOut
    integrity: VerifyOut
    shared_expires_at: datetime


class EvidenceReport(SharedReport):
    case_summary: str
    viewed_by: str


# ---- live tracking -----------------------------------------------------------
class DeviceKeyOut(BaseModel):
    vehicle_id: int
    device_key: str          # shown once; only its hash is stored


class PositionIn(BaseModel):
    lat: float = Field(ge=-90, le=90)
    lon: float = Field(ge=-180, le=180)
    speed_mps: float | None = Field(default=None, ge=0, le=100)
    heading_deg: float | None = Field(default=None, ge=0, le=360)
    t: datetime | None = None    # device time; server time is used if absent or implausible


class LiveShareIn(BaseModel):
    hours: int = Field(default=2, ge=1, le=72)
    label: str = Field(default="", max_length=160)


class LiveShareOut(BaseModel):
    code: str
    otp: str                 # shown once; give it to the authority over a different channel than the link
    path: str
    expires_at: datetime
    max_attempts: int


class LiveShareSummary(BaseModel):
    code: str
    vehicle_id: int
    label: str
    expires_at: datetime
    revoked: bool
    locked: bool


class UnlockIn(BaseModel):
    otp: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class ViewerTokenOut(BaseModel):
    viewer_token: str
    expires_in_s: int


class PositionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    recorded_at: datetime
    lat: float
    lon: float
    speed_mps: float | None
    heading_deg: float | None


class LiveView(BaseModel):
    vehicle_reg_no: str
    label: str
    share_expires_at: datetime
    latest: PositionOut | None
    stale: bool              # no fix in the last 2 minutes
    trail: list[PositionOut]


class AccessLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    at: datetime
    action: str
    ip: str
