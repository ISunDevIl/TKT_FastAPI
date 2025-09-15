from datetime import datetime, timezone

# Định dạng dùng cho tên file/thư mục
TIME_FMT_FILE = "%Y-%m-%d_%H%M"

def utc_now() -> datetime:
    """Datetime có timezone UTC (tz-aware)."""
    return datetime.now(timezone.utc)

def utc_now_floor_minute() -> datetime:
    """UTC cắt tới phút (00 giây, 000000 microsecond)."""
    return utc_now().replace(second=0, microsecond=0)

def utc_stamp(fmt: str = TIME_FMT_FILE, *, floor_minute: bool = True) -> str:
    """
    Chuỗi timestamp UTC theo định dạng cho file/thư mục.
    Ví dụ: 2025-09-15_02: '2025-09-15_0130' (tuỳ fmt).
    """
    dt = utc_now_floor_minute() if floor_minute else utc_now()
    return dt.strftime(fmt)

def to_iso_z(dt: datetime | None = None) -> str:
    """
    ISO-8601 dạng Z (UTC). Nếu dt=None dùng thời điểm hiện tại.
    """
    if dt is None:
        dt = utc_now()
    return dt.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
