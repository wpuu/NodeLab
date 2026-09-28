"""Internal monotonic deadline helpers. No user data in exceptions."""
from __future__ import annotations

import math
import time


class DeadlineExpired(TimeoutError):
    def __init__(self) -> None:
        super().__init__("DEADLINE_EXPIRED")


def after(seconds: float) -> float:
    if type(seconds) not in (int, float):
        raise ValueError("INVALID_DEADLINE")
    try:
        seconds = float(seconds)
    except OverflowError:
        raise ValueError("INVALID_DEADLINE") from None
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("INVALID_DEADLINE")
    end = time.monotonic() + seconds
    if not math.isfinite(end):
        raise ValueError("INVALID_DEADLINE")
    return end


def remaining(cap: float, deadline: float | None) -> float:
    if deadline is None:
        return cap
    left = deadline - time.monotonic()
    if not math.isfinite(left) or left <= 0:
        raise DeadlineExpired()
    return min(cap, left)
