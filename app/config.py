from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    db_path: str
    max_decode_bytes: int


def get_settings() -> Settings:
    return Settings(
        db_path=os.environ.get("RESYNC_DB_PATH", "/data/resync.db"),
        max_decode_bytes=int(os.environ.get("RESYNC_MAX_DECODE_BYTES", str(1 << 20))),
    )
