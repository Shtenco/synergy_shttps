from __future__ import annotations
from .errors import ReplayError

class ReplayWindow:
    def __init__(self, size: int = 2048) -> None:
        if size <= 0: raise ValueError("size must be positive")
        self.size = size; self.highest = -1; self.bitmap = 0

    def check_and_mark(self, seq: int) -> None:
        if seq < 0: raise ReplayError("negative sequence")
        if self.highest < 0:
            self.highest = seq; self.bitmap = 1; return
        if seq > self.highest:
            shift = seq - self.highest
            self.bitmap = 1 if shift >= self.size else ((self.bitmap << shift) | 1) & ((1 << self.size) - 1)
            self.highest = seq; return
        delta = self.highest - seq
        if delta >= self.size: raise ReplayError("sequence outside replay window")
        mask = 1 << delta
        if self.bitmap & mask: raise ReplayError("replayed frame")
        self.bitmap |= mask
