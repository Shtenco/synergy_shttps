from __future__ import annotations
from dataclasses import dataclass
import importlib, os, sys
from .constants import CompressionId
from .errors import CompressionError

@dataclass(frozen=True)
class CompressionDecision:
    codec: CompressionId
    data: bytes
    original_size: int

class AICompressAdapter:
    """Network adapter for Shtenco/ai_compress Gabriel Horn (SGH1).

    The dependency stays owned by ai_compress; SHTTPS does not fork its codec math.
    Set SHTTPS_AI_COMPRESS_PATH to the ai_compress repository root when it is not
    already importable. RAW is always supported as a lossless no-compression mode.
    """
    def __init__(self, path: str | None = None) -> None:
        self.path = path or os.getenv("SHTTPS_AI_COMPRESS_PATH", "")
        self._engine_cls = None
        self._load_error: Exception | None = None
        self._load()

    def _load(self) -> None:
        if self.path and self.path not in sys.path: sys.path.insert(0, self.path)
        try:
            mod = importlib.import_module("compression_lab.gabriel_horn_engine")
            self._engine_cls = mod.GabrielHornEngine
        except Exception as e:
            self._load_error = e

    @property
    def ai_compress_available(self) -> bool:
        return self._engine_cls is not None

    def available_codecs(self) -> list[CompressionId]:
        out = [CompressionId.RAW]
        if self.ai_compress_available:
            out += [CompressionId.AI_COMPRESS_SGH1_SPEED, CompressionId.AI_COMPRESS_SGH1_BALANCED, CompressionId.AI_COMPRESS_SGH1_MAX]
        return out

    def _engine(self, codec: CompressionId):
        if self._engine_cls is None: raise CompressionError(f"ai_compress unavailable: {self._load_error}")
        profile = {
            CompressionId.AI_COMPRESS_SGH1_SPEED: "speed",
            CompressionId.AI_COMPRESS_SGH1_BALANCED: "balanced",
            CompressionId.AI_COMPRESS_SGH1_MAX: "max",
        }.get(codec)
        if not profile: raise CompressionError("not an ai_compress codec")
        return self._engine_cls(profile=profile)

    def compress(self, source: bytes, preferred: CompressionId, *, sensitive: bool = False, min_gain_bytes: int = 32, min_gain_ratio: float = 0.01) -> CompressionDecision:
        source = bytes(source)
        if sensitive or preferred == CompressionId.RAW or not source:
            return CompressionDecision(CompressionId.RAW, source, len(source))
        archive = self._engine(preferred).compress(source)
        gain = len(source) - len(archive)
        if gain < min_gain_bytes or (gain / max(1, len(source))) < min_gain_ratio:
            return CompressionDecision(CompressionId.RAW, source, len(source))
        return CompressionDecision(preferred, archive, len(source))

    def decompress(self, codec: CompressionId, data: bytes, expected_size: int) -> bytes:
        if codec == CompressionId.RAW:
            out = bytes(data)
        else:
            engine = self._engine(codec)
            try:
                info = engine.inspect(bytes(data))
            except Exception as e:
                raise CompressionError("invalid ai_compress archive") from e
            if int(info.original_size) != int(expected_size):
                raise CompressionError("archive original size does not match authenticated frame")
            try:
                out = engine.decompress(bytes(data))
            except Exception as e:
                raise CompressionError("ai_compress decompression failed") from e
        if len(out) != expected_size: raise CompressionError("decompressed size mismatch")
        return out
