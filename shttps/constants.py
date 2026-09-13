from enum import IntEnum, IntFlag

PROTOCOL_NAME = "SHTTPS"
PROTOCOL_VERSION = 1
MAGIC = b"SHT1"
MAX_HANDSHAKE_BYTES = 256 * 1024
MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024
MAX_FRAME_BYTES = MAX_PLAINTEXT_BYTES + 2 * 1024 * 1024
REPLAY_WINDOW = 2048
REKEY_AFTER_MESSAGES = 1_000_000
REKEY_AFTER_SECONDS = 3600

KEM_ML_KEM_1024 = "ML-KEM-1024"
SIG_ML_DSA_87 = "ML-DSA-87"
SIG_SLH_DSA_SHAKE_256S = "SLH-DSA-SHAKE-256s"
CLASSICAL_X25519 = "X25519"
KDF_HKDF_SHA3_512 = "HKDF-SHA3-512"

class CipherId(IntEnum):
    CHACHA20_POLY1305 = 1
    AES_256_GCM = 2

class CompressionId(IntEnum):
    RAW = 0
    AI_COMPRESS_SGH1_SPEED = 0x101
    AI_COMPRESS_SGH1_BALANCED = 0x102
    AI_COMPRESS_SGH1_MAX = 0x103

class FrameType(IntEnum):
    DATA = 1
    CONTROL = 2
    PING = 3
    CLOSE = 4
    REKEY = 5

class FrameFlags(IntFlag):
    NONE = 0
    COMPRESSED = 1 << 0
    SENSITIVE = 1 << 1
    PADDED = 1 << 2

DEFAULT_PROTOCOLS = (
    "synergy.capability.v1",
    "nexus.runtime/v3",
    "nexus.memory/v1",
    "synergy.event/v1",
    "synergy.evidence/v1",
)
