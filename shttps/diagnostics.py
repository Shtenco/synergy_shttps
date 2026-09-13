from __future__ import annotations
import json, os
from .compression import AICompressAdapter
from .constants import KEM_ML_KEM_1024, SIG_ML_DSA_87, SIG_SLH_DSA_SHAKE_256S

EXPECTED_LIBOQS_VERSION="0.16.0"
EXPECTED_LIBOQS_PYTHON_VERSION="0.16.0"


def status() -> dict:
    c=AICompressAdapter()
    pq={
        "provider":"liboqs",
        "available":False,
        "liboqs_version":None,
        "liboqs_python_version":None,
        "version_match":False,
        "kem":False,
        "ml_dsa":False,
        "slh_dsa":False,
        "error":None,
    }
    try:
        import oqs  # type: ignore
        k=set(oqs.get_enabled_kem_mechanisms()); s=set(oqs.get_enabled_sig_mechanisms())
        oqs_v=str(oqs.oqs_version()); pyoqs_v=str(oqs.oqs_python_version())
        pq.update({
            "available":True,
            "liboqs_version":oqs_v,
            "liboqs_python_version":pyoqs_v,
            "version_match":oqs_v==EXPECTED_LIBOQS_VERSION and pyoqs_v==EXPECTED_LIBOQS_PYTHON_VERSION,
            "kem":KEM_ML_KEM_1024 in k,
            "ml_dsa":SIG_ML_DSA_87 in s,
            "slh_dsa":SIG_SLH_DSA_SHAKE_256S in s,
        })
    except Exception as e:
        pq["error"]=str(e)
    hybrid_required=os.getenv("SHTTPS_REQUIRE_HYBRID","1").strip().lower() not in {"0","false","no","off"}
    production_candidate=bool(pq["version_match"] and pq["kem"] and pq["ml_dsa"] and pq["slh_dsa"] and c.ai_compress_available and hybrid_required)
    return {
        "schema":"shttps.diagnostics/v2",
        "pq":pq,
        "hybrid_x25519_required":hybrid_required,
        "ai_compress":{"available":c.ai_compress_available,"codecs":[int(x) for x in c.available_codecs()],"path":c.path or None},
        "production_candidate":production_candidate,
        "production_ready":False,
        "production_ready_reason":"Requires deployment-specific cryptographic review/audit; liboqs is used as a pinned prototype provider boundary.",
    }


def assert_production_candidate() -> dict:
    value=status()
    if not value["production_candidate"]:
        raise RuntimeError(json.dumps(value,ensure_ascii=False,sort_keys=True))
    return value


def main() -> None:
    value=status()
    print(json.dumps(value,ensure_ascii=False,indent=2,sort_keys=True))
    raise SystemExit(0 if value["production_candidate"] else 2)


if __name__=="__main__": main()
