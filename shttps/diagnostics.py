from __future__ import annotations
import json
from .compression import AICompressAdapter
from .constants import KEM_ML_KEM_1024, SIG_ML_DSA_87, SIG_SLH_DSA_SHAKE_256S

def status() -> dict:
    c=AICompressAdapter(); pq={"provider":"liboqs","available":False,"kem":False,"ml_dsa":False,"slh_dsa":False,"error":None}
    try:
        import oqs  # type: ignore
        k=set(oqs.get_enabled_kem_mechanisms()); s=set(oqs.get_enabled_sig_mechanisms())
        pq.update({"available":True,"kem":KEM_ML_KEM_1024 in k,"ml_dsa":SIG_ML_DSA_87 in s,"slh_dsa":SIG_SLH_DSA_SHAKE_256S in s})
    except Exception as e: pq["error"]=str(e)
    return {"schema":"shttps.diagnostics/v1","pq":pq,"ai_compress":{"available":c.ai_compress_available,"codecs":[int(x) for x in c.available_codecs()],"path":c.path or None},"production_ready":bool(pq["kem"] and pq["ml_dsa"] and c.ai_compress_available)}

def main() -> None: print(json.dumps(status(),ensure_ascii=False,indent=2,sort_keys=True))
if __name__=="__main__": main()
