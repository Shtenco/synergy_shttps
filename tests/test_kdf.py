from shttps.kdf import derive_session_material

def test_kdf_domain_separation():
    m=derive_session_material(b"i"*64,b"t"*64); assert len(set(m.values()))==len(m) and len(m["client_write"])==32 and len(m["session_id"])==16
