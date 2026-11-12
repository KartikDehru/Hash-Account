import os
import subprocess
import sys

CLI = os.path.join(os.path.dirname(__file__), "..", "xmss", "cli.py")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "xmss"))
import xmss_ref as x  # noqa: E402


def test_keygen_sign_verify(tmp_path):
    key = tmp_path / "k.json"
    subprocess.run([sys.executable, CLI, "keygen", "4", str(key)], check=True, capture_output=True)
    import json
    k = json.load(open(key))
    digest = bytes(range(32))
    out = subprocess.run([sys.executable, CLI, "sign", str(key), "5", digest.hex()], check=True, capture_output=True, text=True).stdout
    sig = bytes.fromhex(out[2:])
    assert len(sig) == 4 + 32 * (68 + 4)
    assert int.from_bytes(sig[:4], "big") == 5
    words = [sig[4 + 32 * i: 36 + 32 * i] for i in range(68 + 4)]
    r, ots, auth = words[0], words[1:68], words[68:]
    root, seed = bytes.fromhex(k["root"][2:]), bytes.fromhex(k["seed"][2:])
    assert x.verify(digest, 5, r, ots, auth, root, seed)
    assert not x.verify(bytes(32), 5, r, ots, auth, root, seed)
