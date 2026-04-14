"""Attack 3: Static analysis - trace the full key derivation and decrypt.

The obfuscated file reads itself, computes hashes, and derives keys.
If we can replicate the key derivation exactly, we can decrypt the stage2 payload.
"""
import hashlib
import base64
import sys
import zlib
import json

# Read the obfuscated file exactly as the stub does
with open("/Users/avner/Developer/pyguard-master/tests/out_v5/02_function_calls_function.py", "rb") as f:
    raw = f.read()

raw = raw.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if raw[:3] == b'\xef\xbb\xbf':
    raw = raw[3:]

# Find markers
marker_start = raw.find(b'#PYG4S')
marker_end = raw.find(b'#PYG4E')
print(f"PYG4S at offset {marker_start}, PYG4E at offset {marker_end}")

# The stub compiles itself and hashes the code objects
# Let's compile it and get the code hash
stub_code = compile(raw, "/Users/avner/Developer/pyguard-master/tests/out_v5/02_function_calls_function.py", 'exec')

def hash_code(code_obj):
    """Hash all code objects recursively."""
    h = hashlib.sha256()
    stack = [code_obj]
    while stack:
        co = stack.pop()
        h.update(co.co_code)
        for c in co.co_consts:
            if type(c).__name__ == 'code':
                stack.append(c)
    return h.digest()

# _VBHrefxks = hash of compiled file's code objects
VBHrefxks = hash_code(stub_code)
print(f"VBHrefxks (compiled code hash): {VBHrefxks.hex()}")

# _OYoPYSIqu = hash of the currently executing frame's code
# When running the stub normally, this is the hash of the frame at depth 0
# which would be the module-level code object
# sys._getframe(0).f_code is the current frame's code
# But we need to know what frame(0) gives during normal execution
# During normal execution of the stub, frame(0) is the module code itself
OYoPYSIqu = hash_code(stub_code)
print(f"OYoPYSIqu (frame code hash): {OYoPYSIqu.hex()}")

# Now compute _HpriOno
midpoint = (marker_start + marker_end) // 2

eHzSCSU = hashlib.sha256()
eHzSCSU.update(raw[marker_start:midpoint])
eHzSCSU.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(OYoPYSIqu + VBHrefxks).digest(),
    hashlib.sha256(VBHrefxks + VBHrefxks).digest())))
eHzSCSU.update(raw[midpoint:marker_end])
HpriOno = eHzSCSU.digest()
print(f"HpriOno (initial): {HpriOno.hex()}")

# No trace/profile active in clean execution
# compile/exec/getattr identity checks pass in clean execution
# builtins class checks pass in clean execution
# Frame depth check - in normal execution of the stub, depth should be <= 12

# Apply the final mix
SCYDOxyOphc = hashlib.sha256(HpriOno + bytes([122])).digest()
HpriOno = bytes(a ^ b for a, b in zip(HpriOno, SCYDOxyOphc))
print(f"HpriOno (after mix): {HpriOno.hex()}")

# Now read the key bytes from the file
# _XpFNWAPD is the first key
XpFNWAPD = bytes([77, 160, 253, 39, 10, 131, 213, 19, 59, 247, 171, 169, 178, 35, 107, 241, 99, 195, 236, 104, 137, 122, 70, 88, 54, 121, 114, 248, 59, 159, 106, 48])

# _rBRGzjO = XOR of XpFNWAPD and HpriOno
rBRGzjO = bytes(a ^ b for a, b in zip(XpFNWAPD, HpriOno))
print(f"rBRGzjO: {rBRGzjO.hex()}")

# Now we need _zxUeQDmRs which computes an additional hash involving frame code
# _zxUeQDmRs(_jhgwfOVtIW):
#   NwhFIzl = XOR(sha256(VBHrefxks + hash_of_frame1_code), sha256(VBHrefxks + VBHrefxks))
#   return sha256(_jhgwfOVtIW + NwhFIzl)

# The problem: _AgSxuXHGa(1).f_code = sys._getframe(1).f_code
# In normal execution from CLI, frame(1) would be... nothing? Or the import machinery?
# Actually when running "python3 script.py", frame(0) is the module code
# frame(1) doesn't exist at module level...
# But _zxUeQDmRs is called within the stub, so frame(1) = the module code

# Let's check: when _zxUeQDmRs is called,
# frame(0) = _zxUeQDmRs itself
# frame(1) = the caller = module-level code of the stub
# So _AgSxuXHGa(1).f_code = stub's module code object

frame1_code_hash = hash_code(stub_code)
print(f"frame1 code hash: {frame1_code_hash.hex()}")

NwhFIzl = bytes(a ^ b for a, b in zip(
    hashlib.sha256(VBHrefxks + frame1_code_hash).digest(),
    hashlib.sha256(VBHrefxks + VBHrefxks).digest()))

# _SnzfqxNa = _XffgJRddN(_zxUeQDmRs(_rBRGzjO))
# _zxUeQDmRs returns sha256(rBRGzjO + NwhFIzl)
zxUeQDmRs_result = hashlib.sha256(rBRGzjO + NwhFIzl).digest()
print(f"zxUeQDmRs result: {zxUeQDmRs_result.hex()}")

# Now apply _XffgJRddN which is the SPN key schedule
msPQcTP = bytes([183, 71, 171, 0, 75, 71, 97, 112, 53, 246, 24, 40, 88, 24, 73, 82, 26, 148, 152, 109, 12, 56, 122, 222, 128, 186, 242, 15, 70, 23, 242, 150])
DmIPmAX = hashlib.sha256(bytes([233, 59, 12, 200, 224, 167, 175, 24, 39, 65, 128, 127, 54, 157, 90, 49, 164, 7, 129, 174, 192, 115, 125, 120, 1, 144, 160, 135, 85, 239, 231, 139])).digest()
vhpqSXF = hashlib.sha256(DmIPmAX + bytes([107, 221, 12, 88, 219, 38, 224, 137, 203, 36, 130, 8, 147, 10, 98, 135])).digest()
UHQxFFILi = hashlib.sha256(vhpqSXF + DmIPmAX).digest()
azejEuVw = hashlib.sha256(msPQcTP).digest()
vtjigFbH = hashlib.sha256(azejEuVw + msPQcTP).digest()
wnUrIzbDhN = hashlib.sha256(vtjigFbH + azejEuVw).digest()
uGVyYGMTjUk = wnUrIzbDhN

def XffgJRddN(pGVWKakKoTK):
    pGVWKakKoTK = bytes(a ^ b for a, b in zip(pGVWKakKoTK, uGVyYGMTjUk))
    LisLiVdF = []
    kRwxmqhByRR = pGVWKakKoTK
    for _ in range(6):
        kRwxmqhByRR = hashlib.sha256(kRwxmqhByRR + bytes([213, 47, 157, 234])).digest()
        LisLiVdF.append(kRwxmqhByRR)
    cRNHxVp = [(b % 7) + 1 for b in hashlib.sha256(pGVWKakKoTK + bytes([243, 110, 30, 136])).digest()[:6]]
    HVLGUok = hashlib.sha256(pGVWKakKoTK + bytes([161, 206, 34, 176])).digest()
    MMPZsAuM = list(range(256))
    BPtPKZwUdd = 0
    for i in range(256):
        BPtPKZwUdd = (BPtPKZwUdd + MMPZsAuM[i] + HVLGUok[i % 32] + 75) % 256
        MMPZsAuM[i], MMPZsAuM[BPtPKZwUdd] = MMPZsAuM[BPtPKZwUdd], MMPZsAuM[i]
    DfvJtqFi = [0] * 256
    for i in range(256):
        DfvJtqFi[MMPZsAuM[i]] = i
    return LisLiVdF, cRNHxVp, DfvJtqFi

SnzfqxNa = XffgJRddN(zxUeQDmRs_result)
print(f"SPN key schedule computed: {len(SnzfqxNa[0])} round keys, rotations: {SnzfqxNa[1]}")

# Now we need the SPN decryption function
def izmiyvUZB(xoYivvu, SfdPCFSnO, hlkiLJMJa, OZVKXPe):
    """SPN cipher decryption - replicated from the stub."""
    aHETPel = bytearray(len(xoYivvu))
    QlgzfyzzyRx = 6  # number of rounds
    SvsIVdPx = 0
    ZGzkdGoYio = 0
    rwNrAuSW = 0
    anRIlpf = 0
    nfqZoBhXEZz = 0
    gYukFrF = 0
    lfMfHOqp = 0
    qGlkvNfMOwP = 0
    kpXITfJy = 0xFF
    mexVdqvNv = 238
    while True:
        if mexVdqvNv == 250:
            break
        if mexVdqvNv == 238:
            if SvsIVdPx >= len(xoYivvu):
                mexVdqvNv = 250
            else:
                mexVdqvNv = 150
            continue
        if mexVdqvNv == 150:
            anRIlpf = xoYivvu[SvsIVdPx]
            gYukFrF = anRIlpf
            mexVdqvNv = 134
            continue
        if mexVdqvNv == 134:
            ZGzkdGoYio = QlgzfyzzyRx - 1
            nfqZoBhXEZz = (nfqZoBhXEZz + anRIlpf) & 0xFF
            mexVdqvNv = 193
            continue
        if mexVdqvNv == 193:
            if ZGzkdGoYio < 0:
                mexVdqvNv = 17
            else:
                mexVdqvNv = 32
            continue
        if mexVdqvNv == 32:
            LtGOXdPOHyt = hlkiLJMJa[ZGzkdGoYio]
            anRIlpf = ((anRIlpf >> LtGOXdPOHyt) | (anRIlpf << (8 - LtGOXdPOHyt))) & 0xFF
            mexVdqvNv = 51
            continue
        if mexVdqvNv == 51:
            anRIlpf = OZVKXPe[anRIlpf]
            lfMfHOqp = (lfMfHOqp ^ anRIlpf) & 0xFF
            mexVdqvNv = 219
            continue
        if mexVdqvNv == 219:
            anRIlpf ^= SfdPCFSnO[ZGzkdGoYio][SvsIVdPx % 32]
            ZGzkdGoYio -= 1
            mexVdqvNv = 193
            continue
        if mexVdqvNv == 17:
            anRIlpf ^= rwNrAuSW
            aHETPel[SvsIVdPx] = anRIlpf
            mexVdqvNv = 0
            continue
        if mexVdqvNv == 0:
            rwNrAuSW = xoYivvu[SvsIVdPx]
            SvsIVdPx += 1
            qGlkvNfMOwP = (qGlkvNfMOwP + 1) & kpXITfJy
            mexVdqvNv = 238
            continue
        if mexVdqvNv == 79:
            gYukFrF = (gYukFrF * 31 + nfqZoBhXEZz) & 0xFF
            mexVdqvNv = 252
            continue
        if mexVdqvNv == 252:
            lfMfHOqp = (lfMfHOqp + gYukFrF) & 0xFF
            if qGlkvNfMOwP > 0:
                mexVdqvNv = 88
            else:
                mexVdqvNv = 238
            continue
        if mexVdqvNv == 88:
            nfqZoBhXEZz ^= OZVKXPe[lfMfHOqp]
            qGlkvNfMOwP = (qGlkvNfMOwP - 1) & kpXITfJy
            mexVdqvNv = 199
            continue
        if mexVdqvNv == 199:
            gYukFrF = (gYukFrF ^ SfdPCFSnO[0][qGlkvNfMOwP % 32]) & 0xFF
            mexVdqvNv = 153
            continue
        if mexVdqvNv == 153:
            LtGOXdPOHyt = hlkiLJMJa[qGlkvNfMOwP % QlgzfyzzyRx]
            anRIlpf = ((nfqZoBhXEZz >> LtGOXdPOHyt) | (nfqZoBhXEZz << (8 - LtGOXdPOHyt))) & 0xFF
            mexVdqvNv = 90
            continue
        if mexVdqvNv == 90:
            lfMfHOqp = (lfMfHOqp ^ anRIlpf ^ rwNrAuSW) & 0xFF
            mexVdqvNv = 53
            continue
        if mexVdqvNv == 53:
            nfqZoBhXEZz = (nfqZoBhXEZz + lfMfHOqp) & 0xFF
            mexVdqvNv = 238
            continue
    return bytes(aHETPel)

# Now let's find the encrypted stage2 payload
# It's a base64 encoded string that gets decoded, SPN-decrypted, then decompressed
# The base64 strings are the _QFQGabTAsic, _gtPCFqlpQk, etc.

# Let's read the rest of the file to find where stage2 payload is assembled
print("\nNow need to find where the encrypted blob is assembled and decrypted...")
print("Looking for the decryption call and zlib decompress...")
