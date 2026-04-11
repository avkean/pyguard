#!/usr/bin/env python3
# Protected by PyGuard v4 (pyguard.akean.dev)
_llIOIO1l0 = bytes([6, 202, 93, 197, 162, 80, 144, 254, 38, 136, 250, 46, 189, 74, 160, 192, 211, 16, 222, 58, 152, 137, 255, 172, 156, 82, 242, 11, 215, 160, 169, 143])
_IIllIII0 = bytes([16, 120, 135, 181, 207, 229, 170, 98, 13, 27, 200, 36, 81, 147, 117, 157, 83, 42, 104, 197, 39, 135, 101, 108, 253, 31, 2, 90, 143, 16, 150, 165])
_IIl0lOO = bytes([185, 46, 130, 151, 1, 3, 189, 0, 87, 247, 141, 132, 165, 253, 139, 13, 131, 222, 214, 216, 255, 70, 68, 171, 159, 126, 45, 195, 238, 48, 199, 167])
_IOl11I1I1O = bytes([103, 205, 87, 185, 50, 62, 96, 231, 31, 151, 242, 44, 216, 67, 199, 184, 82, 157, 220, 102, 40, 218, 184, 149, 26, 206, 139, 29, 41, 40, 143, 161])
_Oll00l0I = bytes([108, 73, 202, 230, 40, 195, 219, 39, 180, 219, 103, 175, 183, 37, 120, 250, 112, 235, 84, 76, 9, 41, 172, 238, 30, 101, 75, 44, 33, 249, 163, 75])
_O11ll1Ol0 = bytes([28, 117, 218, 66, 251, 59, 65, 77, 186, 162, 167, 138, 252, 82, 97, 98, 150, 229, 255, 197, 23, 238, 249, 168, 83, 221, 226, 221, 84, 216, 197, 183])
#PYG4S
import sys, hashlib, base64
_Ol1IlI0O = type(lambda: 0)
_III00O0 = (compile, exec, getattr, __import__, open, type)
_I1Ol0Il = _III00O0[2](sys, '_getf' + 'rame')
_IIllOOlllII = bytes([65, 227, 59, 174, 180, 211, 255, 119, 232, 48, 177, 139, 178, 110, 117, 223, 10, 111, 11, 182, 165, 251, 171, 0, 224, 103, 44, 125, 92, 57, 171, 73])
_OlI1011llIl = hashlib.sha256(bytes([128, 251, 114, 244, 228, 124, 241, 65, 165, 37, 2, 33, 152, 112, 240, 115, 224, 156, 197, 21, 193, 234, 10, 140, 118, 168, 99, 84, 63, 139, 54, 202])).digest()
_O0O1l11011I = hashlib.sha256(_IIllOOlllII).digest()
_Il00lIl10 = hashlib.sha256(_O0O1l11011I + _IIllOOlllII).digest()
_OlII111OIl1 = hashlib.sha256(_OlI1011llIl + bytes([137, 96, 241, 138, 58, 5, 197, 87, 218, 239, 15, 113, 157, 145, 130, 247])).digest()
_O0l1IOI1ll0 = hashlib.sha256(_Il00lIl10 + _O0O1l11011I).digest()
_IO110l1 = _O0l1IOI1ll0
_IO1llOI1Ol = hashlib.sha256(_OlII111OIl1 + _OlI1011llIl).digest()
def _I0I0O1OIII(_OlIOIl11):
    _OlIOIl11 = bytes(a ^ b for a, b in zip(_OlIOIl11, _IO110l1))
    _O1l0IOl = []
    _IOI1IOIO = _OlIOIl11
    for _ in range(7):
        _IOI1IOIO = hashlib.sha256(_IOI1IOIO + bytes([44, 120, 181, 103])).digest()
        _O1l0IOl.append(_IOI1IOIO)
    _I1IO0I1O0 = [(b % 5) + 1 for b in hashlib.sha256(_OlIOIl11 + bytes([214, 170, 71, 181])).digest()[:7]]
    _O1O0III = hashlib.sha256(_OlIOIl11 + bytes([181, 3, 129, 40])).digest()
    _ll0I1I0O1II = list(range(256))
    _II1OlOO1l = 0
    for _OI00O01OO in range(256):
        _II1OlOO1l = (_II1OlOO1l + _ll0I1I0O1II[_OI00O01OO] + _O1O0III[_OI00O01OO % 32] + 50) % 256
        _ll0I1I0O1II[_OI00O01OO], _ll0I1I0O1II[_II1OlOO1l] = _ll0I1I0O1II[_II1OlOO1l], _ll0I1I0O1II[_OI00O01OO]
    _IOlOll01I0 = [0] * 256
    for _OI00O01OO in range(256):
        _IOlOll01I0[_ll0I1I0O1II[_OI00O01OO]] = _OI00O01OO
    return _O1l0IOl, _I1IO0I1O0, _IOlOll01I0
def _IO10O11I1l(_OIO1IlIlOl0, _OO0010101, _OlII0OIOOI, _ll0ll00):
    _O01Oll010O = bytearray(len(_OIO1IlIlOl0))
    _OI0OIl0IIO = 7
    _O11lI10O1 = 0
    _I1Il1lO1lOl = 0
    _l110l1Illl0 = 0
    _IOOOI0O = 0
    _O0O1l0lOI = 46
    while True:
        if _O0O1l0lOI == 102:
            break
        if _O0O1l0lOI == 46:
            if _O11lI10O1 >= len(_OIO1IlIlOl0):
                _O0O1l0lOI = 102
                continue
            _IOOOI0O = _OIO1IlIlOl0[_O11lI10O1]
            _I1Il1lO1lOl = _OI0OIl0IIO - 1
            _O0O1l0lOI = 146
            continue
        if _O0O1l0lOI == 146:
            if _I1Il1lO1lOl < 0:
                _O0O1l0lOI = 253
                continue
            _OIl10ll0 = _OlII0OIOOI[_I1Il1lO1lOl]
            _IOOOI0O = ((_IOOOI0O >> _OIl10ll0) | (_IOOOI0O << (8 - _OIl10ll0))) & 0xFF
            _IOOOI0O = _ll0ll00[_IOOOI0O]
            _IOOOI0O ^= _OO0010101[_I1Il1lO1lOl][_O11lI10O1 % 32]
            _I1Il1lO1lOl -= 1
            continue
        if _O0O1l0lOI == 253:
            _IOOOI0O ^= _l110l1Illl0
            _O01Oll010O[_O11lI10O1] = _IOOOI0O
            _l110l1Illl0 = _OIO1IlIlOl0[_O11lI10O1]
            _O11lI10O1 += 1
            _O0O1l0lOI = 46
            continue
    return bytes(_O01Oll010O)
def _II0l0I0lI(_l00IOOIll10):
    _I0I11IlI1 = hashlib.sha256()
    _O1IllIlIII1 = [_l00IOOIll10]
    while _O1IllIlIII1:
        _Il0lIOO01O = _O1IllIlIII1.pop()
        _I0I11IlI1.update(_Il0lIOO01O.co_code)
        for _O10O0I1 in _Il0lIOO01O.co_consts:
            if type(_O10O0I1).__name__ == 'code':
                _O1IllIlIII1.append(_O10O0I1)
    return _I0I11IlI1.digest()
def _OIOO1Ol0(_O10OI0IIOl0):
    try:
        _llll00Ill0 = bytes(a ^ b for a, b in zip(
            hashlib.sha256(_IOlOlIl + _II0l0I0lI(_I1Ol0Il(1).f_code)).digest(),
            hashlib.sha256(_IOlOlIl + _IOlOlIl).digest()))
        return hashlib.sha256(_O10OI0IIOl0 + _llll00Ill0).digest()
    except Exception:
        return hashlib.sha256(_O10OI0IIOl0 + bytes(32 * [255])).digest()
try:
    _O1lll1l1O0 = __file__
except NameError:
    _O1lll1l1O0 = sys.argv[0] if sys.argv else ''
try:
    with _III00O0[4](_O1lll1l1O0, 'rb') as _I0OI0Ol01:
        _l0lIIlO001 = _I0OI0Ol01.read()
except Exception:
    sys.exit(0)
_l0lIIlO001 = _l0lIIlO001.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if _l0lIIlO001[:3] == b'\xef\xbb\xbf':
    _l0lIIlO001 = _l0lIIlO001[3:]
_lll1I11 = _l0lIIlO001.find(bytes([35, 80, 89, 71, 52, 83]))
_IO0OIOl1O00 = _l0lIIlO001.find(bytes([35, 80, 89, 71, 52, 69]))
if _lll1I11 < 0 or _IO0OIOl1O00 < 0:
    sys.exit(0)
_IllOIOI1l1 = (_lll1I11 + _IO0OIOl1O00) // 2
try:
    _Ol0OOl10l = _III00O0[0](_l0lIIlO001, _O1lll1l1O0, 'exec')
    _OO10II0l11l = _II0l0I0lI(_I1Ol0Il(0).f_code)
    _IOlOlIl = _II0l0I0lI(_Ol0OOl10l)
except Exception:
    _OO10II0l11l = bytes(32)
    _IOlOlIl = bytes(32 * [255])
_llllIIlII1I = hashlib.sha256()
_llllIIlII1I.update(_l0lIIlO001[_lll1I11:_IllOIOI1l1])
_llllIIlII1I.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(_OO10II0l11l + _IOlOlIl).digest(),
    hashlib.sha256(_IOlOlIl + _IOlOlIl).digest())))
_llllIIlII1I.update(_l0lIIlO001[_IllOIOI1l1:_IO0OIOl1O00])
_IIOI1llIl0 = _llllIIlII1I.digest()
if _III00O0[2](sys, 'gettrace')() is not None or _III00O0[2](sys, 'getprofile')() is not None:
    _IIOI1llIl0 = bytes((b ^ 200) for b in _IIOI1llIl0)
if compile is not _III00O0[0] or exec is not _III00O0[1] or getattr is not _III00O0[2]:
    _IIOI1llIl0 = bytes((b ^ 60) for b in _IIOI1llIl0)
_OI1011lI = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != _OI1011lI or exec.__class__.__name__ != _OI1011lI or
        getattr.__class__.__name__ != _OI1011lI or __import__.__class__.__name__ != _OI1011lI or
        open.__class__.__name__ != _OI1011lI or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        _IIOI1llIl0 = bytes((b ^ 40) for b in _IIOI1llIl0)
except Exception:
    _IIOI1llIl0 = bytes((b ^ 40) for b in _IIOI1llIl0)
_OO10O10O1 = sum(b for b in _IIOI1llIl0) & 0xFF
_lIOll1O1 = _OO10O10O1
_IIOI1llIl0 = bytes((b ^ _OO10O10O1 ^ _lIOll1O1) for b in _IIOI1llIl0)
_lO1l0l0 = hashlib.sha256(_IIOI1llIl0).digest()
_Ill111O0 = hashlib.sha256(_IIOI1llIl0).digest()
_IIOI1llIl0 = bytes((a ^ b ^ c) for a, b, c in zip(_IIOI1llIl0, _lO1l0l0, _Ill111O0))
_OlIlIIII1 = bytes(a ^ b for a, b in zip(_Oll00l0I, _IIOI1llIl0))
_lO10I11lOIl = _I0I0O1OIII(_OIOO1Ol0(_OlIlIIII1))
_lIOOI1I = "p7NxJuqsJF3an4jaHSQe44ob4EMjkw10ipOsHS/8zsK+jvxe+QepjYUXCh8Ki"
_l1lO0lO111 = "9cnpu3MBAuCJhLHyMBJOotvCNJljElGYkJEs7vFI"
_l01OO11 = "iHJrenNzH/l6IAWEEDJloYz4HmGQwhazzXf+tehmKVs9NI"
_I00111IIlI = "9VQpTJH3pWn12Br9IgYzksSmgGPvn0ucyawsVuzL7pMIfINEdnN7GTXWyj9l8n"
_l11O1OI0OO = "E0xNiBHUUKurEijXq+RqKlPAzhepTBUb"
_l0lIl0lI0I = "egvh4FhdoCMK+nqCxrsJeW9v0CbWJ79P+qmOERgyq"
_I011Ol0l = "SMFL1oHQvmi8JRP9kBvocdS09KxNQxPA4Ua+ol94HgxL6I"
_Il01IOOOOI = "brrFCVqu67idxbIwYdF6+W96YskQHHSMN1"
_IIOII11II = "FYljsFz9mzqzqQ6GkUFl8NT/"
_l1lIlll1 = "aPOoHFklleW5SgY6dAHpKF3kq"
_lIOI001l = "8e5Q0Gec1Fgo1C7kuY7JEn8tdZO"
_I1lIll1IO = "P+8kjTi8eRX3XO6/4jheiNzZSNEX6iP"
_l10IIOI01l = "mrxcOGSPW08KddlxyP+mJhHe"
_O011O0I10Il = "1Ee8gbvyyG1SdZ/GohyNXzdB0Bw1O2sSTMr0cFvNy7pfo"
_O1l1IOlI = "WgD/BG/WzcAW9POwtdT/JsA63N3CmiWHV"
_O10OOO1 = "MNKL8a/wWChzVJRAfdwB10OkG4pnQ3f2yrwruDfd"
_OOIIl0IO = "1XhZPrKNEWqSMAwOufdr4D6lkw/9"
_lO000II = "qnKuV/fL+ODg47LJkq/Ape4pee2/"
_IO0ll0III1l = "ymjc7uQ+r4XXLb1FHRvLpFtb9M7NHwva6sGdHOtIOSnXYyhS3X3QgwDD"
_O00llII01lO = "O0/cW7c1nSPAkC68i2dB8pAGElIjd7VHvO+0WVtj+qb0rqcQxbru+TgHsrSpH"
_l00l0IIO0I1 = "yvIXrwW8Q1MqtEw1HxTRzNVvFCr2cVmkeDK"
_IOI0l10O0l = "IzDsV55XqOHn8hOkTzZbqVIMyRk"
_IIlOI11Il = "+gMeTuOPESiLhO+Ey8PPvUI9FWSpQMyqqcEoTz2k3jMbPRW"
_lO1OIIOII0O = "KMQSIrUPhJxKbvrlCnFTC9+nVQ9fkehOs"
_I01l00I = "9pziSsDvQs2ZAfh9UBFw57MjHkeK6AuQs4tBMo"
_O01l01l = "vjwK/Bey6qWtLj8hFqAWmXs9SySMM"
_Il1011I0Il = "XEbisxRvJK5J/Etn3GlJcC7n/VMUYByC2ufZNz6xczGEHdm+tDsHlCHT/W"
_IO0Il001I = "rKU2E0S6PPmaurq4OzFY6YANjM8NkHNNT"
_lOl00Ol100 = "pBEu05EvGu6k8OkGVY/rmW88s="
_l00lOll1I = "6H97/H2+AdlJGZxqTbwY1l/ZSxr"
_O0lI0IlO = "i+GsUzMAiXNjN9A3h4WXQCM7xnQ1"
_lIlO00O010l = "eizlJggda1DdKcvPNz++j5XLxxm815BkeLM1mNFOU35+h/gur6mEw+i9"
_lI1I0OIOO = "XY/BCVdEwQZKhimd1q2egaIHoTzxu80mxvw"
_IIl1l0Il = "x5uPyXQoC5uRH7cAf36xLgJ8/7j9"
_OIll0011 = "qvFaWoey4dy3IrkgyEIMGtuxTVRRSNtlWCiOa8KAQ"
_llI10lO1OO = "BEry1rnXgD/MEB6cZJ7JFqpnqshwM6H/M/LxVBMp4Ps8cICeAyK3sr0LvEKXA/Y"
_Ol11lllIIOO = "+8fgNWxTv12qh+7DMow+G2RvorRNThHkVuHNZik6l"
_OOO10l0l = "X378CAOJmG78KE4D6DlIiBtDjw0b2UzNxCatB9f9"
_lIOll0I1OO = "9duKqCK+rQWV9/koXO8Nu8i2f3wTNmE6THDoXZoKr0zBp"
_O01l1l1O0IO = "2YpSTiF3F4NQU3dYRGbZrZXq8LQZamsAwrElqFwH6YOmvw4eHgMIf"
_O1I00lOO11O = "+nHUwfg2h1z9sCALXBCzinSGoRC6m"
_OI0lIllO0 = "FKQr9fotA+dab1RtXHRRSeaMAjBrAjBQjCUfS1rGtKf4Q3qZVqOj"
_lOl1OOI = "fm9WnlvEomwS6/cNidzVUZd26LgAIGdGeRYwlFIyKTMGUPkvE"
_O1I0010IlI = "L8wSHEcc1MdrTf5vH1/XMMH+keba2enjJT2V2eHq0AmyNDJ5LAVk"
_l01OlIlOIO = "ln5UmwcE93/64LXbLpifOr3lBaNEkggnH8P0B3CBMN"
_OO1Oll1lI = "P0/BnLH+tEQsTTe9GU84lLMRiYy2k9R3JbuD/mUSl"
_lllO0I0OI1O = "aP316xfLCQiDvDQS1+69kAF5"
_I0O1lIOO = "kVjibMTClj5evGJRWD4Rs8Ghyfv7UG7PinDyVgj"
_lOO0l1OOl0l = "ohOFKwhlntXDBb6vZ/Yhw2sJ5ZlhwZV/aoLPE5e66ZzGk29TWbK"
_IlIl001 = "Tf/GOVm+PQvkgiAiATsTxVc4KKeQoBimIem8qj1H"
_OO10I0l = "jNfvb7Zayd6EW2xb7yUKh+r4acIlzi1r87VqSIAbXaTJe7Y"
_I1I01O11IOI = "NX6CJ7W7ritHNynrFlGxJkxX5FSIlhR7LUXBm"
_OOO01lII10 = "mrd1TrqgA5KVNwzaqwCVJKEpzHbpod"
_lIIlOlOI = "so24pPbBuIzHkTSEqR1oWo/5hcZoT/oSpiHFRTfU5sM87"
_O1OOIlI00 = "j+E1sLvsJNXIHeF8Y3+tdJdUVK"
_I0lIOI1 = "8I1aM9vsGyi9gkDlLxP7ELmo/g+4eG"
_I1OOIIOO = "KXwNSXVEjWNLy3Nbjo5wbrE7cudr9uJNhzuYa4FttRKx"
_OlI0O00 = "WK7dFvP3kBTa46hls4awy0ATZltpie6OU99WBdFRFHFK72sq"
_Ol1110lI1l = "mNScG+oYEQVkPXFIaXiLuNlATvGLgC4kqFhFXX5AWZNPW8f6"
_l0IOl0lI0O = "SqlscFun18FnjpMV/QKgiN2Rp"
_I10OOllO = "TLB7b9UttZ8GfWLXlWY5/5fmlxajXJ9J4y"
_l10lO1I0II1 = "xGesqJZLX462AGE7amIcoxzG"
_l0O1lI1lI01 = "6oY1ICIjw4EmHTocPc8geMQiNfB1ws53IYDVSiMCY0XZuVjkDT3Ph0r0O4j"
_I11lIlIl = "TPtxxPU+gZ7LsljlvW8gmyqht5b"
_OlO0OIII0O = "Dg9DlEHxuXOjiKRfpFsbtBLtuh+sKMcwRare7PR8U0PWjvHss2PGdln6kIKC"
_lO00O0O = "bp3pVxFNY3/seNKrIwhBveeIavz28EKRijXPExwxoWY6"
_l1OIl010I = "3GAipY3hkKvyzOuEE86c3lEgFP7NrIsFAwi60V51d5csrXgi9Y"
_IOI1000lI = "ciBTTJW57S1FX0n5AHGHhMkzS1COFHzzi+wLI3VA53IgiBP2TKQYs3Jrjum"
_IlOO111Il10 = "yu5jbAz9bbtV7WasY/b2t8NeLfaPoXt4SKrPm5RTk4Nz+ovq8LcsP+dbGwyynY"
_I00l0O0l10 = "JtRPNtI32FpLMXFRuTTbq5I5TG"
_O111l0lOl = "iM56KYAFozdLHwP1KXq12Jzzk2u0prugqYyvYhA"
_IlO11lO = "1CXdneg+wGV8EieQWt3xQRaJDoRnMPeK"
_IIOI101 = "eYOGMT3SvXw706vmUhblFQWVeRHSbFqbY"
_O01I11IlI = "fWKQ4xoNsJQAfdVYA5wHee163pVhJ8F6IzfDA"
_OlI10I1lO0 = "j3t3YG8TjQVcz+tdazBVsQ7d"
_l0lIl00OI0I = "pJo3+MqeS/xUrUeP68ALbA3NX7"
_lOO0IO0l = "5GN492rChduf+AuuzPHts/FbfDIuXBMGXBZmAIyXCRGFb34iVUxM"
_l00IOIl = "uhSvpNBxLt0aLyLSOZsQL1H0ARKZo/y18Qp50"
_IIO0Ol0l = "S1dwVdp7oIKBvANV4sEwfFKQ9vHcf60rf8orYCDaFs+gBfZIiLH"
_O010lOlOO01 = "YcpAgOoD3iGl2Kv7If2YsHlqf000QqQXAz1"
_lIII1ll0O = "aT/7sxHEBZzooDvFeCKMfRbtLPDis15wa19rDpR2Omg8vfNbogDRIl0v02Mk"
_OI101I1O100 = "q1aYXVR2Km0JGcMqqsertzIFQcCJGxz3EUpbTloBhAw7gvhQUXWxPDINrVP"
_l1lOOOIOl0I = "SJ/k69bzpYI0IXzxK3s6hLOF"
_O101OIl1O1 = "TOxQw01S/rvGkMqFR9uXSJ13Q4hhjVvoQN"
_II00I10 = "l/7OcF1GPqR8NHrEPkwreL/q+3yL1jee0p786ghyxnNxPhD45nXv"
_IlI00O1 = "xH3EiiYnYYQxvN+s9KR/Ad9Se2tokHRL"
_l110l1II = "iwT4zQafJu+NrabVBcy0bgjSuxD3HwoLd6KO1"
_Il1I10Ol = "ca4AZKIPgcrSkslwW9C1ELx4w3JgDq93GMLMlnQ"
_l1O0111l0OI = "g+nktO0NoEa+Q/Cdv9rIEyaa5"
_I01lOlIl = "bIm/KiXHGlxxG8KCO7iCLaKkTRSZeW"
_ll0I0Ol01 = "m6/NkncduAcn/c1Li0e3AgtuexhrdR5r"
_II10IlO0l = "6R7gASUSwq5+vFF7NwtP8M37IULCcAacsz/f4UvLz7r2fWV"
_lOI10OI = "v5gPZEIjXn4VICUyCtp2zX73nMWn1tuzx7DTLA"
_OIOOOOOI1l = "EfF4/8txmF78jA/7qvrlXTvkpw0k3OZ8hTvUNzmQzAtLCuB5ophPNm"
_I1OI0Il10l = "BFKCepkubEK0tP6VrJChBR2EsEf0DgBlO4fAeVDPq26fACJGqwD2"
_llO0O00Oll0 = "sZAKUE1qMe9VjjiV9SROr6lCKqiW4MOEt+yjYys1RLb9qPamJpMltqdrw+ar"
_lOllIOIl = "2k/JTW6Woe2glqqE5RMK9LipbwFqxIpoP9HJqs9UlU9mwow65z6PS"
_I11II01O = "+96/Eh0C08JpLGfBphh6pkLtanMCiRb2rvmCDAF0vkRp"
_lOIIOIOO = "QjqufhdTYbPV4fjBXChZKA5+wyXexR7ACXUZ"
_Il1Ol0IOO00 = "Gau9LW5RNB4zteg3dqWMKhSi1u"
_OO00I0O = "E2RZTjUmSTS9NkJR2EeUDvSRCQL77XTvNMWqCOd6sLn6FQ03"
_OlIllIl = "W0qOgnYvXv/DqTwIIwxnCdD0YsILG"
_l0llOIO1l0 = "o6iQec2PySMSxFHJAC9vqBI7BCpRR5ObXO1NQTdoFYWh4cWosB"
_Ol1I01lO = "lGTJvjeeKtOC9ok+pramq8iYWNyy"
_OlIII1I10 = "0iaybFkovZaNQ3hDKlKAVqk31ol+8HV7Vf9KD8Uxx6jcMAScBGOyg/"
_l0O1OO10OO = "Id8OQ3LSDp+9bf0UM3vvUz4uEWW46J1jLB0hpIuQ3VrkZ"
_llO01I1l = "LhEW8O7zaI6xNoawSyY7FpwWYgltt"
_lII1OlOO10O = "mreSDFujdLoCemNkNT3e6oardVZvFGeAFdpkqplxU+XgiZCcftxUFHiDC9+/"
_lO1O00OI = "X30CtRKg1bFl1wa2Xln1RR2DHGQGEcFFGL541j/a7MbG"
_l1IIIOOll1 = "yEQDUdBxU8mynJsnGb4jxvGe"
_lllOlOOl1 = "Z91rIRnhiLUkFKQGtyljXHNmKEuyDDphWfqaK"
_I1lOl1O1 = "E7XBoc1Rqcr9PddUdoHHmUGRU0CMmnHil6btB5bGCnuroEe3Ckm3YZIO89"
_l0OO0IIl = "hRSxhbzN2nPxCemoAbkPqDVsVuZD4G+v4CsTAVc1"
_I00lIOO = "/2K8UsgIIJoAaduN7y5xT1FiFfPvhQWy"
_I01OOll = "qJLvlPkkPMcBU13KCuvgAkAdXBORyiMuDHYIeUrOwsKzKdB0YNhBF"
_OO00l1I0I0 = "fh5vjdbIQx4tLqax3a3i2uw35lN031cfthDezigN3vSVRg5aYL9nlPJ"
_lIIOOl11O = "WJrtOE6rUeL0hOx2QqJ7bLPjAgsyvp71KSU9e3sbNn2CPY"
_lO1OOI10 = "b/rM39GjDtW/zhm1XwIHny3TRYaDbZ"
_IlOIO0O = "N8hl26DBPrsgp6NKs6QsQLkB9myDp9Pfk2/FHaS1SDhxfvtadX"
_I00001O0 = "C1hMTqSMwDfu4VI7z9A8tPran0hJeEbPZrOJAxQcGrBhLqL4xRITxI5UuWZwWC"
_Ill10010 = "hlMjGdJ7nvflTPC+pb9TJcTsEq7SymfhK2TYKW+jpl1Do0RmGrTh"
_OOIOllOO0l = "4dDfmFTXdZNN1MwqXA7bLSbR4Boy7KikCI2mYKd"
_OO01ll1 = "O3XsI0BUTLPeVMoW4T7dcVeQ2saP+sG9PzyBe0EaJT0"
_OOl01Il0 = "/O74/j+n3lo0A+SA53SiSCEigvf3L+xW7a"
_lIOIIlI1 = "9bohcCvpFOD/u5k5R47YJUWJ8Pqd4tr4TVNHxDP/Qht"
_llIO0O1 = "mOXHIewZYoYxhZNmpt/ZYnK/Qd"
_OOO1O0O = "hy7LNHIsvruisBO/WyoyXFJCXLdKrLxKihMf183"
_IO10O1OIOlI = "f4M2mkpAuOIbBYaBwMsll0c8B5rMeysDZ85VNtGzi6ThEQzwf"
_OII100l0 = "uumNUHuVXP8kVqyAxmq0ZKeXLpDD7nls"
_O0O0OIlIOI = "FE9pMnJ5li0X1F+Pgz3m5U50nkrGBHMK3O5RH/QnJqqhoYoqZ4jf/kpY5wERtN8"
_O0lIlII110 = "5Tnq+D3OgNI0N3hHmxsRno0TLzFu+roac9zjXUG9pXH1M/ctM5"
_lO1OO1l1000 = "AQOp4hFHZULzjvE+v2gglgRgwtssa65IrF0e1cDBSDk4kGSHvTF"
_llO01I0 = "D99c6H14AHSqExT6vvBQYzkvR"
_OlO10IIIlI = "PL08C5B10U3ymq7SLGelGelennGjxEXGPTfv+Yf"
_O01110011l = "MMcAeFg3Iu+t23VAvlpBICsA66XBaMozEBaTwmO+a7"
_O0IO0OO00O = "GJ2WlAVOh/v2cjK5wI6pMU7F0m+U"
_lOl0lOI = "cZH7IO36LCyH2Ur6K3UZQ6wtq0D9DtyFV4VvnfwGahMznl0KHN+Du9Jr5b8FcC"
_lOIllO1 = "dxMzsYdhPmpHsYSjaUHi1BdpMlK5Ssq9bKA+yHQ"
_IIl0l011O = "vsBSkVVGdJ5GnR+w5TBXV0QFLV/W4WtSD/7cx4OulZIGULdi6nW"
_OOO0lOIl000 = "IRN74YeTIp2TzWU4I38E6cDpXhnJQvow7K3HjavcDB2QVURUO9ko0akGXI3l"
_llO1lllI10O = "f7EEitaGJYEEcMdDqg6TtCmqzr5QTekytHr2rhE4STISUpcurny"
_IIO00O1O = "RPJL0QbXUY7gWweRB5Uud0MeNrcHnC0yPcKGK"
_l0llO0lI1l = "RAq54Crvm7A1J0xTADEJpwC4Nhxa1vB9VozP1W"
_l1ll10101O = "v+EoMY0o+mogx+MPTSgiipPVUAPxEFoTr0gAILIddIk1"
_O1O1OOl0I0 = "C4JLRwiu1QM1ALUoolVgM2WdMlGP9n6YEGbX3TUnlwbIfssmQzlC1stC"
_l1O1O1O = "Nl4q3arwxJCZZfimk2+PZKoTvZk76F8wT0kFziB"
_IlIIO0011l = "jgPxEWircNqaP41xxKX/ujPheRNZ/2YlFDCvC"
_OIl01I0I = "K98RB7vV285k3N/eySEHikq7bq"
_Illll1l0 = "0zo0m853J/3c58k9RCEcaqZ1wH7f0gIE3KmKqJ9/ga/+2izyh"
_I1IO01II0 = "7l1RwwCYYsWcPk9A9D1+gKAK54HfIt0l"
_OO1Ol01 = "Xpfk/H61911lacpBBAeiXlRZgCEUYkd2/QGRPQmodaA5o5xbB01yKVBOIUm7"
_l0OI0l1I0Ol = "Cohd7PZclc/GBH2Oe5nLBMi/4pAlCVPGLwLYFMVcx3KwB5myvktp6"
_OI11IO0l011 = "yLDQRkrukgEqLAvGaPKS7JSi8RzmJEdiEmT5K"
_O1IlIlll = "0P5OHZO4uyQj9OATeD52XnD8K"
_O0O11ll = "CEg0hmqiwTgPq5UDMGQt23B18ERnH8Cd3MtkSFI"
_lOIlOIO1 = "duUQfIlqYTvpkfFmx+nC+NOr+fs7JO8bj7i9"
_lO1IIlI101 = "lBR54YP7KbcR38FPWvOVN8qkfnYFFOa9kT0evwoi0Kd9hjXlkBfTh4td"
_I0110IIl = "oAQuBFiLKQ45wNil560GSu5pr1piExqxw4w7IOXh/A0Czpm"
_IO0Il00l1 = "AUU7POQ73/l0emqPW0ABVbFox8p5/rLs74f2MYa5D4"
_OI10IlO = "6wJlloYBEYaFJ8RL/4KN3eby3c5PZ6Y"
_I0OOlII1OO0 = "XDJnROQ2A1oZHVJghZtzzjwPf8h"
_I00OOO00 = "YNNE2xXfOW3QTINmwgAVXVg3UOvCzmk9neP"
_IOO1l0OO0Ol = "ZDk48L72ZrTk/YSqhqVYxjOaQv/fSiheG"
_OOlll0I1 = "Uhieya7iuXJzb0ncEWacYCdSK+0scLpmC6Jrw"
_OI1I00l1I0l = "5bwxai4kB6rGLA6i6/NtFagWDiJmzD+eV2I/ptqT9jU"
_I0l01Il = "iEy6BaSTRinMmmgi7hTcWQpvqK"
_l0O00Ol10l = "C8QTm7rI+fQbUBId4vrGfGLMA6YLkR"
_lIlIII11ll = "8CqHqt+ZBJu652/pgiGtHY8JtxS1klxAeMbRGGDX8bGChLFP9AoAiLuaPa93CC"
_I01l0III1 = "Fb2t6oqpgjjQUJkRea3bLhvHzpdN7UfEK"
_lO000lII1 = "RQgbtn/w7kKwkHXfBTdCUQjFElYSth9PHoHfrECc8ZX0vjOQAOSlTXDVWzNZ0"
_l1l1I00O = "MTtZO/yEt1ZZ39Z4hUbCKE0kYZzdEl+CYJPgmAKFh4b"
_l1IlllIO1 = "FfRxlbxWR81oOnXBnso3ej/xvfGta4yfF3ehuqc27tBYfDDVl/SGqn68ISPBy"
_I0IIllIIOl0 = "PTCrwltolS6OG45Q7kf3O+4pPhOKQoQHNbek+Is"
_l1IOOOl1I = "wp0eJsbyqTQYxckvLfqipFFle8hRD983M15bimE/GLn4"
_I1II01O0I = "kAQplZtzH7qYSsLYZapJz+ulTUvbgipWhi7ZyyvKsmEw5ldUioAuq7fc2YPmh"
_OI10OIl11 = "MTtEMyoZqXoDS/GJnOJFrwgBCTHMvDZELpAYjKYmxXcaebzs7KDSM"
_O010010 = "2iB4TY1Q9rGnLyrAIBB3+AVVjfmOG3k/m3"
_IOl10l1IO = "hI5gZ00WoH0t6VCy/FlgY/JT+D8"
_IIlI0l1I1OI = "l871k2kh2nktO/DwxU7eJDLtEQ/Z0u8yyEAfgcmKk4FG6"
_l1I1111O1I = "BuiNHk4cHOQ2cZQl50z1irWk9PGpcjS"
_l11lO0O01I1 = "3tB02j/J9RRwVDxwhfzh53NVTPJ3+IvpmDG3onJjLM4"
_Il1IOlO0I0 = "adrn0n7XCLQcz8RsFFjTPnvdZIA"
_IOO0OOlO = "qjItEYB9mfR8a1gDmg7JuX4OwDyt"
_Ol1OllIOI0 = "XY4tkOUirNPpEiyidqLIf1EjjJUEt3hn2ioslGomBvgDJtQAx23WAcg6FWg"
_OOlO01101 = "XyfeC0wHxQRmowT9NiXFjtHa"
_O0lO00OII = "YNsZL5/xd/vOMP+yROAZ57iQPUHHm4cgZw"
_IOOl0Ol = "LjvHRzrr+yq2Y2O/dIhlRpEjF8mKH8Z8YJCpw5n"
_Il01100lO1 = "kEWo2Vpwb8HQk4ohurXXeFP4KsDBFOR6"
_IllIl11I1 = "AyzNIWNKagwh23ao5Oxq5w2ZmouMyLX"
_O0O1l1Il = "zB2sZs+0WxYfvKh+g+7GusagJUvHowydRD1nxgDA2UfBdTNJ"
_IO00I1Ol1 = "LKWnKH1pvjRIglG+YwQIAlecySM"
_I1IOO1O1O = "m5AffQOzBtqOBQWrcCVsHkAvtMsBWxQMsmJhUaEII2"
_l0ll1llIlIl = "HyOW0beDWsESB5PKciai2D3P5y3424xB8MT/Cfd0ng"
_l1l0OOO = "IElYSt02bSSZzsZudLH9vg4vOLlBVHWmrYo0"
_Oll0Ol0I = "SIm9tpFCNVSx91/437pPyaox3ziFk2bcu9X9hyAfQPlIODnlH92yelZTJcg2lgA"
_O0IIlI0101 = "ZQYvBEUmt73aB24AmI3O1/r/dSZu3MOa"
_Oll0000OlOO = "9GReuwBI+aruXQulWvTqgHuVnEweXFaMGS1J1BHRMCRO2pmifM3bd"
_lOII1I1I = "0V/FvmWbk0hK3xxQsZzGGigofpsvZtQRWsytLyAjEa6hmzjyh/qM0ac"
_Il0l0I1O1 = "vGpEJw241fC5iEh5jNgt5jKI3tfKi4r/JVz"
_lI11IOlII0l = "5sLxGsPP/Km6MnViu75rXyqU8g9TDP5aXOLcV"
_lIOl0Oll = "7Ltoq+Q89klp4DydwHPxECvSTrH+CfEHgaUajDeFv38n+"
_lOlI0OO = "ZZYijh9CDs2zXrhBkrlYn3fU1"
_lIO11I0 = "SVXVY8CGR4tNaSla4ljcJT/n5h/jkcki99myaicpQNCkHe/AB/QwTc1LFloBtk"
_lII1110I = "iGOBrUl6RjXL1mHnIAORjjz0A2b"
_l0I10OlO = "DL8QLGMKOa2Ful0/iynraQgiAUcvyzaYN0IQGieVeiD5BF"
_OllO1OIOlO = "Ai2Zn0aPUJ5t6WnMipKm0Z9uc8KokyJbRmPCSsZSSH92DRpKCFU"
_OO0II11IlO = "730J3NzqCm2BmYnN2g05rxivULOV/dkankwUe9cFfc"
_I0lI111l0 = "sFGN5ShfZjY2WvyZYYuEpVE4O5ddUdde3zrYHVRzxt"
_OlOOlI1 = "RNYHRoZpSK4QxvFLTvdSbtS8oPoC2"
_lO1OIlOI0l = "Y6NBGGzpFfhWEYNjDynctM2oHj4INjHwVlAefGMZ7u9ObFO1GZ+m00ldwUNP"
_lIl0Oll = "C6dnjAkP08xlStLk2oZR7twGhbEMElirngGkY9GCV"
_I1Il0lI1I10 = "KMWNDFK55bK/InEuVPJj5DVw7H65qXkTFcQwILxZMiQQ7C"
_O1011l11 = "Zl+RKSBWZJt2MA84CdcGLOa9hbEG+Q2by9tnjw/LFA0Vm5OKlRLrxZ"
_lIl0l0IO01 = "iFPJOvazKvpNT8nPVcKv17NoO4amTmcO3BERlQrIeF4PvbX6I3URmRiv3"
_O01llll1O = "kXfA6RqL9rsUdgBaMGJK5RMOrd3lLA1lqgPohw"
_IIO0I0III1 = "y15t1rmzk0c7cJ5CAyFLTyGeK0Wub8oBKfG0XC5LtxAwufdxLh1"
_Ol1llII1l = "V36dYYCA/onISa6JCBP0ZtjEQqlCMFoDLj/xCuW4GHpyJiCBX4Fa2FQM+2/8Loc"
_ll00I0O0111 = "Vf5m7vSx4SVKwCjF21cklTYdKGwyKYWjS7+i"
_lO10OOO00O1 = "w/jjq5JqLTLPYrkgPf5Rx74T0mIjMFes7HzNkqFYX"
_llOO1IO1I1I = base64.b64decode(_I0lIOI1 + _Il1IOlO0I0 + _O1I00lOO11O + _IIl1l0Il + _l1IOOOl1I + _lI11IOlII0l + _l1ll10101O + _OO0II11IlO + _l00lOll1I + _I0OOlII1OO0 + _lO000lII1 + _OOl01Il0 + _I00lIOO + _lIlO00O010l + _lO000II + _OOO01lII10 + _I1II01O0I + _lOI10OI + _O0O11ll + _IOI1000lI + _l0O00Ol10l + _O1IlIlll + _IOO0OOlO + _I0110IIl + _OOO10l0l + _lOlI0OO + _ll0I0Ol01 + _I1IOO1O1O + _OIl01I0I + _lO1OO1l1000 + _l00l0IIO0I1 + _IO00I1Ol1 + _lO1IIlI101 + _lIO11I0 + _OI11IO0l011 + _l11lO0O01I1 + _lIl0Oll + _lO1O00OI + _l1l1I00O + _O1I0010IlI + _lOl0lOI + _O0lO00OII + _O10OOO1 + _O010010 + _IIl0l011O + _l0lIl00OI0I + _l0lIl0lI0I + _IIO0Ol0l + _I00l0O0l10 + _lIOl0Oll + _OO01ll1 + _OI10IlO + _l1OIl010I + _O00llII01lO + _OO10I0l + _lO00O0O + _OI0lIllO0 + _I10OOllO + _I01lOlIl + _OO1Oll1lI + _IOI0l10O0l + _lIOOI1I + _l01OO11 + _IO0Il00l1 + _lllO0I0OI1O + _OllO1OIOlO + _IlO11lO + _lOII1I1I + _OII100l0 + _IIO00O1O + _llIO0O1 + _Ol1110lI1l + _I0IIllIIOl0 + _Ol1I01lO + _I1lIll1IO + _OOlO01101 + _l00IOIl + _l0IOl0lI0O + _OlIllIl + _l10lO1I0II1 + _l1l0OOO + _I11lIlIl + _OI1I00l1I0l + _lIII1ll0O + _llO1lllI10O + _I11II01O + _I0lI111l0 + _Oll0Ol0I + _OO00l1I0I0 + _OI101I1O100 + _O111l0lOl + _O0lI0IlO + _O0O1l1Il + _l1lO0lO111 + _O010lOlOO01 + _IlOIO0O + _Il0l0I1O1 + _IOOl0Ol + _l0ll1llIlIl + _lOO0IO0l + _Ol1OllIOI0 + _IIOII11II + _OOIOllOO0l + _lOl00Ol100)
_lI0O0l0Il1 = _IO10O11I1l(_llOO1IO1I1I, _lO10I11lOIl[0], _lO10I11lOIl[1], _lO10I11lOIl[2])
try:
    _O1IllIO1l = _lI0O0l0Il1.decode('utf-8')
except Exception:
    sys.exit(0)
_OIl0II1IlO = {'__builtins__': __builtins__, '_III00O0': _III00O0, '_OlIlIIII1': _OlIlIIII1, '_I0I0O1OIII': _I0I0O1OIII, '_IO10O11I1l': _IO10O11I1l, '_Ol1IlI0O': _Ol1IlI0O, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': _O1lll1l1O0}
try:
    _IlOl1IO = _III00O0[0](_O1IllIO1l, '<s1>', 'exec')
except Exception:
    sys.exit(0)
_Ol1IlI0O(_IlOl1IO, _OIl0II1IlO)()
#PYG4E
