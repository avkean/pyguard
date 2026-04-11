#!/usr/bin/env python3
# Protected by PyGuard v4 (pyguard.akean.dev)
_O0lOIl0O00I = bytes([64, 34, 114, 199, 121, 43, 100, 194, 240, 177, 216, 118, 33, 208, 154, 166, 167, 195, 0, 164, 238, 45, 96, 160, 128, 47, 229, 155, 192, 102, 240, 77])
_lI0lllO = bytes([14, 43, 123, 39, 198, 11, 167, 126, 233, 173, 144, 222, 132, 181, 76, 208, 86, 83, 235, 255, 7, 240, 227, 122, 230, 117, 111, 174, 94, 55, 20, 136])
_OII1OIO00 = bytes([182, 250, 107, 63, 65, 149, 107, 254, 174, 122, 32, 162, 180, 221, 250, 62, 150, 172, 27, 221, 46, 11, 31, 211, 122, 202, 178, 76, 115, 225, 58, 175])
_O0O110OI = bytes([155, 250, 105, 1, 221, 227, 122, 84, 220, 50, 176, 181, 132, 114, 30, 101, 212, 137, 13, 141, 40, 240, 161, 73, 95, 4, 74, 155, 198, 143, 239, 8])
_O11I00OI1I1 = bytes([14, 172, 171, 76, 184, 28, 45, 52, 251, 132, 85, 52, 95, 163, 124, 94, 125, 152, 122, 90, 21, 166, 54, 237, 20, 247, 217, 238, 11, 104, 42, 189])
#PYG4S
import sys, hashlib, base64
_lOIllIOllII = type(lambda: 0)
_IOlIlIII1 = (exec, type, getattr, compile, open, __import__)
_I1OlOIl0 = _IOlIlIII1[2](sys, '_getf' + 'rame')
_O0llO0I = bytes([45, 207, 203, 185, 105, 217, 94, 126, 219, 205, 233, 48, 29, 175, 49, 232, 104, 162, 148, 197, 150, 45, 205, 45, 237, 234, 243, 131, 118, 11, 9, 254])
_O11000OIl = hashlib.sha256(bytes([160, 210, 99, 73, 103, 149, 205, 175, 97, 176, 166, 140, 70, 135, 157, 147, 188, 195, 90, 90, 60, 254, 53, 150, 245, 161, 168, 202, 118, 230, 37, 69])).digest()
_IO0O0lIOOII = hashlib.sha256(_O11000OIl + bytes([144, 94, 141, 75, 114, 181, 232, 124, 110, 164, 179, 137, 68, 251, 24, 64])).digest()
_IIIIO1OOIOO = hashlib.sha256(_O0llO0I).digest()
_OIIO00llO = hashlib.sha256(_IO0O0lIOOII + _O11000OIl).digest()
_IO01l00 = hashlib.sha256(_IIIIO1OOIOO + _O0llO0I).digest()
_l0l1II011I = hashlib.sha256(_IO01l00 + _IIIIO1OOIOO).digest()
_l1I11Ol = _l0l1II011I
def _IOlIO1I(_I1I1lIII1):
    _I1I1lIII1 = bytes(a ^ b for a, b in zip(_I1I1lIII1, _l1I11Ol))
    _IOO0l00Il10 = []
    _O11OOOOO1IO = _I1I1lIII1
    for _ in range(9):
        _O11OOOOO1IO = hashlib.sha256(_O11OOOOO1IO + bytes([243, 207, 135, 166])).digest()
        _IOO0l00Il10.append(_O11OOOOO1IO)
    _O00O0IlO = [(b % 6) + 1 for b in hashlib.sha256(_I1I1lIII1 + bytes([208, 240, 203, 98])).digest()[:9]]
    _IIlI1I0IlI = hashlib.sha256(_I1I1lIII1 + bytes([114, 63, 189, 99])).digest()
    _OlIIll0 = list(range(256))
    _ll00O110 = 0
    for _OIl0I0001 in range(256):
        _ll00O110 = (_ll00O110 + _OlIIll0[_OIl0I0001] + _IIlI1I0IlI[_OIl0I0001 % 32] + 7) % 256
        _OlIIll0[_OIl0I0001], _OlIIll0[_ll00O110] = _OlIIll0[_ll00O110], _OlIIll0[_OIl0I0001]
    _l0lI01l1O01 = [0] * 256
    for _OIl0I0001 in range(256):
        _l0lI01l1O01[_OlIIll0[_OIl0I0001]] = _OIl0I0001
    return _IOO0l00Il10, _O00O0IlO, _l0lI01l1O01
def _I001IIOO11(_O1I01I01l, _O01O1I1, _Il0IlIOI0, _O0l010I1):
    _l1II1IO0 = bytearray(len(_O1I01I01l))
    _lO0ll1OO1 = 9
    _lIOIIll = 0
    _llO110l1O = 0
    _I00l1IIOO0O = 0
    _l1I10I1I = 0
    _lO0000O01 = 180
    while True:
        if _lO0000O01 == 100:
            break
        if _lO0000O01 == 180:
            if _lIOIIll >= len(_O1I01I01l):
                _lO0000O01 = 100
                continue
            _l1I10I1I = _O1I01I01l[_lIOIIll]
            _llO110l1O = _lO0ll1OO1 - 1
            _lO0000O01 = 232
            continue
        if _lO0000O01 == 232:
            if _llO110l1O < 0:
                _lO0000O01 = 80
                continue
            _I1Il1ll0 = _Il0IlIOI0[_llO110l1O]
            _l1I10I1I = ((_l1I10I1I >> _I1Il1ll0) | (_l1I10I1I << (8 - _I1Il1ll0))) & 0xFF
            _l1I10I1I = _O0l010I1[_l1I10I1I]
            _l1I10I1I ^= _O01O1I1[_llO110l1O][_lIOIIll % 32]
            _llO110l1O -= 1
            continue
        if _lO0000O01 == 80:
            _l1I10I1I ^= _I00l1IIOO0O
            _l1II1IO0[_lIOIIll] = _l1I10I1I
            _I00l1IIOO0O = _O1I01I01l[_lIOIIll]
            _lIOIIll += 1
            _lO0000O01 = 180
            continue
    return bytes(_l1II1IO0)
def _l1lIO01l0lI(_IO1O10l00lO):
    _lI0lIOI11I = hashlib.sha256()
    _I0IIOI1001 = [_IO1O10l00lO]
    while _I0IIOI1001:
        _llIlOll = _I0IIOI1001.pop()
        _lI0lIOI11I.update(_llIlOll.co_code)
        for _OllII011lI1 in _llIlOll.co_consts:
            if type(_OllII011lI1).__name__ == 'code':
                _I0IIOI1001.append(_OllII011lI1)
    return _lI0lIOI11I.digest()
def _l1I01O000(_OOOIl0I0):
    try:
        _Il0IIl0OII = bytes(a ^ b for a, b in zip(
            hashlib.sha256(_IlO00lIl + _l1lIO01l0lI(_I1OlOIl0(1).f_code)).digest(),
            hashlib.sha256(_IlO00lIl + _IlO00lIl).digest()))
        return hashlib.sha256(_OOOIl0I0 + _Il0IIl0OII).digest()
    except Exception:
        return hashlib.sha256(_OOOIl0I0 + bytes(32 * [255])).digest()
try:
    _lO11lOI1 = __file__
except NameError:
    _lO11lOI1 = sys.argv[0] if sys.argv else ''
try:
    with _IOlIlIII1[4](_lO11lOI1, 'rb') as _OOI00lOlI0:
        _O1lOl0I01lI = _OOI00lOlI0.read()
except Exception:
    sys.exit(0)
_O1lOl0I01lI = _O1lOl0I01lI.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if _O1lOl0I01lI[:3] == b'\xef\xbb\xbf':
    _O1lOl0I01lI = _O1lOl0I01lI[3:]
_OO0IOIl1 = _O1lOl0I01lI.find(bytes([35, 80, 89, 71, 52, 83]))
_I010000lOO = _O1lOl0I01lI.find(bytes([35, 80, 89, 71, 52, 69]))
if _OO0IOIl1 < 0 or _I010000lOO < 0:
    sys.exit(0)
_l1Ol0I110 = (_OO0IOIl1 + _I010000lOO) // 2
try:
    _OIl11IO000 = _IOlIlIII1[3](_O1lOl0I01lI, _lO11lOI1, 'exec')
    _l0l1l0IIOO = _l1lIO01l0lI(_I1OlOIl0(0).f_code)
    _IlO00lIl = _l1lIO01l0lI(_OIl11IO000)
except Exception:
    _l0l1l0IIOO = bytes(32)
    _IlO00lIl = bytes(32 * [255])
_O0OOIlOI0I = hashlib.sha256()
_O0OOIlOI0I.update(_O1lOl0I01lI[_OO0IOIl1:_l1Ol0I110])
_O0OOIlOI0I.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(_l0l1l0IIOO + _IlO00lIl).digest(),
    hashlib.sha256(_IlO00lIl + _IlO00lIl).digest())))
_O0OOIlOI0I.update(_O1lOl0I01lI[_l1Ol0I110:_I010000lOO])
_Oll1lO1I0 = _O0OOIlOI0I.digest()
if _IOlIlIII1[2](sys, 'gettrace')() is not None or _IOlIlIII1[2](sys, 'getprofile')() is not None:
    _Oll1lO1I0 = bytes((b ^ 138) for b in _Oll1lO1I0)
if compile is not _IOlIlIII1[3] or exec is not _IOlIlIII1[0] or getattr is not _IOlIlIII1[2]:
    _Oll1lO1I0 = bytes((b ^ 131) for b in _Oll1lO1I0)
_OIl1110O0II = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != _OIl1110O0II or exec.__class__.__name__ != _OIl1110O0II or
        getattr.__class__.__name__ != _OIl1110O0II or __import__.__class__.__name__ != _OIl1110O0II or
        open.__class__.__name__ != _OIl1110O0II or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        _Oll1lO1I0 = bytes((b ^ 96) for b in _Oll1lO1I0)
except Exception:
    _Oll1lO1I0 = bytes((b ^ 96) for b in _Oll1lO1I0)
_ll0l0l0OI1l = sum(b for b in _Oll1lO1I0) & 0xFF
_O01llO1II = _ll0l0l0OI1l
_Oll1lO1I0 = bytes((b ^ _ll0l0l0OI1l ^ _O01llO1II) for b in _Oll1lO1I0)
_l0OII111 = hashlib.sha256(_Oll1lO1I0).digest()
_II01OO0l = hashlib.sha256(_Oll1lO1I0).digest()
_Oll1lO1I0 = bytes((a ^ b ^ c) for a, b, c in zip(_Oll1lO1I0, _l0OII111, _II01OO0l))
_Il1I1I1OI1O = bytes(a ^ b for a, b in zip(_O0lOIl0O00I, _Oll1lO1I0))
_l000lO0 = _IOlIO1I(_l1I01O000(_Il1I1I1OI1O))
_I0II01l = "TzUFdV3JYEQsZlALulfQ0EkLe28SAPcrMtGPmWuymWqvNI+"
_O1I1OOOI = "ii3i2QDjLdv41Q+qsjxx1Tw/XIg="
_lOl1O10 = "CbfROQKegNcKPMhzgftUggXuq5iWDLKr2Oq/Kju0v"
_O00I1II = "wJWx65ROJYZXDsEm8gWFkCjjBNdV6PNhQy5wN0o8yN7"
_llIOl11OOlO = "oe+0sJI/VSTk2VU3ExESlDmxOTBE+HqJ+Ip58dU7AaD6ScPRhUjd4W/NI"
_OO0lOI0I1 = "OPW83nR3d8HRLb7+XTHE5ZKvd"
_llO0lOl = "g1DcOb/QyELHq/vYxVE47A7Dvca39CWZ8BB4rBKFaOu2N5yS2uGngzr7vNj"
_IIll1Ill = "bh/PLqVwfEDPnUqykYb+/45/lhI7QxMwRxp6/UTPw+VtNjvx1a3czxUOq3Eg1"
_I00l1l1IIIl = "oHcyDpajpaCBcbzcePfmHYiX"
_OIIlOIIOIlI = "K6T1PEHKOjk7ydXAGKHbcigVWc1yLzZXg6PdXNSqPSXaeVGUfu"
_O1101Ol000O = "jwCDT0eESfeEbidwx+gfLrghkCtcn"
_l1IOII1O = "NO5D6EsKV6MNdO04Bh/+yTNU+Aul"
_II10llIIlO0 = "/y7R+dE/kEryxm4aFRLtnA2FvQSXNkR"
_O0Il1l1l0 = "T1jet3TxI6QumWl19ZKHo/HEK80tOGFnOuQh4cXC/YxFIu"
_O110ll01I = "MbUy03YrWLVcIPeMWJh1iJzOwoaImGoA0jSmdszTjqFFK5lEhHk1uBT8"
_OIl1O0l = "CW7+qY6C9P7iAcv7ExU/RNVw8Oe+a0UmCDQbaK6cn8Yx"
_Il11OIl = "zeAqj1aats2hZBk7WmDapxtzLIeCtt+qMThjNtYOjcCXgdQrd7jOxdsACfWmbz"
_O0OI1IOI = "2beJOcHGExPDhtCs+DR/GWuQFUy+r0"
_IOO1l01Il = "94miwtDSeaMM2PGF+9hujxTJrJVXdxYE+EQm1F8rM"
_O0Oll0l0lII = "BPQZ0UgvQQX1SCFeLO9hQg/qIID5"
_I1OlIOlO = "8B9Veq1SaXjLiE9Q42nqNOw8JyvFcVxQIpsvSMwHaEKcYQqH"
_OlOll1I1l = "B1l0QVbXZsX0IuIUmxJYy5sMeVoJHU"
_II111l11 = "bK80zipQJyVisDpGT59W3HZsNFIUsLkglSL7NAS"
_I1OOlll0 = "e2DUz6XK44NkjXJHwzy7xs4ZL6hJe+xJzjHxdJ29oEGnIS3X8gu6XoIx"
_llIIOOIOl0O = "RI/ebeCYy2FfxbJGQeFuPiOZjzG9tOtyIaqNC8qJDjyldg"
_I00Ill10 = "4x4vo1ffkmTFRiPQHdBTDOy440Jse6EtJLBu"
_lIl1Oll = "Wb6GPS+fv4EYnoG5iOiAfFMNnTrYs5LuEaOEQeSwi9/cgA73pFh28QD3Pv"
_IIlOIIIlOOO = "YppyExXmIpUPhOsTx+YaCI2SV9xB8YkRI5ERUqWFt5"
_lI0Il00l1lO = "pvv0OvkeCHymrLw+adQ2TGn8egrASTTjbsHylT"
_OIOO1O0lOI0 = "ZBdkfn+mBhXBwMbRBYp5hdDe9VMqhAzVBLeQjC4j0urdE2duFxo5t"
_OIl1l0IlO1 = "rg2aGCElXu+hL9rLNLso5x23VvbcUregK"
_ll1I10O = "s/tEhm4lPJSwNa0wsosZnFGChwd5"
_OIOIO11111 = "NxEhfWW6AHoAZYKq9DmojpFPdOdNSjnB/aMh9Piqn613IUoJiBA"
_IlOlO1IOlOO = "euG+VOo6zXWFkS7BUdrjMuKiK7ZaLPA2+DFtYvOWo31E0dxjg4"
_I0II011lII = "I3TajbMOpXW9guFIi8KG2VQMC"
_lI110l1lO0 = "kEgSGd4H4yF2j6LREDCFGPHzy66ZM40N0rey9Q"
_IOIl101 = "kA+tyZqR1PYU+RY4xxw3EnceMHb+zCY10JH2EAeZs7qxDIKTi73dZHyPB/u"
_l101IO1O1O = "o57bPT6XbgmoOYr9g6L4l/uVuLnvAS0xmWcx/eq6yyLFPx9eE"
_O0Ill1l00OI = "3fW/YWtc0mzG3UGXzpwPCTu557W9/FoLGP+DvgaKebCr"
_l100OI1O111 = "lzP/3oDjdVjUql1EEKadYD2mmSfRDszGl0HE5zNTfs/rAk"
_O0010l0l1O = "rULr+WIgNkEigamjWAyNvCn9uazE6HPgYIKSDt7TSH9p6Nr"
_IOO000l = "W6ayUZlRST2ZkTHCQJxRt87h62nP11GEXC7cUzAdA4KUfjKPyZROiYU869j"
_Oll11O00I = "bHhx5IFvPtbn5Ed7GsbrvkEDGC1oTuLWKkEsE2nhQENrNaoQAwzp09"
_Il0O11lO = "IGghcevaA1jUIsaUOZ73ReRe5XKRth"
_Ol0lOI1 = "Y7yyTJnYBRrZ69X3K1Uefsduuo6b1IEQXiqxpRut25pyAvi"
_OIIl0Il1O = "37vSz3LYaBLeB6lnBSBDKqelBUnQKeB0m+ty31SZZB+L6pbI"
_II10O1lI00I = "2Y/sw6jtTxkbLvRKkO+zNLgc/V"
_lO0I0101O = "COjfWocQhr70soZqXHGcFN4qr"
_lOOlIlO10l = "v5trFc17VW8e4HlgVPPSqXOAS"
_lllll1OOIO = "1V+Om2IUoq4lHGlcmsVZYxkyhI9YianN/Nbbso"
_llIl00IO = "q5pxq8YXTIPgfWkZ72rmAUl8MigMyMI"
_lII00lIl1I = "amzjUlf4kfBD3pcZ+9jZFPB8MLITM2cEZ4UM5jdP8luDNf+u"
_O1OI0lOlO = "n5CMDI1CBE/FQ/K69RW4FyccMyQjWBVhUNO"
_IO0lI1I0I = "LagPIRqvrelk8jx4FRHGLLgffmE1FBMAw8wY3cdEv4ahxJZ1H"
_O011IOO = "qhfBu04KCK/TnntWNS9tSiw4At0BR/YOzPdZHjGWy"
_IOOO0OO0I = "xRHV/HnqwPAlNyDYZi87RQcP5FNG"
_lIOI000lO = "FMIcEdyB5yMOE/8LWMZWt/UfGgwOce/wgap5JNGnkqYYRjNH7HOdztsV72jojC"
_O110OOl = "ps/iUjlYGnn/0PeBWwfjC2zhsj"
_OO1IlOl = "8shVD4fAl/uARgffMYMHH2F9"
_I110100 = "5hfUAkJJQSWzom5izvF9V6kvhDQt0FYX"
_I01I10OO0l = "HQvXC9R5YDqWwNsF8r3nrzjTigvWVk"
_lIlO1Ill1O = "vSCKNer8ybM/tZna80v7bZFLy8lZ20LhKJn6T"
_I0O0I1I = "4Zyhe6zbtEGPVhcC+FSChGOPy3OqfM23fZtnjdEKOStJqNMMYh15tRoQu8Mnx/1"
_O0Il1II0O0l = "fRJ0lV23X7uuT+3pTtHrxqDogorvTQHibCqjYd1Ug+PV9eEnrROnOa/B"
_OO10IlO11l0 = "M0b0dcpJDVZzV8xFTkDKZJBTppM89RNiCzcZ9VJZb8mLRKA0G4Vufb3RWlL"
_OOl0O1I1I = "sDRSKA3jDCfFD3oslvN9YBpe"
_O11O010lO = "g79oFELuu2bsw4Rvc1viXOxFCl+XAA363aXwCJnYa30ViMkHiA85"
_ll11O11Il = "7cgwD4fxemiHHtCmf8vEZwfg3NJsJkRBGkqfYonyHKdBhoDrZTF4YScef"
_I0OO111O = "QebFNUOQ8QB03M2BkAN0pwgKimXADy"
_OO1011O = "dRjbPssHvLZnSlfUfBtuwQuH7PDSy82Xaey9WbwdF"
_l0OI1l0 = "u51PeO6C3xIiPQVIrtCp8Cc3b7vLDow3a/l2ldR7Kbu7"
_O0I0l00Ol1I = "XBJBD+dbTGi2YJhPi2xpPXy0GvSyP/CfvGn8zwICHMiD5MaM5078DBcGZtD"
_O0l11OOI1l = "4pgwdXrDuNixgvFeEyEC3vgnF3BSF8unkugB4UzX3Ue+"
_l1l0OOl11Ol = "IN/2L1NPc5qC9a/1FwYA6fiMsfV7ZBvDPWXTRcKHTGXf"
_l0I1lOO = "YNxXsyVdUxQL3HAf7y3M5e0RjfL8KeCCvs3SvQt/VQc1pbDFLPIiAHkaot"
_lOlIIIOI = "EkeKXWYS6akH57KQHvJd7zUG5TjCqMJ9/"
_O1I0I0IOO1 = "bJuyjIeOWG2HP/j08iitXIZIjz5vgPBRFIiWD5Izvw"
_l00lO1II = "vro1KGs2ew08ROEVjGYrrAL8gLGeu4U8yccChxbX3Zwxi6ayx"
_I1O00I00 = "4K4y5ukXKicaecRnoz36E7IuoIK92FbR+B+YXsMS"
_I1101lIIO1 = "TF6ET8RT67MDl4WKvEGDpZEfuDC1nfCfxg3WgoudLu4ebplIIcY67"
_OlI1I1I = "cChzbgtxZqzFhJmX0z4Ive5kmELL0chqJFEUDcPTgWRZ8rxlN58XvJq"
_IlO1llI0 = "2pmva3FMRqwP6CYZmzdNmcWOMAb4iNUhUOy3l+L2YkKIW"
_I11l1011 = "Q8zbxhPYwAGjBppdW9UqZeeqgxVKHPRXpWV1i"
_O00IIlII1 = "BSXmbML0ueQA3L1C5q2t8NCzA5ZWmFNTGwHj7EU6CsJrDY4IQ+CX3"
_l00IOOI0O = "tj5BeCjB6s2oT00DUmO+p+gkRl+XSJhHXi6LQnkeqASG+NOvEUAOj95UB/RhT3"
_O1Ol0l1lO0 = "YD5rqEvowZPGe2wHIeLJ6xMJW4ALXu"
_lO01lOIlI1I = "C+5+uCTAye0ZdqoODMZ7QZFvr6NqjkziIRefi7mb2P1PSQRqT9URqcG5dZ"
_Il1IOl01lI0 = "rOIUHT1Ney9drr78JAVNxGBHRByyzDSZWZjS5HOQrffu"
_OOOl1l1IOl = "CHLmwwvn+kbqKoGqWkRo2Q1BhTNfQc"
_lO0lIO1OO = "mvxetNVfJ68LFVGFJniGzhrzXRJryv4iSRJ"
_lOOOII0 = "rpD8ZkGyBast+aibJKkt9Pst"
_l1IIOl1OIO = "bOPeeihxH3MWZPa5L0H2W/n9q7cY"
_OOII1OO0 = "bNrXn0XtxLG1eLuYb6Ad3gqcDBMa/VNdaL5Nxy004tvRd0hmuiOVTsp"
_ll1lIOOIOO = base64.b64decode(_llIIOOIOl0O + _IOO1l01Il + _OO1011O + _l00IOOI0O + _I0OO111O + _OlI1I1I + _lI110l1lO0 + _OO0lOI0I1 + _l0I1lOO + _O0010l0l1O + _lllll1OOIO + _O11O010lO + _IIll1Ill + _IlO1llI0 + _IOO000l + _OlOll1I1l + _I0II01l + _Ol0lOI1 + _Il0O11lO + _I1OlIOlO + _lO01lOIlI1I + _IO0lI1I0I + _lO0lIO1OO + _O1101Ol000O + _II10llIIlO0 + _OOII1OO0 + _IOIl101 + _I110100 + _OIl1l0IlO1 + _IOOO0OO0I + _O011IOO + _lII00lIl1I + _II111l11 + _O0Il1l1l0 + _I1O00I00 + _l1IIOl1OIO + _IIlOIIIlOOO + _OIOIO11111 + _lO0I0101O + _OIl1O0l + _Oll11O00I + _I00Ill10 + _OOl0O1I1I + _lOl1O10 + _l00lO1II + _O0OI1IOI + _lOOlIlO10l + _O0Ill1l00OI + _O1I1OOOI)
_l1lO1O1Oll = _I001IIOO11(_ll1lIOOIOO, _l000lO0[0], _l000lO0[1], _l000lO0[2])
try:
    _IOO1lO1l1 = _l1lO1O1Oll.decode('utf-8')
except Exception:
    sys.exit(0)
_l1l0IIO01l = {'__builtins__': __builtins__, '_IOlIlIII1': _IOlIlIII1, '_Il1I1I1OI1O': _Il1I1I1OI1O, '_IOlIO1I': _IOlIO1I, '_I001IIOO11': _I001IIOO11, '_lOIllIOllII': _lOIllIOllII, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': _lO11lOI1}
try:
    _O1I1O1O = _IOlIlIII1[3](_IOO1lO1l1, '<s1>', 'exec')
except Exception:
    sys.exit(0)
_lOIllIOllII(_O1I1O1O, _l1l0IIO01l)()
#PYG4E
