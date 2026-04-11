#!/usr/bin/env python3
# Protected by PyGuard v4 (pyguard.akean.dev)
_lI1I0Ol = bytes([65, 51, 5, 117, 64, 30, 80, 109, 23, 15, 165, 160, 81, 248, 171, 205, 47, 159, 115, 59, 244, 194, 29, 233, 73, 146, 167, 160, 134, 39, 7, 31])
_IIl1OO0l = bytes([129, 238, 251, 34, 209, 242, 76, 28, 57, 224, 199, 100, 48, 217, 156, 178, 209, 206, 159, 71, 42, 161, 32, 122, 28, 63, 3, 34, 6, 218, 195, 149])
_I0lllOII01I = bytes([4, 106, 240, 230, 151, 164, 247, 254, 158, 65, 72, 200, 230, 22, 131, 101, 102, 158, 188, 146, 223, 254, 179, 205, 24, 180, 41, 152, 184, 24, 240, 108])
_lIl010O = bytes([56, 128, 219, 243, 101, 227, 152, 37, 209, 15, 57, 76, 67, 190, 138, 152, 132, 69, 81, 67, 247, 36, 88, 69, 135, 44, 252, 111, 127, 164, 85, 20])
_II0lllO = bytes([127, 158, 114, 127, 142, 253, 138, 9, 27, 5, 15, 230, 242, 149, 199, 25, 74, 43, 122, 235, 42, 7, 4, 245, 221, 14, 30, 239, 189, 221, 237, 251])
_O0lll111OIO = bytes([81, 183, 203, 156, 9, 98, 167, 158, 160, 96, 42, 112, 3, 217, 175, 35, 83, 254, 1, 249, 172, 19, 235, 143, 72, 159, 72, 172, 127, 110, 93, 160])
#PYG4S
import sys, hashlib, base64
_OO1IIO0O = type(lambda: 0)
_O00I0OOI = (open, exec, type, getattr, __import__, compile)
_l1I01O1 = _O00I0OOI[3](sys, '_getf' + 'rame')
_l0O11OI1 = hashlib.sha256(bytes([253, 206, 192, 12, 42, 95, 66, 115, 133, 255, 148, 123, 33, 157, 182, 145, 52, 225, 24, 250, 30, 83, 57, 152, 85, 37, 156, 112, 1, 243, 115, 19])).digest()
_IOIIII11OOl = bytes([60, 4, 230, 251, 16, 71, 90, 234, 252, 228, 185, 81, 130, 241, 82, 143, 134, 246, 108, 158, 43, 111, 115, 201, 235, 194, 135, 81, 48, 215, 167, 86])
_I0Ol0O11 = hashlib.sha256(_l0O11OI1 + bytes([252, 38, 232, 128, 235, 13, 223, 106, 157, 176, 80, 10, 210, 192, 248, 123])).digest()
_lI10OOl00O = hashlib.sha256(_I0Ol0O11 + _l0O11OI1).digest()
_O0010IOOlI = hashlib.sha256(_IOIIII11OOl).digest()
_I1IOII10I = hashlib.sha256(_O0010IOOlI + _IOIIII11OOl).digest()
_OO001I0I0O0 = hashlib.sha256(_I1IOII10I + _O0010IOOlI).digest()
_OOllO0O0 = _OO001I0I0O0
def _I0I00llll0(_Ol11011I):
    _Ol11011I = bytes(a ^ b for a, b in zip(_Ol11011I, _OOllO0O0))
    _l1O0OOOll0 = []
    _Il01l10l1O = _Ol11011I
    for _ in range(8):
        _Il01l10l1O = hashlib.sha256(_Il01l10l1O + bytes([119, 150, 177, 95])).digest()
        _l1O0OOOll0.append(_Il01l10l1O)
    _O010OOOll = [(b % 6) + 1 for b in hashlib.sha256(_Ol11011I + bytes([185, 231, 4, 154])).digest()[:8]]
    _IlO0O011O = hashlib.sha256(_Ol11011I + bytes([137, 9, 248, 173])).digest()
    _lIIO10l10 = list(range(256))
    _lOI10O1OllI = 0
    for _OllO1lI in range(256):
        _lOI10O1OllI = (_lOI10O1OllI + _lIIO10l10[_OllO1lI] + _IlO0O011O[_OllO1lI % 32] + 132) % 256
        _lIIO10l10[_OllO1lI], _lIIO10l10[_lOI10O1OllI] = _lIIO10l10[_lOI10O1OllI], _lIIO10l10[_OllO1lI]
    _OOIO11111IO = [0] * 256
    for _OllO1lI in range(256):
        _OOIO11111IO[_lIIO10l10[_OllO1lI]] = _OllO1lI
    return _l1O0OOOll0, _O010OOOll, _OOIO11111IO
def _l1011OI(_OOI001IOl, _OOIO0OO1O00, _OlO0OI11I, _OO1I0l0001l):
    _I11OII0 = bytearray(len(_OOI001IOl))
    _ll11llOIl = 8
    _OOlI1I1IOO = 0
    _OIOl0O0Ill = 0
    _ll1OlOIlI1 = 0
    _Ol1II0OI0 = 0
    _O1II11l1l = 140
    while True:
        if _O1II11l1l == 79:
            break
        if _O1II11l1l == 140:
            if _OOlI1I1IOO >= len(_OOI001IOl):
                _O1II11l1l = 79
                continue
            _Ol1II0OI0 = _OOI001IOl[_OOlI1I1IOO]
            _OIOl0O0Ill = _ll11llOIl - 1
            _O1II11l1l = 155
            continue
        if _O1II11l1l == 155:
            if _OIOl0O0Ill < 0:
                _O1II11l1l = 41
                continue
            _Ol1OOlI = _OlO0OI11I[_OIOl0O0Ill]
            _Ol1II0OI0 = ((_Ol1II0OI0 >> _Ol1OOlI) | (_Ol1II0OI0 << (8 - _Ol1OOlI))) & 0xFF
            _Ol1II0OI0 = _OO1I0l0001l[_Ol1II0OI0]
            _Ol1II0OI0 ^= _OOIO0OO1O00[_OIOl0O0Ill][_OOlI1I1IOO % 32]
            _OIOl0O0Ill -= 1
            continue
        if _O1II11l1l == 41:
            _Ol1II0OI0 ^= _ll1OlOIlI1
            _I11OII0[_OOlI1I1IOO] = _Ol1II0OI0
            _ll1OlOIlI1 = _OOI001IOl[_OOlI1I1IOO]
            _OOlI1I1IOO += 1
            _O1II11l1l = 140
            continue
    return bytes(_I11OII0)
def _II11IOOO1(_I0O00l0OOOl):
    _ll1Il00l0I = hashlib.sha256()
    _IO01l00l = [_I0O00l0OOOl]
    while _IO01l00l:
        _IO10l1OlIIO = _IO01l00l.pop()
        _ll1Il00l0I.update(_IO10l1OlIIO.co_code)
        for _Oll10I10101 in _IO10l1OlIIO.co_consts:
            if type(_Oll10I10101).__name__ == 'code':
                _IO01l00l.append(_Oll10I10101)
    return _ll1Il00l0I.digest()
def _l1100O1l0(_OOlO1II):
    try:
        _I1IOI1llI = bytes(a ^ b for a, b in zip(
            hashlib.sha256(_II000l0l + _II11IOOO1(_l1I01O1(1).f_code)).digest(),
            hashlib.sha256(_II000l0l + _II000l0l).digest()))
        return hashlib.sha256(_OOlO1II + _I1IOI1llI).digest()
    except Exception:
        return hashlib.sha256(_OOlO1II + bytes(32 * [255])).digest()
try:
    _II11O1I1l = __file__
except NameError:
    _II11O1I1l = sys.argv[0] if sys.argv else ''
try:
    with _O00I0OOI[0](_II11O1I1l, 'rb') as _lO1l0I1:
        _OIIOl1I111 = _lO1l0I1.read()
except Exception:
    sys.exit(0)
_OIIOl1I111 = _OIIOl1I111.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if _OIIOl1I111[:3] == b'\xef\xbb\xbf':
    _OIIOl1I111 = _OIIOl1I111[3:]
_lO01O11I0 = _OIIOl1I111.find(bytes([35, 80, 89, 71, 52, 83]))
_O11OI0lll = _OIIOl1I111.find(bytes([35, 80, 89, 71, 52, 69]))
if _lO01O11I0 < 0 or _O11OI0lll < 0:
    sys.exit(0)
_l0lOIIOIOO = (_lO01O11I0 + _O11OI0lll) // 2
try:
    _I0l00O11Ill = _O00I0OOI[5](_OIIOl1I111, _II11O1I1l, 'exec')
    _OI00OIlIlO = _II11IOOO1(_l1I01O1(0).f_code)
    _II000l0l = _II11IOOO1(_I0l00O11Ill)
except Exception:
    _OI00OIlIlO = bytes(32)
    _II000l0l = bytes(32 * [255])
_IOI1lO1lI = hashlib.sha256()
_IOI1lO1lI.update(_OIIOl1I111[_lO01O11I0:_l0lOIIOIOO])
_IOI1lO1lI.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(_OI00OIlIlO + _II000l0l).digest(),
    hashlib.sha256(_II000l0l + _II000l0l).digest())))
_IOI1lO1lI.update(_OIIOl1I111[_l0lOIIOIOO:_O11OI0lll])
_OOIl111Il1 = _IOI1lO1lI.digest()
if _O00I0OOI[3](sys, 'gettrace')() is not None or _O00I0OOI[3](sys, 'getprofile')() is not None:
    _OOIl111Il1 = bytes((b ^ 109) for b in _OOIl111Il1)
if compile is not _O00I0OOI[5] or exec is not _O00I0OOI[1] or getattr is not _O00I0OOI[3]:
    _OOIl111Il1 = bytes((b ^ 46) for b in _OOIl111Il1)
_III11Ol = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != _III11Ol or exec.__class__.__name__ != _III11Ol or
        getattr.__class__.__name__ != _III11Ol or __import__.__class__.__name__ != _III11Ol or
        open.__class__.__name__ != _III11Ol or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        _OOIl111Il1 = bytes((b ^ 111) for b in _OOIl111Il1)
except Exception:
    _OOIl111Il1 = bytes((b ^ 111) for b in _OOIl111Il1)
_I1lOO0OI00 = sum(b for b in _OOIl111Il1) & 0xFF
_l1llIlI = _I1lOO0OI00
_OOIl111Il1 = bytes((b ^ _I1lOO0OI00 ^ _l1llIlI) for b in _OOIl111Il1)
_llOOll1OI = hashlib.sha256(_OOIl111Il1).digest()
_l1OI1ll00OI = hashlib.sha256(_OOIl111Il1).digest()
_OOIl111Il1 = bytes((a ^ b ^ c) for a, b, c in zip(_OOIl111Il1, _llOOll1OI, _l1OI1ll00OI))
_OI1l0O00l = bytes(a ^ b for a, b in zip(_lIl010O, _OOIl111Il1))
_O1IO11IlII0 = _I0I00llll0(_l1100O1l0(_OI1l0O00l))
_I10lOIIOOO = "kBTEortdv1yLOQAvcOX/6SJoVKHMrq9p3IwTgsJd9+IBLjHzzc1mg"
_IlO1lO00O1l = "vDCchL76eyE80JcQHJFKVReFbZgebylR"
_IOI11lIl = "OhpGVa2/OVpD93OBz8GE8M3rPvfsPGye8oqZuRkRFk1EgMW"
_II0IlO1 = "KDKB6SIkm78MhU5IpFZQtV82YjUTvXzSe1ILi7hT"
_O1lIl1OO0I = "KWl82H1gP5mLzPdD4vw48orUpNuRMAI"
_OlOOlI0l1l = "PG25MV0BSP3sd3WYSYzm0qYWQTdtjJvvJs4jdUymsNMb0CJb+n/i++FZ"
_OI1I1001ll = "+sCvzz7Pnw/KPqbRV8gCkSyKcEXKtp/++qAZ7DI6KJJ1a"
_O001l01000 = "jv5YzZW+9pyeH4NFvFojtkNkgAvs3PCUhmTPa33nO+jMAN3+"
_l1I1O110l1 = "JKpfrKyUdJeklcR6qZBrO7f1fqy7d/FLka3Jaf4dw4IzvbyE+0"
_O1OOO0I = "2O0dxFw3w0D0cu/xKDMcbSQUO3y7yqfOQtDzTU"
_IllOOO1 = "bn2IVEtkTvodbAhLk8UMDQdr2pT"
_I0l00OO1l0 = "BqBDzLIG+C/PbIHjCZ4zK3YZ8lEpTDBEFv"
_OOOI010I = "bBj8M/JrA8LctqluY3BITTswgOe+P"
_lIll0O0ll = "vJ5SUg9e8Y+ka5umUMyxDGsiamGedkUFtQ0UZ4IbpS8IM"
_I00O01O11II = "8hZhcs5hqrp6Gs1tvlLYtFX9"
_OOIII0l000 = "xciKwGQUCtb95JcYPj0EZa2jd6qPPqh"
_lI000IOO = "XhaVKKTEaxsdPvEawdQgpIT1gs/2C7uMz2nKQFEx"
_Ollll1I0 = "K1+zlQ9+8yisgM+Py2AnsrP+HZA+BYbxEfUbZ9+24MFibygJ"
_lIllll01I0 = "rEKAwdaawu6+g7TztM3DlhbPEimz97ro2CnUfKS7Iy5F"
_lOOlO0I1l = "iHEexsGsXetMaF8H3AZt3+ShXi+WI3Fgy"
_II00Il1II0 = "RbTJ/Fnzm/RwowRAunZe5J91H0C1u/zGdb4NgZFWzI0Y"
_I0Ol00O0 = "nRl+lt1Nntp3FPA8KAloEqAguz5QCapVduslBCA/b"
_l1OlO0l1l = "1xusofmRAX8PmVJ1ANAKD8hBz8hjNBYOIdxGy+VMi1+3Ow"
_OIOO1ll = "4DjOHQeeQbiRQxySU42vlsWGG/fdT6xU+qDQChlhdi"
_l01l0II0 = "vV08zwNyIYH0DJkrWuW4LocoHqmgVeSnkDG6"
_IOl1010I = "mZsZpXUycsvHWFN5n/Q3pZ+DzVodKQv90v0HFI4LdrRtos5XixRPVhq5fVZu/R9"
_lO00OII = "9Iu9lG3M+wohRD+dM2BwdrfeJSB4d2CBEQLk4/f/zrraY"
_l1100IO = "HQMMYqRbCYQI5nLzgOwMshhlN5wfj93u6zimNq3tQyoH/07Eln"
_llO00O0I = "fvIK5AMQUnyPxfugRMQcMPy1kF4SKtQ1Y//HV+TLpH"
_O10Oll0ll1 = "DPuAgzfgzjqL1VLCNcjyUTehH8u40tqpttg+Zof/S3t0Wn5kg"
_OlIlO1IO0 = "PdD+HtPlrPjFWU6kJjpQoD4+hNQBogyl"
_l00I1I1l0l = "TJTLWXVbVPKNljmUlwtMyVtQep"
_l00l0OlO = "TdAtu2lrt177EWfdE+1DdnMwdt+yEU0hmgDRhkSlPc8Vibsfi"
_O0I0000I0 = "rqb7IbQ48jYLOlYeIt5Dy+qdHjpfNwnrdCTYxU8CLilSH5d1CU"
_O1IIOIl = "1Mg71Xzsp6viRtc1gHpP8ETL3vB3z"
_ll1llIOlII = "2UJf27jwDqGO3DrubzSVqb3Yh6dbZ2DluyhcEIFH4p3U"
_IOO0OllOl = "giCjqc85vbBxtSxDwUu1uuET9ewjMAckoBVu13hG1LXyu9J"
_ll101Il00O = "a/S7PsrZetcFsRQjBOKoQNZnOrkk8e+hr"
_O10O0l0Il10 = "oT1yfGtaWhYgPf7BU7+QEzkbT4MMXstBsgsx+gnI4yeSPxHx6vF84p"
_O01101l1 = "F1uGoDVDV29phzH0Id/q5qaAzZ03QLjl5DCgo0lVpGUqzC7ucAeIw11CF"
_OlOO1OOl = "1DIzWsp8axCs3a0FtsJZ+zVXVUG0JcDZsJyc"
_IO0II1Il10O = "3Tm/xf/AEMrhUW0ZwzILSv7McNO9mY8lo0GEj35WnuT+90NMOvQ"
_OlIIlII0Ol = "MnN8xvvAL6y3/KMkVI9oNHWWk7Y22KZaq5HCwgJNr"
_I1II0I1lO = "aoeDfhMstemr85y0Spi1/LmKDhVV7OvjT6OGterizayjCbbx1ifj4BmO"
_IO011l11OO = "P13158R/xMPhrXsthCkGP0y7mLUWHPqmdvw2oZ/082Js5JSg4DFL4q"
_ll10ll10 = "KTVX2XzfDK+v8g7DGLmK3OBwMJW41JAcxYXwZ"
_IO1lOIO1II = "Y/feSLuBepX6dkyobc4xKbEYhXJfqAcRNL"
_OIlI0lO = "ON6bdh4NhNED+ekJKiOIhvwD7"
_l1Il0O1Oll = "y64Z3HO9H2zDhlZHWEWeaUW8dwNwQcsr8tItu5IOkcRCrZPB1Jk3iCNmSX"
_I1l0lll10l = "csuJ9Ya37f3SiZF5b01PJ6ejtZrplwWsKbfGepccVDi"
_lI1IO1IO1I0 = "nUUA0FeKwfbq/e9visI+zU9GL5BbSdxMTYnk7LDEIYESYYA+"
_IIOl0II1 = "XzRk8jwogNbWSu4tThCqt+GwoAt7kUNEJVqd/WrLWUNB6q/VozM0V8ie51D"
_l11011O = "cJWHJYfuSYL8GcCwdlBYKpKFY/hPwTi8fR"
_I0lIl1O0lOO = "F6bne8fIetFKcj0RrTl18OybW4EVnIYMqwtNktjW2vF4S+6fHI9YZbX2tS"
_IOllOIIO = "ECVeK2Gg/e1SfEnKsQwvigBIbYMo1xxlk25/8xAeamm/f7VJsptXhq6r5ormxqC"
_lI1OI101O1 = "prSWpYyDNrWV6VdrZA3W/EBmPir6kDS93hu4eaenbfKpUgtEF/"
_O0111I1Ol = "UiyXJjo4mcD5LH96oTBWGDmxHi3GrGSe"
_IOOO01O = "2Id26er8w7sUaUM3hR8Mdhvg4ke3ZcvC2muk1neLam5NphNM0iIhczx3"
_II00l0lI0I = "SBr3DtVJCBznHWqOiSbdQbUBvZJIbf7ZF1284c+SKe4L"
_Il0OOI100OO = "Dv5EXyRbpSNaObk0TEMPfYyKF"
_lllll10O = "RUxzzEfY1am1eNPRf2HaPTnY"
_O0lOO101I = "YiqrGLDEcA90+1OAIODk/sxgX+g2J3S8CPUkzI3pRHUJQA8ahMU7mDi"
_I01OO1lI = "5E44kCBzL5q0nG5FpGyLp6MdZPfK5+Ru"
_I1I0OOI = "seerjfaQi0xo/1jSqd90TZo1MvLnRkHwwZVBgBTGYrPxJQB/x9iq5MnyEF"
_Ill1I1I = "4ndhqQosI2uMSFwaawlrXIjnEKTbn32b6c7PsZBBBpgqq/GXysJ3S3"
_O10lll0 = "Ik3cHUwU/lF/Cbwdu9TeBXWWVhw/kFP30G1woEdRuSDhPW"
_IIOO1I0 = "w1R6p3xMw9k4MV6b5rzeLfmtEpTegg/CsE+p"
_O0IIIII11O = "2f1yOojB6HhAC5BR09Qrz3fMQRo1nfPIWJQMqmDHSM79"
_II0I0lIl = "1PmNdy3zBl/g2nyyyvbTLOM6"
_lOIIOO0 = "4ltGnldc1IfWp+Z5Kxuuwgqfx2"
_Ill1Il1OO = "Ac16gNLLQPpaYPAW1FZZzuny+5JeDzBjXSr1yj2Wynm8EjTDTsamkciQR+S69jo"
_lO1ll0l0O01 = "iDd78SJVDZAXogWgs2SzACxjxeBFTqRBzWkpOP5BSTM"
_OOII0110l0 = "a6H6MRYRmb+Lhuy2fZ/ghh+KKxORiRU"
_I1O000I = "6ht9JWfaEmPfFZizwV6VHjBwthflf6N5zpL9vA+XTwoH2xvvPfeH"
_Ol0O1llOl0I = "XG6gd3bpWhoTfS0Bq4UiE5rAnUsLVn6Hg1TfAJ8tN"
_lOIOOl1l1 = "l00Ywf7YyeBDyaxvg2ca/Gh/4"
_I0O0I0O1I = "9ej4/zClOkJ+U8czO4HRCFkEcei2SWDZ7PQfqwfIw13v"
_OlI1O0O1 = "13qafjnzNKvUJ6MqByvpW5AppESZ2RGUNgHh0/aVy"
_lI0lOlIO = "N4s7t6s4Bk+i448+hRxdhkNUqlch+cXSeKuf7AkxzeY2ZdTqUYeO6eNaVm50b"
_O10101100 = "uREP9ISw+7oyk2AEe8HUbNUW+ITWB1H9fdW1"
_l11Il1lIO0 = "CocvKB0PfUUPsaj2vlY="
_OlOIlIl = "EfHQFPevQXk98lCS9a77dBe0CCp"
_O0100010lI = "/qVr8JwClG0q0C/eAE84Qyor99G9y+LsRwiHXSh"
_I0l1Ol0011l = "+Fvl2nommp6MCqxJ9k8e7xDivps9eJ680"
_llOOOI1l0l0 = "gHjBc051Yg7u51JxdkQCHT7Xb0"
_OOI10l1l = "4dAd2o4ab/i65sE8qMUq4OZ9ezh80E0H87T9YXI9a2ef9HkM6/e9pgTxfVYWU"
_lOII0Il1Ill = "LCzbVxHgAFJ4CT6IYMImpCrtin+elKk7I0t"
_IOOI01OlI = "dcg/XwA+gwLSfxMwH00v5bZ+EtlbT8q1NJBqEw"
_l1100l1O1lI = "NeenDkIcGKuY/Ne8HHDxM8dtKivp"
_l1IIO1Ol010 = "KquAF3bQ9SyuGrB3L6ZkxAvr"
_IOOllIlI0lI = "lpz0u+M74A7nHTZ+4z6DOV7nZalI0UPizyjEI2Jkw5L97pZ+uHYpPWYPp5YSp00"
_l0lI1IO = "BjzhfoB+bINgM5t1KPnHBdYC"
_OI0l101lIIl = "tZYbhe/TXIOj+b/s2lDyXz+WRx5eqQyp57z"
_I00lIl1IO0l = "hX2zzuniZURYQAYlU0/xM3hI9LThz"
_lIlOOllO = "Ux/nYbdJNX6agVtCBpcRFBTaY9CWLVxJy"
_l1I1O00 = "CX4mkzp9Bilz9F3GB2wdToReDC0K/iH"
_I1OIIO1 = "lZGh+f0REV1nm2IFfILnNyO5cq6HrSpP330lvKinxn"
_O1Ill11O = "v7knCAg5db127ptV0UQkemU/CGS68PzbrC9RMS0rxRubqvvGaIxo+Dk"
_l00Il11IO = "mjhuD8UaoOyeRzUa7TubCgw5g2G7/R19XfEhbT8Cz2eAWQLreIokQq"
_Ill1I10lIO0 = "J9xGaGBYsqLJ3TiQf7WnKrcHhw3x3/zw"
_l1IO1Il = "PyAaJzADfPGT7jZEt2p5Qperms4"
_l01OOl0O = "wMeDPlbwbT2pfobDv6b8itvEZBy8J4fq"
_IOI1l10 = "5dzKq/nAOhbJipMe3/kMxXmC6UQl265dbh3yPDwZywFU3MlsVcG0go9V"
_llII101OO = "h9F69rqa+epuv+kirjfHafw2i6oh3"
_II10l0O = "hf64OMm/2UOEqcW/9mwD/V+DJ7R9T"
_lI01lO1O = "G0jHHU4ZGDmAqAm2QEol6RH3i+WxbjWP3FeDNklYctRBIqKT0KUuA16G"
_lO10O0lO10 = "okJXEfusj6VOUbW2Z+Mu+lci2ZKx85oHVEvTOb7X+IZuf1xT+e"
_lI00Il1l = "NI5mx9odx3mUcZ/DimEIKLdKWzrDzB"
_ll0Ol10I = "nKZLzaYm9WC/gyZ14vO/kmFxNIsy5+v49tzr9"
_IO10lII1II = "YVaotmmhobllryDrA9WUwhfAzItxWN9P96Ed5EFTD//qkKKa+m44s3gYn1kZ"
_OO1OIOO0 = "vPEcjCchFVrJR4Aho8zwO94/3"
_I10101IOI = "FzodpuDK+FhxlXKRb2eJmz2txd8QyqOkf/NOLn8/RxeswAphTdPsAl"
_lIll1I1O0Il = "4Y220Pgq+lyM6EkC1EWGLF6VU4oxV5zSziu1xETTSMfRNM48/h1lawc"
_OOl1l1O1 = "MQwwK2+tldSPrmVCc1IHBY39X"
_O00O01Il0 = "ndSBKHcXrF5xbgkpDFiYJjRteVcEd"
_l0lOlO10I = "XanG2hrj4APsOWhaHb1XZdqjEByTKHBBhzFgCZ4gqVopBZT0dI4"
_I10O00Il0I = "Pt2C4gwdOdF3Wg34cGJKnbhBwBAzSxRLiFpZoB5hPTMRyYOIvX5"
_lIl00OlIOI1 = "A1sRuXadFkClTULRaBI4T9znL4dM1qeKVSFk39GqdQ8a5UNQlyZlq5bfyhZ3sM"
_II000I0OOl = "Wdu/1Gh5YaOHKPkOsfW4Nmp/9Htt3xMYUxnS0w8"
_III0Ill = "JOX6C2va8nIxoX7iYpTGg8YzKKVuwi5RhZ"
_Il0O10Il111 = "cIp1HxzPdBDZG30Atr7/dlEx+G9ugf+4PbsThukmK2DTkFtjNQr6wb26A5v"
_OOIOll0010 = "LHEYolvTZOCdJcvXL1I/NA1r+3JT0IVB3Bwbc+Cmfdn1NscTwQT330"
_IOO01O11IOO = "B/mUtsmh3veOe89AiXhiFm71N4fQOy5Ub85j46tn62dd8TVx45KeUOrc+A"
_OIIOI000OOl = "Xk+wDFHBBTJ5hyJS6FQAp3azghi8eLvptsZ/DkQzLbBLubfXdZMKr80"
_I0l0I01OI0 = "2oNTf7NHYyZhkvl0+jXfTLWEKVBB8nVw7FKccsbdaRJ4JdaV1uZJAHng"
_lll0O0llll = "XPbtv8aAabmFjcqMvz27MfXqXxg6ScRtrjCu+VlxAS0BGwoUiBIJVnK8qp"
_OlI1ll0II = "RbAQLErx3+sRc8JPHJvM6AURcNJ1d1+LP"
_IO10IOO00I = "lQYECpYTIPpLCIaJAAbgnV9y69/rW3tWBvEfuUb1"
_llIIO0010O0 = "0EemBgDB/SW/IJiWPGKtSwHrLq"
_O0lOO001O = "EfcHZ/1RtF4j41qFPKyyJtMBEwRCZ3Iz4c7WkR+GIZroWljtiC/"
_O1IO1OllI = "wdMjw5Ms/0kWf/Sb06nBR5PamrT2DAa6JoZBAvTlj/E9fO2rfloA8GuX"
_IlO1l1lO = "foSjM1Te4KtNKCYJbuSyVd/nf"
_OIIIl0l0 = "fTzJLzNbv4TcwJJFhrcE7qIf5huMvsXD3EEdWO5lBQ5IGA"
_Ol00O000 = "q/SoEQeMWH93R4J049E2fwWafeW/c3/Fu+q"
_Oll00O0O100 = "FUPMZ20jwlZ4p59DC9hS6kgUwtIEq4u8XVPKSISkiIPMW6otTmF7y/"
_OOOl0l1 = "dmhmSqI6DY5NKOKQabSwhBhi"
_lII00O001 = "wfWx7JVBjbu6RGgjxPXcaDMbfwxuk3NFU6kAVNiLiK0GEJVntY"
_OI10I10OIIO = "uP6h7QFMJdinGxRTxBXVS1yGMsRHwdT2qULIKm5"
_IlOO110I100 = "quX5Na5ZLJMonD0V3ag3pm3k62jALgMh5T3mSGqJthadvF+87"
_IOOO1IlOI1 = "80tSFhKChxg0by+keh9qPKyDzwgo7XJ04gun2480QW6/D1A8G0ne"
_O10ll0IOO = "38RHu8Q0xho/wvwN15nEwi7K6aDpWNVbw8E2rJw7EKuXgNR"
_I1lIlII = "quc/9UmazT9dpls7I6Kg5ZavpJqf7VI7PyRBUf+3Wper9A2OyzBdTON"
_lOI01l1I = "sr3SBlGzTXZGoIPXjt/uOMmmXwbBDjacP"
_l00l0lI01 = "ullD3X9+BTXChRfnVpWV0zhOux3g"
_lO10l1llO11 = "SbsJeL+t9G8plJce4++p8GmrnuVfw"
_lIO0lII1 = "lfyWr3sr7VBscp3yjUs9WKqDjk6t7KcWC8o"
_IIlI1O0O110 = "4E6MTI8K8AsoLy7punywIwJ1wp0OwnwIn1ihX"
_OlOI00I0O = "E6hFUHW8jCtq5YlzGznWFKMZtUm/+nCpPvb6YinfvYT0Xa/vsclXD"
_l10IOIl = "5n05XY8aRS102JB6hp7BXylPsnLyH0dSXjeltcsZ2sB6zAS69e"
_II10IO0l1 = "CaB66R+7HatPqR6meybnKXyXuC/2bx076WV+N10nAkbQpTFtMHaiylW1OTZ"
_O11lOO0 = "JKb6a1k5ypSLf5TGoB5jw+Ub2uaAFmgst9LwCLp0nIrvPFPYIU"
_O0l1OIOlII = "vUTGYCvOX5YK6OLUxhnTvLK2OKsr8BfTrTHC+Dp/MNHRGYX677GQJW62xr"
_l0lOOIlI1 = "RVro9S4kuQFyss2PMXVrhQgo41gm/hTm4wADAdXUB7rSCj3D1C"
_lIOlO11ll = "snm9lWU1DFg1QsKJ3oYk0OZwYnd"
_IOI0l1IIO = "HwNxAtRjxQAIBLZWWVJXumBGH/JS5uzgtRJDJClb6CQpNRB1UCgIu"
_ll1lOOl = "m3NXuSQnn48TszAUnerKH+IJOaYY4FrnS7xWn5"
_lll1llO1OOl = "a6nfR/63rvKypwDgdb0DCi6EctkfMHmgcupua9Q1L2fch9Dga6LckC"
_O1II10Il = "48iriWqlM9906QUYKLDJLO9VAYeZv14+Gqspf"
_IIIIl0Il = "xKCxMT3DN+OvV2vNjQZiPgLWbE/c3TRk3UiHcU"
_lO1OIOOO1O1 = "so5w6yJUHUzfdLiiII+xlIWv"
_O0I1Il0I = "kazpseTwXKyd/sGCRDFNAh2rjzTOmgsTwrr"
_llOIlI0I = "q5Gnd9SVccJ8OTAGj13pOTC/98fhnpt2v6/jgVOmNaiGIto+HF"
_O00110OO = "Eb57z7YdTxpC6fqWNTpolcGLOZeCfraJF0ivKAnCGmYt2iD8W+v"
_OIl01I0 = "tZD3zyzuOloqLgl5PkK4bCImTSxdctp7AwkjEz09"
_IO0lO1O111l = "SXAUsK9bRjP5YNV07FcUWWmN916Ze1mS0qJWGVODP3pnYwJUTAGvM"
_lII1llOl = "51CZUJPfHPN/uQjo2G+AO11BP4TY4v2xvRmNBoWWxC7jgDQ5G2f/Hvag+56b8"
_OO0I1l001 = "SlVXs8rk7+FHg50HjsQ/r1BgNmUf1rvY3vSHlAR8wqB6Wx"
_llI0lIOl00l = "/LqLGYUTV+/S7xglhEQRBH9E425bq6NuJbFRjpQ9RL9ZQVS"
_l0lI0Illll1 = "DX5RVKAhEYijYFs2jBOUc11DEv8jSv"
_lIlOO1l1 = "LCCH5EAt3zZjc2/P+k8eYSXJO1xjOCTREnTUhGJ7qNRuxccJ"
_I1lI11O0OIO = "yEVIiJfzYqdtz8VQXaprZprfwOpkbegr4IAa8Chlymner"
_IO1Ol0OO1l = "IZPXXtQC6U5SordorvfoIBevUNlqa+NVcbT/QPohqXxaCEf2MGg4Mfd2"
_l1ll1IIOO = "YI8uoSK6PH+/BFVKaZC4wZt/tV5Pd0V"
_O00IOO0l1 = "F9KNGTCfzWXaeM4W97YRf6FGspP7KeUx1"
_O01l0lOO = "1PO0Rq7uODW8NHu8GUuGXiTSXPdVAD7"
_IlOOI1l1OOI = "vRPM4NDTE6EJvfV1K43a3+dlqhRVMi5ueG9NLjdV51T8/6iIyvNREm"
_O1OlO00OIll = "Xjw3TXgWNHXfDIs4YyPsRPRldRcgzqio2kqm0k"
_OII01I0IO = "zQrSDFfE3rHdpVmlNbXS1wDrpwWky"
_Ol0lOO10llO = "poleE5OBD5fQR+JWZ1rHxampCc3370Uy89OfTzHJoJiqvhSp9KQwbh6Tun"
_II1Ill1OO = base64.b64decode(_Oll00O0O100 + _I10O00Il0I + _ll1lOOl + _IlOO110I100 + _lOIIOO0 + _IO1Ol0OO1l + _OOOI010I + _O10ll0IOO + _llOIlI0I + _OOl1l1O1 + _lI0lOlIO + _I1II0I1lO + _I10101IOI + _OlOI00I0O + _IlO1l1lO + _l1100IO + _II10l0O + _l1OlO0l1l + _l10IOIl + _O0lOO101I + _O0I0000I0 + _IIIIl0Il + _O00O01Il0 + _IIOl0II1 + _OlOO1OOl + _l01OOl0O + _O00IOO0l1 + _IIOO1I0 + _lOII0Il1Ill + _l00l0lI01 + _l1ll1IIOO + _O0lOO001O + _Ollll1I0 + _I1lI11O0OIO + _I01OO1lI + _I00O01O11II + _OOII0110l0 + _II00Il1II0 + _ll10ll10 + _IIlI1O0O110 + _OOOl0l1 + _O1Ill11O + _OlIIlII0Ol + _l11011O + _llIIO0010O0 + _l0lOOIlI1 + _I10lOIIOOO + _l00Il11IO + _IO1lOIO1II + _O11lOO0 + _IlO1lO00O1l + _III0Ill + _OlI1O0O1 + _lO1OIOOO1O1 + _l1I1O110l1 + _I1O000I + _Il0OOI100OO + _IOl1010I + _l1IIO1Ol010 + _lIll0O0ll + _O10Oll0ll1 + _IOO0OllOl + _lll0O0llll + _O1OlO00OIll + _llO00O0I + _OOI10l1l + _IOI11lIl + _I0lIl1O0lOO + _ll1llIOlII + _IO011l11OO + _I0O0I0O1I + _OO1OIOO0 + _IOI1l10 + _OI10I10OIIO + _Il0O10Il111 + _lO10O0lO10 + _II0IlO1 + _OIlI0lO + _lOOlO0I1l + _l1100l1O1lI + _O0l1OIOlII + _l0lOlO10I + _IOO01O11IOO + _lIlOOllO + _O10lll0 + _lllll10O + _lI1IO1IO1I0 + _II000I0OOl + _OI0l101lIIl + _l11Il1lIO0)
_lOO1I010I1 = _l1011OI(_II1Ill1OO, _O1IO11IlII0[0], _O1IO11IlII0[1], _O1IO11IlII0[2])
try:
    _l11O1000O = _lOO1I010I1.decode('utf-8')
except Exception:
    sys.exit(0)
_O101I1OI0 = {'__builtins__': __builtins__, '_O00I0OOI': _O00I0OOI, '_OI1l0O00l': _OI1l0O00l, '_I0I00llll0': _I0I00llll0, '_l1011OI': _l1011OI, '_OO1IIO0O': _OO1IIO0O, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': _II11O1I1l}
try:
    _l00IO00I10 = _O00I0OOI[5](_l11O1000O, '<s1>', 'exec')
except Exception:
    sys.exit(0)
_OO1IIO0O(_l00IO00I10, _O101I1OI0)()
#PYG4E
