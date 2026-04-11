#!/usr/bin/env python3
# Protected by PyGuard v4 (pyguard.akean.dev)
_IlOO0l1I010 = bytes([28, 203, 255, 109, 89, 182, 66, 5, 136, 46, 73, 147, 132, 177, 210, 222, 47, 169, 188, 164, 99, 144, 116, 86, 204, 19, 43, 64, 109, 143, 195, 36])
_O1O0IlI = bytes([123, 0, 204, 108, 202, 13, 131, 254, 23, 71, 63, 97, 254, 49, 204, 104, 228, 218, 241, 114, 31, 8, 81, 168, 55, 99, 228, 32, 66, 197, 203, 249])
_lIIlO111I = bytes([29, 116, 208, 198, 246, 82, 176, 126, 118, 137, 31, 42, 176, 134, 64, 13, 14, 19, 116, 41, 136, 211, 95, 215, 59, 79, 89, 207, 112, 95, 101, 237])
_OIl0OOOl0OO = bytes([253, 216, 66, 235, 226, 20, 83, 122, 103, 50, 58, 101, 175, 185, 237, 236, 251, 119, 169, 48, 0, 77, 231, 111, 16, 96, 137, 206, 186, 223, 122, 16])
_OO0I1I00lO = bytes([97, 31, 210, 165, 178, 198, 59, 250, 47, 57, 150, 192, 154, 148, 82, 71, 101, 161, 153, 211, 8, 38, 66, 43, 172, 24, 213, 204, 113, 167, 251, 80])
_IOII1OO111 = bytes([146, 76, 24, 104, 13, 118, 19, 133, 24, 161, 246, 161, 1, 217, 26, 14, 112, 143, 119, 73, 193, 212, 130, 244, 178, 202, 16, 71, 119, 251, 6, 81])
#PYG4S
import sys, hashlib, base64
_OI1OlOl = type(lambda: 0)
_IOOll0OI1 = (__import__, open, exec, compile, type, getattr)
_lI0110lII = _IOOll0OI1[5](sys, '_getf' + 'rame')
_IO0I00OI01 = hashlib.sha256(bytes([240, 87, 180, 234, 94, 247, 75, 3, 200, 93, 46, 0, 198, 217, 131, 244, 29, 142, 203, 190, 117, 156, 70, 67, 119, 103, 223, 159, 165, 10, 68, 206])).digest()
_l0I01lOlOO = hashlib.sha256(_IO0I00OI01 + bytes([184, 110, 95, 71, 174, 0, 130, 189, 184, 197, 80, 95, 17, 213, 180, 62])).digest()
_Il10Ol10 = hashlib.sha256(_l0I01lOlOO + _IO0I00OI01).digest()
_O10l01lIIll = bytes([169, 12, 40, 28, 242, 171, 173, 133, 8, 252, 66, 184, 192, 216, 159, 98, 222, 19, 190, 178, 125, 30, 166, 232, 10, 236, 45, 177, 149, 85, 205, 214])
_OOII01I = hashlib.sha256(_O10l01lIIll).digest()
_OO0O0OI1l1l = hashlib.sha256(_OOII01I + _O10l01lIIll).digest()
_lIll0lI = hashlib.sha256(_OO0O0OI1l1l + _OOII01I).digest()
_l1I1l10I = _lIll0lI
def _OII1O0l(_I1O0011011):
    _I1O0011011 = bytes(a ^ b for a, b in zip(_I1O0011011, _l1I1l10I))
    _IlO1l1Oll0l = []
    _lII01I0101 = _I1O0011011
    for _ in range(8):
        _lII01I0101 = hashlib.sha256(_lII01I0101 + bytes([143, 251, 230, 162])).digest()
        _IlO1l1Oll0l.append(_lII01I0101)
    _OIIl1OOl = [(b % 5) + 1 for b in hashlib.sha256(_I1O0011011 + bytes([80, 222, 106, 197])).digest()[:8]]
    _OlI0OOIIO = hashlib.sha256(_I1O0011011 + bytes([49, 72, 183, 118])).digest()
    _OlIlO00O = list(range(256))
    _Ill1101I0 = 0
    for _IOlOI011I in range(256):
        _Ill1101I0 = (_Ill1101I0 + _OlIlO00O[_IOlOI011I] + _OlI0OOIIO[_IOlOI011I % 32] + 218) % 256
        _OlIlO00O[_IOlOI011I], _OlIlO00O[_Ill1101I0] = _OlIlO00O[_Ill1101I0], _OlIlO00O[_IOlOI011I]
    _llI0OlO = [0] * 256
    for _IOlOI011I in range(256):
        _llI0OlO[_OlIlO00O[_IOlOI011I]] = _IOlOI011I
    return _IlO1l1Oll0l, _OIIl1OOl, _llI0OlO
def _IlO0O1O0I(_I1l1IO10, _O00ll0100OO, _OO10OIOlII, _O1lOOI1l):
    _lIl01O0lO = bytearray(len(_I1l1IO10))
    _ll11O10O01l = 8
    _OI10I1ll1 = 0
    _I1OIO10ll = 0
    _O0lOI00I1 = 0
    _IO00I0O1lO = 0
    _OI1IlIIOl1 = 163
    while True:
        if _OI1IlIIOl1 == 93:
            break
        if _OI1IlIIOl1 == 163:
            if _OI10I1ll1 >= len(_I1l1IO10):
                _OI1IlIIOl1 = 93
                continue
            _IO00I0O1lO = _I1l1IO10[_OI10I1ll1]
            _I1OIO10ll = _ll11O10O01l - 1
            _OI1IlIIOl1 = 234
            continue
        if _OI1IlIIOl1 == 234:
            if _I1OIO10ll < 0:
                _OI1IlIIOl1 = 84
                continue
            _l0OlI0OIl = _OO10OIOlII[_I1OIO10ll]
            _IO00I0O1lO = ((_IO00I0O1lO >> _l0OlI0OIl) | (_IO00I0O1lO << (8 - _l0OlI0OIl))) & 0xFF
            _IO00I0O1lO = _O1lOOI1l[_IO00I0O1lO]
            _IO00I0O1lO ^= _O00ll0100OO[_I1OIO10ll][_OI10I1ll1 % 32]
            _I1OIO10ll -= 1
            continue
        if _OI1IlIIOl1 == 84:
            _IO00I0O1lO ^= _O0lOI00I1
            _lIl01O0lO[_OI10I1ll1] = _IO00I0O1lO
            _O0lOI00I1 = _I1l1IO10[_OI10I1ll1]
            _OI10I1ll1 += 1
            _OI1IlIIOl1 = 163
            continue
    return bytes(_lIl01O0lO)
def _III1ll11(_O0OlIl00OII):
    _IOllOO01 = hashlib.sha256()
    _II1OOlO1lII = [_O0OlIl00OII]
    while _II1OOlO1lII:
        _lIOllI0II = _II1OOlO1lII.pop()
        _IOllOO01.update(_lIOllI0II.co_code)
        for _I0IlOl010 in _lIOllI0II.co_consts:
            if type(_I0IlOl010).__name__ == 'code':
                _II1OOlO1lII.append(_I0IlOl010)
    return _IOllOO01.digest()
def _lOlllOll(_Il1O00lO):
    try:
        _IO1IO1l = bytes(a ^ b for a, b in zip(
            hashlib.sha256(_OI0O1IOl + _III1ll11(_lI0110lII(1).f_code)).digest(),
            hashlib.sha256(_OI0O1IOl + _OI0O1IOl).digest()))
        return hashlib.sha256(_Il1O00lO + _IO1IO1l).digest()
    except Exception:
        return hashlib.sha256(_Il1O00lO + bytes(32 * [255])).digest()
try:
    _llII1lIIO = __file__
except NameError:
    _llII1lIIO = sys.argv[0] if sys.argv else ''
try:
    with _IOOll0OI1[1](_llII1lIIO, 'rb') as _ll1IIll:
        _lO0II0O = _ll1IIll.read()
except Exception:
    sys.exit(0)
_lO0II0O = _lO0II0O.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if _lO0II0O[:3] == b'\xef\xbb\xbf':
    _lO0II0O = _lO0II0O[3:]
_lllIIlOOO = _lO0II0O.find(bytes([35, 80, 89, 71, 52, 83]))
_O1Ol1Ol1O = _lO0II0O.find(bytes([35, 80, 89, 71, 52, 69]))
if _lllIIlOOO < 0 or _O1Ol1Ol1O < 0:
    sys.exit(0)
_I1OI111 = (_lllIIlOOO + _O1Ol1Ol1O) // 2
try:
    _IlI1OI1 = _IOOll0OI1[3](_lO0II0O, _llII1lIIO, 'exec')
    _OIlI10O1 = _III1ll11(_lI0110lII(0).f_code)
    _OI0O1IOl = _III1ll11(_IlI1OI1)
except Exception:
    _OIlI10O1 = bytes(32)
    _OI0O1IOl = bytes(32 * [255])
_IIO0I0l10l = hashlib.sha256()
_IIO0I0l10l.update(_lO0II0O[_lllIIlOOO:_I1OI111])
_IIO0I0l10l.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(_OIlI10O1 + _OI0O1IOl).digest(),
    hashlib.sha256(_OI0O1IOl + _OI0O1IOl).digest())))
_IIO0I0l10l.update(_lO0II0O[_I1OI111:_O1Ol1Ol1O])
_OII11IlI = _IIO0I0l10l.digest()
if _IOOll0OI1[5](sys, 'gettrace')() is not None or _IOOll0OI1[5](sys, 'getprofile')() is not None:
    _OII11IlI = bytes((b ^ 195) for b in _OII11IlI)
if compile is not _IOOll0OI1[3] or exec is not _IOOll0OI1[2] or getattr is not _IOOll0OI1[5]:
    _OII11IlI = bytes((b ^ 14) for b in _OII11IlI)
_l1OO0l0OOI = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != _l1OO0l0OOI or exec.__class__.__name__ != _l1OO0l0OOI or
        getattr.__class__.__name__ != _l1OO0l0OOI or __import__.__class__.__name__ != _l1OO0l0OOI or
        open.__class__.__name__ != _l1OO0l0OOI or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        _OII11IlI = bytes((b ^ 156) for b in _OII11IlI)
except Exception:
    _OII11IlI = bytes((b ^ 156) for b in _OII11IlI)
_lllIOOOIOO = sum(b for b in _OII11IlI) & 0xFF
_O110IOIlOI1 = _lllIOOOIOO
_OII11IlI = bytes((b ^ _lllIOOOIOO ^ _O110IOIlOI1) for b in _OII11IlI)
_I1O0Ill10l0 = hashlib.sha256(_OII11IlI).digest()
_OI00I1IO = hashlib.sha256(_OII11IlI).digest()
_OII11IlI = bytes((a ^ b ^ c) for a, b, c in zip(_OII11IlI, _I1O0Ill10l0, _OI00I1IO))
_l0lI1001 = bytes(a ^ b for a, b in zip(_IOII1OO111, _OII11IlI))
_lO1lIO1O1OI = _OII1O0l(_lOlllOll(_l0lI1001))
_O11lI011 = "1cwlOGzdoVYS8IFuDjM3mBmd0la7p3NdIf2VV"
_O01O0OllO = "PLXmjmaUH14ltfM1tRq72UHMxnv6VxMyDkJjW/QoFC69YzQ/e"
_I1OO1lO1OO0 = "gXKiogMEF5U3ZfAnLjZBVZg/PQ"
_OI0l1OIl1O1 = "uJIuAU28WpIn3NBIRLnXcoAqQ8kyp+SnzUxlwVkUoaEFViA"
_l00OOl00l1 = "jkzfhrvyM28O9uGNCt4VkQ1sSX6rWxN8c2n"
_OlIIOll = "izWxDOZOHKAZWOgteKnL903sQJK6GBDlHWb8"
_I1O1ll1I = "LAsBemlRPD79uTgrdNwtbbwH8I7nME5tMXBIVjsUEF846JU6"
_lI01II11 = "mG/shcf0j3APRLGcWrO0wUJ+e7D0A"
_O0OIlOl1lIO = "f6dbR+Y4kI6w67OYlCLmquRBvJNfTJZppPyMZp4KN7GL"
_OOIIO10Il = "rF1h0iU4cU6UXGVBKN47bejZYl24kRVujeFMT0TyGdVMh9MQMIJttpLOPoE9a2"
_O01IlOl1II = "+jm+QQTXxTS5BqZth2uRlj4rR0ppPiL"
_lIOO1l010O = "x2ihlidXG49rrY3d41N0HIKptbluOfoqZ"
_l00IllO111l = "lqL61/qPcGqPca01GKUS3dwpoatNWv+"
_lOIlI01OIll = "GvffM/dhGtELQ1XKAfk7J9uu2rMl"
_OlI01lI1I = "SrBiiTBdwNlBMk+rxSqrtQ0NeqbIFP"
_ll100lO = "oYwHKnwFcxvG1eCZGiSKPctSCKBfHC5AgPYayCGENkuKqA2ovNV1aSG"
_lOl0101 = "vNOEoaaLhjmh1uCpiOhEtLBzZD/B+NaEpt7+mQQ5xANJWPfNj9KsbnX"
_Ill0lOOI01O = "tQgQhzXfA5IbC6EuHOOUeqZ9O"
_l0OlO0O1 = "R5KGLO4UIQYfyONv9hFchGji0Us4V1"
_II1Il0OOlI = "YsFq6GCSBv+ISiBbygJjsAqIyABz89tdDffdGVuhvRRD5JQ+"
_llIOll0 = "2ECK3hh9oOKBLdFlRwhzHWsE3rv6AaI+iJlbsSZHH"
_OOOI10Il1 = "37ga1Ol7DtiRiwPCSTqK50RHLeCN6X3a8kIP9QyjnD+IuFHz8"
_OOO1lOlOO = "PTzocsofS5zcKHc6jPl9IQkjV5L3ZT55I3dwVW7Jvyy5lwpmHXVuPj6i89gftkt"
_Oll10OI11O = "UKkCzi+faAEeqrDpUfxYNXplJkTH0KWE7HyHlH7+0F/gt2PJIKYfmTt"
_OI0lIl10lII = "5Q0CJT5r+7HtMA4mvXrhQq4UhpqvCMkorH"
_O11IlOIl0 = "21EtBfu6hzYsS1epCT42Cv1w+irCIYMyR"
_Ol1O001O1 = "liFnpsV67nz8sBtSmKVXUF3pwcH491u9X5AKnkAjrfv5wwYGuPr23Xy"
_I0I0llI = "z+WAohihBQGqKe70XndU8LixSFBSzFOzwE24XRejjCpNS5RYPHkgPFR"
_l010l01O0 = "Nm3IaEkpHTEmQRqTCXSRpg7vja4nbBisrjK"
_IOlIIllI10 = "8GUXUON6da9Ln+hKrccpRYCBNv4CfZzqFJ4IYHj08MufVOHWUxu"
_OOII000l1l = "T3XtlSCTqVs5n/fmpAvRLd0ev3+tvXYV5wSnUsULjImtaesS+F9B"
_OI00lIl1Ol = "n1rA/j0/OCt6a0lEuamvSwlmyYGkBuCFtIMH/r7B1OMN6whQP+sWThQ/B0"
_IIlIOIIl = "JbrbczntstPWRB+A+5pLCE9k98/FWl6zfHKxIa"
_O000I00O00 = "kxMpk36WacGUhY0RGxvRecFEYNxf5+LL29PyV"
_I00OI01 = "5AV6aC8oWi3SW/ZI8eOYrOFj6/hYfKUwVb3Tj5dZNKkAmi4Ze2ZXON"
_II110l0 = "FwJY1bKNIIJ6vuyzVJNRZw5ALFw+ZvUHnMgwmUW9Ioliw"
_O000O0II01 = "ndHX6yQfEQe8wwjbPqluodOptNNmG83m4Si7vB"
_II0II0O10 = "JnRdy9cXeU1AENY9SK73Rd8T9xwmKQ5nYLaV"
_OO1O111O = "vRXA3+l+KJCESBizLDCAJaYuO"
_O1IIOl0l11I = "j5SG9Xl03FMdNBv4XZBBt07mkXOUogpvhSmjf4wFllEOlniE7fAthU+"
_OOl11IO = "dR8h829BxlESSlz/NcwEFdtTiOKRJ00wcsZn6jF1e2YD1nPp"
_I1O0lllI = "Rpspma3q6gWGLney95LVWLXBl4gOz5nWWGhpR9"
_IOI1OlO = "CAapF2V9DmNndFgkrR1VMKdTW56df278CpY8FqFsFw"
_l1IIl10I1l = "TqzV6/TxdwnMfq4w0gZS9BWs6FC4sz5qN8nxV0lNY"
_Olll0lI11O1 = "mambxJGKFhV+tYo6/aXautm4VpS"
_IO0l11ll0 = "O640fs1fyesyU44CdpFjIFAtgywmqDvRNIjHZhR54m"
_OOOO1l1OlIO = "YcYDg/kSwJogiXVsQQG5yRoCLntSBJY5KSdI2NjOthNbJejQWHmdWxvTaMGq"
_OOl1lO10 = "i3sEeXJj/Ek5xsVwzrexUVwI3UrJRiYvdvO1PkeI0UfWfNV7yLj0J+jd"
_O101O11ll = "su3PUMFEN+5JBqrzutGkHrs5h4C6ddx3i+KJN9"
_IOl01OI11O = "05bEcWHxewmUBHVydTCS4++3vT69hiMkixpOtB4Awewd6BS0NZfa9X3lyRvkQh"
_OIII110 = "QiR24//wRt/aThWagibf6UmeWHsUFbI87fBfIGu5Ed6HLxt9OpgmrXnNYGE"
_ll01O10O = "1UnnyFQKlnQP7GNsVwVt2MddvQA"
_lIl10IlI = "kDJXQjUQmImYdtv359gxDyFTsam"
_O011O001 = "Yq5hBX2878lkHZvd92gc8DxZVFd1Z8F"
_l1l11IIIl1 = "pWA01Y/cako9T+0LlpuiEkYK21vz"
_Il1IOlOlO = "sbVmpYrFb9OXUIaPr9AT87LpVr+jO9HIlLRQ"
_Ol10IIlI = "xoBKNBPOppeXnEn5KTkgyp3BNpmj//q4Wk"
_IlO101l = "0+EyJFw6+7TXBqVY0Atj6hzm"
_llOlOlI11O = "e6Gu5v8iUcBWPbZGYjk3dqJNAJp"
_OO1IO0l1 = "nnY5wakb9ounj07Nd0jhxMoS5nxHH3Z"
_lOllI0IlI = "DOt0MWCfj+zLwgS9z/NfFqeWHSRE8TLbnZVwtAYGurtC+56JZPHC"
_l10l1I1OO = "VvPNOAbzi1kmBxPz/upl+gkBRIbzRmJAsPOXxV0OQ75h9CPvXiiozzQh"
_I01IO0llII = "tVDMAcEBbY/YhAga8tDL0Tpg2h1"
_lIOll0ll1O = "Xt8NCRj1eFMCS3lI00bP+uhKZ1ywLLrK9W77fb37PZNM3OCpS"
_lII1IOllI = "0JJQWOVAmHGGeTJ6TBNlS84+c0cJKYCmLr6"
_lIO001lO = "pIasACjGyQW3N6HdFhgso6g9ZztQA1+XJSfC9iWJCagQd7lDF"
_Il00O0OI = "Vuf/h0nchuaNa8p8EbDMNa4QDTLYY2j0AcqscXW"
_OlIll111 = "Zn5i02vimEMq1KnbN9sf1sn1JpimRN"
_lO1llI1IOO = "gRmMQvi4HDhKmJcyP0z04jWH+ZgxcG6OnlRZMaTTtQgOW6o9aTFv"
_I110O11O = "xOisb6eT5ohLD9Ey6HUGC2YfAos"
_l0IOl0I00 = "64v27NkLxzED+amYXkH8Vjfno"
_Ol0I1l1O10I = "h2tVzMQxsIQk2YkWNwucwoQmm"
_II0I1I1 = "PGrszjC++6fbaetRm+oAFXqpv9Zmefw9P23xLeMUNODF++VV/dbru/XP0"
_OIOlI1I0IO = "zgAkD6sZ1RhFu0UsFEOoPdrbpV9yaoOoXIpzerWChpPg+m3"
_OOI010l = "V6a/B5tqGXIwVc3lTPn09kCRqY"
_IIOlI011I = "qMn3TWiWC+tl8Rnxr4t/3/83SBYAkdFBOLhgIdpaH5dgV/F8WAVXWG"
_lI1llIII = "wPKgkfhb/SyACXmEI4+C9voFFknHJBIgKrGAyzK1DX2rd97A"
_O1OO10I0 = "jdIrhdxmyzSFHOU96fb2tVFG/MeI0+DFDH15i+QpPdxLQ+/4BKYWG8xxiyu"
_IIl10llI0 = "L+QVP3+PivHVtWVXMhl9jkDlimVIBHtEGa16cvNIC2v1BkC0iwODz"
_IlIlIII = "AdNBCLmhKb4cGkVRQ9FHTf992Dl7RMl6rlra"
_OO1OO0I = "KAD9FCMdUM54s2JfaY8cV3Jrd9LCQ=="
_IIO0O1l = "adCGKduWssWfvx6JYIm659AY4bXMVO/K"
_OI0I0101OO0 = "2MSdniJRkGqW5wX9cYvP55D2gd34u/LsRDSa0"
_IlOO00IIl = "D4JFBZ3MwX0n0UXgcBhVTouST9YfiIoLslnQsTnhnQ0UjLmBoSV6++6"
_I1101lII1I = "ciXGzuUq2ogApUw6KZuCwqJJ7iAToqqiuX4PvQb3/oonBXBaVq8"
_Ol1IIlII0l = "BVsTgrcsZ6T7gAxUrUpwiGZ5Q5OPCJoy3Td"
_O1I0Ill1ll0 = "icXY9iEB3Om7X2qmZRx4THEzvGjm1yA4IND"
_l01II0ll = "ZUsIX3FwvfL7sYCTKijsHX+OhQYZhptn"
_I1l10Illl0 = "8fJQEo37UuPLg54BlKLYQUc+NypB1RPDdS0"
_IOlO1I0 = "YWYq+FtJ4x3sD8REnyc5OSyuGLnfyjV5vbyH3WnS0Ze+3yy7f48m3ORfs"
_OOlIl1l = "UxghiVWUcwfnABlwhN6XxshX1y4UR/c9lEes8WWT"
_l1IO1I0 = "RfvVssOJR5pBTiDbWkcqRJ2hoaUK0bZML4v+Jtz0lX"
_ll10Ol00l0 = "M5jAAnv9b6og2zUqrK2nKCDz1/oKVU1FVNRxKUicr0nFzQM7Zq"
_I0OIOl01II1 = "uiXDIEghwXupSrmvesr3qwwFO+CuskXrFtup53wKeLL5WcG8N"
_I01Oll0l = "vlBm/0BxeLvKYC6s+3RC/S9w+FA0ru1j07i+lhjHt"
_I11I1Il1I = "VaWzRDuZ/mq1N/6cKxOC5GfZXgl6G8T4oean1YudDIj"
_Oll011llI = "smPGRpf++iwZWSo7w5PXR/VMCg"
_OIl1lO1l1 = "Aide1mqbZsfA/XJldZbgVymI3B9nbGXzXfPBrSEZCdQFwyQR09i/8gdWT7"
_I100IlO1 = "QmlkHdJJlwAzf/lDMAStY5bcSUyzkv/wJ7emPBfNzNm8L0Oh8TYCVdVRf0IXzl"
_OIO1OI10 = "H2Ck6LxpyAsGff5XL5/iBkLDy4I32U3pHiDNp4Ypy2RceD"
_OllI1l111l = "QZ0bmaBtF5//wvaLVHJKDroFOhIug55UGEpB"
_I0lI1O00 = "DfUdZgqOt3rFuHaV7H5EMfjIyk2k1DqiUFLg"
_l1l0011IOII = "kSQHrN2zDSyC21pDXSkjnFKUaL4v/PX58XZnPkPn/Pd3r3HkuYqdc"
_OO1IO1Il = "Esapo+BeTnT4pBDWZrbK1yCVGld3gwbDCKBsnszjDPH6We"
_lII0l1l1l = "s7D04vnPygptC8ZPV39QmbfCzY7GHj1bMo4EUrFL18anSYvVUWIH4o"
_lIOOl1O1 = "3UUueFv3dXQ7P8sRJ4AY2IzBWgSPt0Gh3wIbdSaeS"
_ll001IIlO = "S4GdyeNdfhKbYOBg4/xaIryAcVkdoTqjUu1O2D5YjwAilrRw1ZApq"
_I0l1OllI0IO = "+S+Ztr4uytWUd8LC9VD59nQKOfgALwPbqy9v/EWq75ZviCwg6yVu7Sce"
_l1O1I10IlI = "e05+sxfabbJHbsSuy4Ku5aF6VJ"
_lO1Il1l0l0 = "fctA/yV68vXG/8d55XtheAOVIgNgEnZcGPizUT"
_I110l001lOl = "0js/N6j3IgMXmjz1sGkBavDgFz"
_IOOOlllIl1 = "DdVH4xyLy5Oyg9ucyg8ZZMxHVF1lcRzJEJCcBih"
_O011IOlI = "RArJbFkO33lkDWAp5OjBlH86jKqhq6upIMICC6QeUQsBoVFL"
_II0l0O100O = "UZfcG0QXVuStTxiqUo4cfhmbQQAfF/oeZm49zieht7/BJb6pLbzVbZ"
_lI0l0lIIlOO = "AdQjSqDP0uLTTCOD0uhMHzrs/Cwgt/7"
_I000lIO = "1as55GadTJKsfjEQ7+IvZWMGbiGnebZg9AnyWq"
_l01O0ll11 = "+2hunH4b9lahcteb4qnKnGqubtvNwd1Tml3W8p2LYNRrH4Xh8F"
_I1I010OOO = "kOViDAuqjanfkc/Adxx+n0R9qvEWYeR5ULGYFlzXjvkevokuuU6qTKp"
_O0IO0l00 = "02kdloCTbJrRsL9yBcQ+PYrg6I1csRBx7wBDTNSGivBD"
_lIO0110 = "v1z6XXg82hNdIJA6IZHGEnjwhc0AKekjkO"
_O011l00OO = "dVm25AXFDGthWNP2KyGmhkul5TSIqpuPsgTdKF2"
_lO1IO1O = "egCioGctl8csyR903aUm4176ux+4mRurvdLqwTyAdbgAz6slemxax"
_OO0OOOOOI0 = "oimtUPGGrZazENY8VzJ/64hSUZ2Qs"
_l1lI1OOl0 = "AYtsH+7CKhHdPHCLHqVYqS1RIPaff6SgNnYS8/2fF5ZljzVbm"
_l1ll1l00O0 = "ocDWtGP/BsSvnAh+Fa0MMVNRrjk7TlHj2"
_l00I100 = "/Wx3ptFTX34rMsYxwJ1JHdVAKflfXQsZ5xvJ2D/Yg8gNtNa+du5"
_lIO0l011010 = "7vfLMHSGQBiRw3ZSrNP6ZL2kdywx"
_ll00I01 = "HRJXWhi9qIySt341BARoHhOlEdC33fFvKatBjw64dvz"
_O000O01l = "aI93hxsM7vlEd6V3ok62EhJh/HNC2LQPxYnNLIiBlVDSBch17pNCAyIBrl"
_Ol01O01O = "MNMguURfytAZEtXQbRB27n7vHPj4i0pQJp"
_OOIl1l0III1 = "Ix5uvl/x0KIeinWV2A97/YG3jQ2RJXn"
_IOOl0l1O0O0 = "UNmuFD476yNHMZ/v0xjEQd8KFvETDGN+l9p0A0"
_I10l1lIlI0 = "x8wdq+cj0Q1oslVIlvmPLgYhMzKsCIGjdqX5G/x35sORGzACo8wVqWFmjPfY1wM"
_OI0I0OI = "mJkoyU7xMpmQvB0hg+1zQkuhDh"
_O110II0ll1I = "4wFNfenpZWCCrLzpIIK0BfnhDE7aX3XVK"
_lOIl11I00 = "V5U7gj3pm+jFjyELQAai4gCTRMlZZXAqEypb"
_OOI1II11I0 = "L+jo3lp2AbbnehyjYS38wdaOGo10kmaQwy0bvXCp"
_lIlIlO01O = "0TDqUy7ki5iXZ76Te2yS01M/gao2Fo7Bhh"
_lllOOII0 = "M/2EN44tE5bs9ZFnin51HqDyE4pu8YBkMvAXmv4uvwvkbYt08gDrmK8CdSSjw"
_ll0lO01II = "5xMc+9NGrd5UD1SQr02ZWK44RTbSLjoM"
_lO0001l = "WKL/TeVjqneT0u/MbfgVvhMXXksO8YUhYueGZQObo/f2NbwKb9S"
_llIIlO0I0 = "F3wVAKhVDaI94G0HwabaYBCVG"
_IO0O0lll = "K6o0Sn3zr0Lv9gFbQQdiaEqa7P8C2wX"
_O10llOIl = "li6Zz5c0TIRS/9g6vT2W7q/a7"
_Il00lO0O00 = "9lPFcxHyyrQ9JvhmeG26BXySF"
_Oll000OII1 = "imPfK14VSVIv75tCReYhNW6Bvv"
_O11llIl = "liIRhMkqYFOXZnDK/nmPZbbwitZqf"
_lOO0O0l11 = "0RLU39pXpj9vYL0s51KDePpK"
_III1I01O = "1ZPsVonYVAgb/rJjE+2XIFz+/pBjYowp8lBVue4JQ0"
_OllllI0 = "TyNFi6OBgtbeUXxK98b/OO5ndTR4L+PLuD6+ara4HCMkUzjtW4n"
_l1ll1011II = "d+Ioco/2uRAsAxk3inhjfUQbvrk5A+fAtG161EvKet+ttmNg5Sxs"
_I0OIlII = "UH8J5pY5oTcD058FyMUKM5/rhVOaEaqM9lgcsHSZ/P"
_O01IO1OI = "57vkKIWC+HfVEN0cM6bYyASGR5oMR"
_OlOll1O1110 = "2n8mcEsMncp9Ubkh2VyUGyoKcDcDST14XHp"
_IO0OIIOI = "HwbO3Fj9uqUPVN2MMIhbPq4hAEyOb"
_llIO111lI = "iL/Mh5P7VRzkuTL/9nt8hXF2kSA/7qP9tU9VaoXjX74Oe2"
_O0OI101Ol0 = "LV7tJoJoszW/JtBkhHTLWwuN6HgEQ//mQWWeK380qd9bT2CTo8VqpM7nOfqDVi"
_O0Ol1OOI00I = "mk2jimm8pLdYNox/y4Ub2Rzk"
_OI1l1001I0 = "A/9DuKgZLttGVtheHDGEL+tz+gbHVRW3AF6fruY49M4"
_l0OIO0001l0 = "dDb71dyCPq3DAux5WiRbjzgwVQ0oA2V1Rrnpy"
_OOO11II0 = "m5HO0b2FmfpwujpPcg3sn0bcFcfBdiv7cndUnKAlNweasQ7dh8amgOZhs5O"
_I1IIIO110 = "xUae9Nfgrrxm1OFWe8CpYWPe"
_lO00lI0I0I1 = "bK4CajwOnXtmHl0x7FfbcrRpwW4gdFShHPS3HJXIVQGADCpM"
_III0lOO1l = "isFeOxiAcWIxt95A4gbMEUUqw6U7hVaF/"
_O100IIOOl = "nSMJsaIX1g31mAX0g35A5w3aJ"
_lI1l0IO00l1 = "drIGD/SumNzcqHsn5xAIVsIL8TzWoKaUL35G9drqC7sRvptm9/2aSqXyAlrYQ"
_lOI0l1l0lIO = "b26h585QIJ4IDC6hNjETXAZ8D+KFHwT3ueIFA+bUV"
_l00010l0lO = "dflEuDCjJPKlwarux43xL6/jmOwKGB"
_I0l0l01IOI = "JXOozqecBNIz3GXCf5YFmQKQLuvUZewPtJWqlTyHdy1b+sh5"
_IOIO00l = "/WBC7wtbBwRMatSMyeTrv6gy"
_IlOO1Il1 = "au9OAWBmYk9moKRpufOG8Oi7r9XIsd2uEFBYZl6g6B"
_I0OI0l0OI0 = "BurgWO9rTNJrK1WZ0EBTrt5hJGdZTHiCXs/"
_IO00Ol11IO1 = "ez5d5EAau8/8OxTAyZvgONolara5Nghtv9X3KU"
_O1O0IOll = "W6CvdBYiHu6wdNRXwP5I5N4ivA36mNyp6o3tgV5cu2pTBTh9Ep3Ts8JHNYGsHwy"
_lI11I0II = "NYFeDYRWvuDMsfdv9+Bozt3ei+pZm2NyF1rdSQzKnwWWAWc6uvsWIPs"
_Il1OI11lOI = "B1gcw6HJR+b4j28z0rqV8C5q6PRZDzpnVyXmxuXpGWGwgjbeXXqUP9nd"
_lllI011I1l1 = "MIAFPwkFt0eI9t0VhmUu274OgZ5ypnNHVb01pKHTSl2Gr3q+MWs6PaFUg"
_IO1O0lO = base64.b64decode(_O000O0II01 + _Ol1O001O1 + _IOI1OlO + _Il00O0OI + _O011IOlI + _I0OI0l0OI0 + _I0lI1O00 + _III0lOO1l + _IIl10llI0 + _O110II0ll1I + _OIOlI1I0IO + _lIO0110 + _O0Ol1OOI00I + _O01IlOl1II + _lI11I0II + _I1I010OOO + _O0IO0l00 + _IO00Ol11IO1 + _IO0O0lll + _OIII110 + _ll100lO + _ll01O10O + _I0l0l01IOI + _l00OOl00l1 + _OllllI0 + _I0l1OllI0IO + _l1IIl10I1l + _OlOll1O1110 + _l1ll1l00O0 + _IIlIOIIl + _l1IO1I0 + _lOllI0IlI + _OOII000l1l + _O11lI011 + _O000O01l + _OOOI10Il1 + _lI1llIII + _OO1O111O + _Il1OI11lOI + _O011l00OO + _I01Oll0l + _OlI01lI1I + _O1OO10I0 + _I1101lII1I + _I10l1lIlI0 + _l1ll1011II + _I00OI01 + _O100IIOOl + _O1O0IOll + _lOO0O0l11 + _Il00lO0O00 + _ll001IIlO + _ll0lO01II + _l1l0011IOII + _lII0l1l1l + _OIl1lO1l1 + _IOlO1I0 + _lOIl11I00 + _Olll0lI11O1 + _IIOlI011I + _llIO111lI + _l010l01O0 + _IOOl0l1O0O0 + _lIl10IlI + _Ol01O01O + _O011O001 + _OOl11IO + _l10l1I1OO + _OOOO1l1OlIO + _OOIl1l0III1 + _I110O11O + _I1IIIO110 + _lIO0l011010 + _O0OIlOl1lIO + _lIlIlO01O + _II0II0O10 + _l0OlO0O1 + _OO0OOOOOI0 + _l00I100 + _OIO1OI10 + _lOI0l1l0lIO + _lIOO1l010O + _I1l10Illl0 + _OOO11II0 + _II1Il0OOlI + _ll10Ol00l0 + _O11llIl + _OI0I0101OO0 + _OO1OO0I)
_OlI1OOOIlOI = _IlO0O1O0I(_IO1O0lO, _lO1lIO1O1OI[0], _lO1lIO1O1OI[1], _lO1lIO1O1OI[2])
try:
    _OlOOl00ll0 = _OlI1OOOIlOI.decode('utf-8')
except Exception:
    sys.exit(0)
_IIIlOll1 = {'__builtins__': __builtins__, '_IOOll0OI1': _IOOll0OI1, '_l0lI1001': _l0lI1001, '_OII1O0l': _OII1O0l, '_IlO0O1O0I': _IlO0O1O0I, '_OI1OlOl': _OI1OlOl, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': _llII1lIIO}
try:
    _I0IIl10lO0O = _IOOll0OI1[3](_OlOOl00ll0, '<s1>', 'exec')
except Exception:
    sys.exit(0)
_OI1OlOl(_I0IIl10lO0O, _IIIlOll1)()
#PYG4E
