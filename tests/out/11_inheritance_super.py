#!/usr/bin/env python3
# Protected by PyGuard v4 (pyguard.akean.dev)
_I1llIO1 = bytes([5, 49, 111, 48, 122, 244, 151, 160, 140, 216, 68, 113, 124, 104, 111, 196, 241, 30, 12, 207, 42, 166, 10, 140, 243, 161, 165, 240, 162, 113, 40, 156])
_O0l0O1II111 = bytes([159, 60, 18, 136, 3, 76, 88, 71, 25, 216, 247, 161, 232, 244, 185, 163, 211, 185, 163, 190, 163, 61, 29, 39, 186, 115, 218, 65, 182, 70, 98, 226])
_II10lOII = bytes([213, 227, 31, 84, 179, 160, 94, 19, 24, 233, 160, 80, 207, 146, 203, 171, 151, 250, 115, 78, 72, 9, 125, 66, 56, 179, 240, 139, 228, 231, 171, 23])
_l0lI1II = bytes([190, 67, 48, 235, 206, 138, 121, 126, 5, 202, 251, 141, 34, 102, 198, 84, 181, 46, 114, 58, 170, 133, 183, 25, 10, 208, 14, 69, 153, 245, 99, 117])
_I1O1OO0 = bytes([18, 96, 247, 201, 161, 34, 245, 208, 195, 217, 77, 87, 179, 64, 62, 140, 2, 60, 215, 23, 239, 34, 58, 195, 157, 35, 117, 165, 54, 115, 36, 141])
_O00l01O0 = bytes([18, 159, 24, 232, 182, 51, 230, 102, 18, 158, 160, 20, 65, 180, 124, 111, 224, 31, 140, 172, 114, 23, 126, 158, 220, 178, 49, 172, 52, 169, 191, 6])
#PYG4S
import sys, hashlib, base64
_l1lI0IOll0I = type(lambda: 0)
_lOIlOI01 = (compile, open, getattr, type, __import__, exec)
_l0OI11l0 = _lOIlOI01[2](sys, '_getf' + 'rame')
_lI01I00 = bytes([163, 229, 190, 218, 18, 103, 19, 155, 177, 223, 91, 52, 116, 28, 6, 30, 236, 163, 121, 118, 50, 126, 158, 121, 84, 95, 134, 133, 75, 10, 47, 169])
_OI0I1lOl1 = hashlib.sha256(_lI01I00).digest()
_I10O1OO1OI = hashlib.sha256(bytes([218, 21, 10, 112, 132, 26, 109, 122, 50, 215, 225, 141, 72, 127, 83, 189, 241, 253, 173, 1, 173, 70, 23, 69, 44, 152, 199, 38, 51, 141, 217, 152])).digest()
_O1O0IlI0 = hashlib.sha256(_OI0I1lOl1 + _lI01I00).digest()
_IOlOIO01OOl = hashlib.sha256(_O1O0IlI0 + _OI0I1lOl1).digest()
_OI01I10IOO = _IOlOIO01OOl
_OOllll1l = hashlib.sha256(_I10O1OO1OI + bytes([204, 227, 16, 75, 116, 186, 93, 44, 35, 136, 152, 43, 7, 154, 25, 40])).digest()
_O10I0O1O = hashlib.sha256(_OOllll1l + _I10O1OO1OI).digest()
def _OllOl10(_I01lOOOOl):
    _I01lOOOOl = bytes(a ^ b for a, b in zip(_I01lOOOOl, _OI01I10IOO))
    _OI0Ol100l = []
    _lIIII00I = _I01lOOOOl
    for _ in range(8):
        _lIIII00I = hashlib.sha256(_lIIII00I + bytes([9, 243, 88, 205])).digest()
        _OI0Ol100l.append(_lIIII00I)
    _llOO1lOI01 = [(b % 6) + 1 for b in hashlib.sha256(_I01lOOOOl + bytes([180, 38, 26, 155])).digest()[:8]]
    _O0I1l0lO = hashlib.sha256(_I01lOOOOl + bytes([131, 37, 102, 8])).digest()
    _OO01lO001I = list(range(256))
    _ll1II0I11OI = 0
    for _ll1lOIl in range(256):
        _ll1II0I11OI = (_ll1II0I11OI + _OO01lO001I[_ll1lOIl] + _O0I1l0lO[_ll1lOIl % 32] + 198) % 256
        _OO01lO001I[_ll1lOIl], _OO01lO001I[_ll1II0I11OI] = _OO01lO001I[_ll1II0I11OI], _OO01lO001I[_ll1lOIl]
    _O1I1lO00O0 = [0] * 256
    for _ll1lOIl in range(256):
        _O1I1lO00O0[_OO01lO001I[_ll1lOIl]] = _ll1lOIl
    return _OI0Ol100l, _llOO1lOI01, _O1I1lO00O0
def _lIOOlOO10l(_l1I1lO0, _IO11I1llI, _O0IOllI1, _O1l1OllIlOl):
    _IO1l1lO = bytearray(len(_l1I1lO0))
    _IO111ll = 8
    _OIOl1OO0IO0 = 0
    _lO1OOll = 0
    _O0OI0ll11 = 0
    _lI1IO00 = 0
    _OI0I1IlOO = 111
    while True:
        if _OI0I1IlOO == 114:
            break
        if _OI0I1IlOO == 111:
            if _OIOl1OO0IO0 >= len(_l1I1lO0):
                _OI0I1IlOO = 114
                continue
            _lI1IO00 = _l1I1lO0[_OIOl1OO0IO0]
            _lO1OOll = _IO111ll - 1
            _OI0I1IlOO = 224
            continue
        if _OI0I1IlOO == 224:
            if _lO1OOll < 0:
                _OI0I1IlOO = 168
                continue
            _lOlI001 = _O0IOllI1[_lO1OOll]
            _lI1IO00 = ((_lI1IO00 >> _lOlI001) | (_lI1IO00 << (8 - _lOlI001))) & 0xFF
            _lI1IO00 = _O1l1OllIlOl[_lI1IO00]
            _lI1IO00 ^= _IO11I1llI[_lO1OOll][_OIOl1OO0IO0 % 32]
            _lO1OOll -= 1
            continue
        if _OI0I1IlOO == 168:
            _lI1IO00 ^= _O0OI0ll11
            _IO1l1lO[_OIOl1OO0IO0] = _lI1IO00
            _O0OI0ll11 = _l1I1lO0[_OIOl1OO0IO0]
            _OIOl1OO0IO0 += 1
            _OI0I1IlOO = 111
            continue
    return bytes(_IO1l1lO)
def _l0lIl1l1II(_l1Ill0OIlO):
    _lO000IIOll0 = hashlib.sha256()
    _l1I1l0O = [_l1Ill0OIlO]
    while _l1I1l0O:
        _ll00l0llO = _l1I1l0O.pop()
        _lO000IIOll0.update(_ll00l0llO.co_code)
        for _lllIOl1OlOO in _ll00l0llO.co_consts:
            if type(_lllIOl1OlOO).__name__ == 'code':
                _l1I1l0O.append(_lllIOl1OlOO)
    return _lO000IIOll0.digest()
def _OI1000II(_l1I11III0):
    try:
        _OOI1ll0Il = bytes(a ^ b for a, b in zip(
            hashlib.sha256(_OlIIlO1I0 + _l0lIl1l1II(_l0OI11l0(1).f_code)).digest(),
            hashlib.sha256(_OlIIlO1I0 + _OlIIlO1I0).digest()))
        return hashlib.sha256(_l1I11III0 + _OOI1ll0Il).digest()
    except Exception:
        return hashlib.sha256(_l1I11III0 + bytes(32 * [255])).digest()
try:
    _OI11O0I = __file__
except NameError:
    _OI11O0I = sys.argv[0] if sys.argv else ''
try:
    with _lOIlOI01[1](_OI11O0I, 'rb') as _O0lI1lI1I:
        _OOOI1l0OO = _O0lI1lI1I.read()
except Exception:
    sys.exit(0)
_OOOI1l0OO = _OOOI1l0OO.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if _OOOI1l0OO[:3] == b'\xef\xbb\xbf':
    _OOOI1l0OO = _OOOI1l0OO[3:]
_II1I0O0Ol = _OOOI1l0OO.find(bytes([35, 80, 89, 71, 52, 83]))
_OOOIOllI1O0 = _OOOI1l0OO.find(bytes([35, 80, 89, 71, 52, 69]))
if _II1I0O0Ol < 0 or _OOOIOllI1O0 < 0:
    sys.exit(0)
_I00Ol01OI = (_II1I0O0Ol + _OOOIOllI1O0) // 2
try:
    _l11IIOOOOI0 = _lOIlOI01[0](_OOOI1l0OO, _OI11O0I, 'exec')
    _I100IO0Il0 = _l0lIl1l1II(_l0OI11l0(0).f_code)
    _OlIIlO1I0 = _l0lIl1l1II(_l11IIOOOOI0)
except Exception:
    _I100IO0Il0 = bytes(32)
    _OlIIlO1I0 = bytes(32 * [255])
_llI0Ill = hashlib.sha256()
_llI0Ill.update(_OOOI1l0OO[_II1I0O0Ol:_I00Ol01OI])
_llI0Ill.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(_I100IO0Il0 + _OlIIlO1I0).digest(),
    hashlib.sha256(_OlIIlO1I0 + _OlIIlO1I0).digest())))
_llI0Ill.update(_OOOI1l0OO[_I00Ol01OI:_OOOIOllI1O0])
_Ol1OO0O1Il = _llI0Ill.digest()
if _lOIlOI01[2](sys, 'gettrace')() is not None or _lOIlOI01[2](sys, 'getprofile')() is not None:
    _Ol1OO0O1Il = bytes((b ^ 161) for b in _Ol1OO0O1Il)
if compile is not _lOIlOI01[0] or exec is not _lOIlOI01[5] or getattr is not _lOIlOI01[2]:
    _Ol1OO0O1Il = bytes((b ^ 191) for b in _Ol1OO0O1Il)
_OIIIIlO0Il = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != _OIIIIlO0Il or exec.__class__.__name__ != _OIIIIlO0Il or
        getattr.__class__.__name__ != _OIIIIlO0Il or __import__.__class__.__name__ != _OIIIIlO0Il or
        open.__class__.__name__ != _OIIIIlO0Il or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        _Ol1OO0O1Il = bytes((b ^ 182) for b in _Ol1OO0O1Il)
except Exception:
    _Ol1OO0O1Il = bytes((b ^ 182) for b in _Ol1OO0O1Il)
_IO110lOlI0l = sum(b for b in _Ol1OO0O1Il) & 0xFF
_IIIOO0O1l = _IO110lOlI0l
_Ol1OO0O1Il = bytes((b ^ _IO110lOlI0l ^ _IIIOO0O1l) for b in _Ol1OO0O1Il)
_O0Il1Ol1 = hashlib.sha256(_Ol1OO0O1Il).digest()
_I00I1O000I = hashlib.sha256(_Ol1OO0O1Il).digest()
_Ol1OO0O1Il = bytes((a ^ b ^ c) for a, b, c in zip(_Ol1OO0O1Il, _O0Il1Ol1, _I00I1O000I))
_I0OI0O1I = bytes(a ^ b for a, b in zip(_I1O1OO0, _Ol1OO0O1Il))
_lllIl0OlIO = _OllOl10(_OI1000II(_I0OI0O1I))
_OIOI000 = "331cAEgL2QqqSAHMpbsUrrrU0TDblhwSdyApCu"
_OO11II01 = "gh6PoLNJr+2G9ajkBo/NWK80fFounXLJxo+"
_OIll010 = "rNtojT76dIljh7Q3k+slgKtQ7"
_I1l00I0lll = "H9/8mpkPHux8DoO4eq2TBlm1O+b9TkwP"
_l0OOO00I0 = "verneTOtYdIqQbbrYI8YH7baUWNPp0bF+0oi7v5vG9hwkF8KjJ9ch4xGt"
_OI00lO1OI0O = "AK8r7p8LU87fxGd3fNjtZ8ryODaepnGSCLn3C+V1+U90"
_IIll11lll = "K9JHAB4BROnU+csZkhkVj6jecH81Gq5vVkxGezH5pQ8X7ued"
_IO1llIII = "FgtFc5eWYurHa48zChosvFt3eQYh2+AAkPSK3rGNJzaLQkWndg/s52K3l2+ubT"
_IO1l0lIlOIO = "Dn2f+E1dQx2dBkambPSO2bgW8F9FJSIVRP8tf96UoYVuRoEoj"
_l11l101 = "ndy1vFmG12On5pxqrcWNHZrSP2ej9nYrDp15OW7Y1MT8+PbCb98Lo65p6h9pvsp"
_lI0001O11l1 = "ce9mKDIlA0oNGZLShnPFW5NjPhobTNgQL1ySdMI0ErAQf58NsJkimvNVmu2YF"
_O1lIOO1Il = "Svg+Ieprjmeb9Y7JBWqo82b0viG8nrYlA39Gbjf"
_OIO10OOOO0 = "dLrczk/KxGZmOCNPKnJEDBbMqrTUqbi7w5OPb3+15DI6eNRkSru"
_O0lO11I0IO = "MErpuJ3ppj0XH02rosoIil2dvnN8gWCNkyMrgYcJ6Op+e/P05m"
_l1Il1ll = "4nUD7YJs1EaptlhJYtJEF9Vd2LWkXTdP8FXj0mHJh10+Kd"
_lO11O0OI = "47miSXhiLmb9FcOoce9a/qQgIqlfqBj5cgcIQcOWxgd7RtcBvPGWkD"
_O10l0lOOI = "IVyqIVThkCroIUUpDQ0pWiZDUdHIDZm"
_Ol1011OO111 = "CqytvCkPOJaskP1R6LaLzbAJ7F/m2uaz4g"
_lllOI110 = "uOzPgS7Wxv9WdIF8ge3o4KLqWWeSL8L3YgwJ3hLbRnayRGbm"
_I10II0IOlO0 = "TYuI7Fn2oFpLifgC609ss82xGnhVU38ugmeApXgESjFJ"
_I00I00Il = "pr05SPq9B34/SgbP0ww2Aw83rxeG7j183F06GFOwuyEn"
_IlIOlllOO1I = "H9RyjdlR//iw7q4MM993OE0pMFUQaxxZuejpEp/NyuKKXjFjuCFlO5wrnnAwkk1"
_lIIll00I0 = "iaeCQgIWjjj6iv1dqfZnONDbMqP9Lj866BXIBTSDeOJK3+nXHal1jxMB8u"
_I1I0Illll10 = "W0kOs2/zLVqFL2jckjlj3NSdC5ZqAsWGlJl9SWQw"
_I0Oll0I11 = "NbrcTFrpfJFmZ8sSRWkmSeREX6GNpQ5f04iuniLQEN90YXRQU40p56rYt"
_IOI0l10II11 = "SnGpOpKeVHXynRPZ6+qbFklf0QkRnHF2b3"
_O101IlOI1 = "6RfO0ZuiCtO7zN+w88ybx1zo8Hdq2TfKGol"
_O0I101OOO1l = "V+Z4s5pIPAu7nadOar4k8RZa"
_O11l0lOO = "0I3/u1/jaWDQCoIPMk+kwpbkILAQUdlI7rx"
_O1IIl1OI = "BEpb67qvO/yjIjAFA9PkIbk6IxFvTS"
_OOII0Il1 = "01Uu/2hZDiJeicbHtUK0VTT/ToC1XhIL1"
_OIIIII10I0 = "8Z4M1ZFTvTb1bb4CczAz/PZa7W8bXqIg"
_llI1l0I1I = "XnkIEixtGkMHC/qgDBqqn8wS"
_II01IOI1Ol1 = "z4Z05UZ7p185dPJdKtepu9VODTPcRw"
_l0O1O1l0I01 = "6L3+2VRVq+h6zWxrj+JA7hvIqVk7mZx3O/KBGqbnmoL0gUKsU0Z71LAKZ"
_I1IOl1OOI = "ZCgC7vp6OBWUBPp2owzRn+9Jfc1Q2/rxvxla"
_I01OOlll1 = "V1jD0EOd599QAormbJqw/VrZBOpJOriKaQ48+DjL0FkO"
_lI011Illl0 = "mgXuEivuJzsLNV+UlGYreKC/8rJ70"
_I0llOI0 = "O8T12sRoLAk4NgrFE+RKEDW/ebw"
_Il1lIII0 = "j2eo0uiczS/l6XWbiywX3lwOG1LSnc"
_I00llII0 = "Fk97Zj3X088f+RIKMbE6kMVryU9QvZt/"
_IOlO00111 = "HlQQviBasRipOMbKPZoiic6codnRy+Uysea+QOlw8HHXNH36tz53ju2MgFu+N"
_OI1l0OI = "DYlhVljbimZRtSg2ZG9QHMlnq9ovlCnBXIBpaH4ugJEbU"
_lII0Il01 = "uF+/bfunF7XUyrq283/e7H5m0Gd/JulBEc/5au2Ws/E5pg+omV"
_OI0l1III1l = "WvyDcBeOaY3ixnC9Hq8Q8t9e"
_O01I01llOO = "WZ8DhbU4+eNCKWBVJIizHWrTHb3Hg0/zo+R+kb5CnN5zlx7NXm"
_O1ll1lI = "EqD+pFkOIwIuKBHOGLp6Q+nc1BKxsJC035q5AIlSqn3A1NQzpmj"
_IlOlIlOO11I = "kzdAP32GN9EqYcNX3a1PV1IMO090n/PiJc705Dp91lkbqIIAdTqjfPH3SH"
_IO1Il101 = "pzyxhBrlzpPsL7vKAtqKAp6myVSZ6"
_lI10lO0 = "1B1eg/BdJKPrKzk+yh8Qbzx0eO1TbTT4NlrM9nhfVl8F"
_Il0l1OO = "qt5qW/YYRksGaqEWBEOHm2W3Z3zbU+gTxBeAVLZihiXoANNd8ibV"
_O0l1l1I = "2K4a9CF8sftONxSVbINtWMLfOV+JpUq73UNbn//v7x"
_O1lOIIO11l1 = "50jwo3eGi3qKKDJFlmk1VCKtWxYdh9t"
_lOllIll10OO = "cLgs0flsr6Na5C4utw16j9w8kQRhbs"
_I01lOlI10O = "/+rTnkutbdozCjqDFXJtaDAsR/LVFoe"
_O1O1OOl = "dNsp3Ntim/A1/OdKaiAc2z6GW4u/F1VKu7o"
_l0Il0OO = "spADJlxdURlWP7lnQHKU0evUTmJt0ARU9LyuONfV88Bs3ydysB7Ym836x"
_OOIIIO0O0O = "vNESV9ibbJTxc2owhgIQnXTd+V"
_l10000lI = "qnQ/7y/fn+Mn0X0pDCE/0oOlcakURPfIdg8L+ENZi1h92VTJp4Z4"
_Ol11lII = "VQKifHSeWDp4uoM2O1KTDG4JxS4ULu4G1ZcsgTjDcGEPMX3"
_OOIIl0100II = "4yamn7nMhlI0IORVsa6icKzG14Q5BqVE8vIY"
_lO0lO1011 = "e4qOZWO/d++8DfB3VuatQdXea"
_lIO1lI11OI = "J13gnp1WbIODQD/DzOzLEwDaniYR0mag74qjZ798R"
_lIO00l10OI1 = "h3logmGStdsHrLF9BUVw/N7/enT9/n0c5EX+aUDJzflCry25pWeydmJksj1"
_lllIO01I = "w7fdyLqhYlHcUKJ4Y7uZTw2TlbxZpj"
_IIl01llO = "T2E/cCb1J4JqysfBTyRmdV/A/DoOPpCVEKlEgpDE"
_I1O0lO10llI = "qozCET8oe5CBHFfbz++YvR6bo3dwJw6ptpEQ7O54inV12KAGbHQ373"
_l10O01O = "irQlX4yakNuCNHk5JkWJ+6aH/QwCoW+26yoWlnefXgzVoR"
_OlIO101110 = "QqQjquWwDTptqV8QZVygyM2hDz+1Gr1cDvngofyeA4VPgCNB"
_l0l1IlO = "PNXRejWEY4+Y2PzG5nnue/Gd6n7MyLFvdBlshy"
_lO0Il0l0O10 = "WwuAkLKgp9qv50b+6Xtg9QYNDMSMfxktF6eE7ZI"
_IOO1OOOOl = "5ljDTbYiNZXCFl3SwYfLx1MYGn76"
_IIOIOOl = "rfTWLIKoe50v4RzwJU+Am4rPwdfkcaf4VjXQ"
_l111I0l0l0 = "O/ZS4gyX3UzT9BDT90sW10XP6r"
_IlI0ll1 = "y/DOczHvc9oQBA/Hy5y5I+A5v4a05HsoULnJv0C5PfHWzz"
_lll100O1O = "nxnC8KOvA7PfTlm9d60OuJMnMqwO8BTzbQ6p+EPRIWaxVvRnmuC5s/"
_O01lO1OI = "j5gafPuRpBrshJh1mGMfaovTiQ"
_lllI1l1 = "MHSB5V1TAgHKacrrLxk9xSo8dLPgpeC"
_l10lOIO00I = "//hrA8bEuRV+clVkVplvm5iFPVjCyxgD6NpeWip2mod20KqAPdaDwWdL"
_l00OllI1 = "vYk4QXUu7Dc+1gEmCB5THpXF5dT8lLa6YQpueqI8ef+cCaBLMzX0UZjZx"
_llIl0O1OllO = "++OTpIhg1uC0qFdOpUgU1Vg1J/nRpQzF/pOz9bjM7P"
_OlIIOlII10 = "Dr9z4XYoOmVSwb1e1aaYHLFmBFbDKsyxu1+qfCqjk5empUDzZn666zCVl/mW"
_OlOIl0I00O0 = "BV6CNCmPxZH5TdWmCXEvyQ4wKAT+AOrgaWYNWni3cxZFM6x"
_II011lOIIO = "hhxeQl2tLJgUD0BfkCTlg1oIz2teJ9mFKLxLqDrLW"
_I0I00Il = "YZ91CtvKbQRepZAefDopN7bApOWT+Pjq7E86+Y0e3QfWHuHkHZcnqBvsLYjW"
_lOO101I0 = "Ty2JNKprO7U4geoUc3tfRNydFGrh"
_IOO0IO0O1 = "x6hZhnHciE+5n7J82LV30ONKjDZi0//IWEIPbnlaiNFMeCZ2T9QSsz"
_l00lOI0 = "G4a4La4QmXAtUTRV83JapbEPyjSIev9DUx11w"
_OlOOI1lIOll = "q5mGaqn+vYpZ8398Cgn2p0LESoeu2pQ1rZKyMU6FkFMW/"
_OI1IO0lO0 = "ZL2hgVhsIewtzXaNwSr5eN3sKmDYLP"
_I1OII1OllO = "88wMN3HMrmcvRmm23Q/DitBr9C7Ld75rmyA70zNKK5F2zAvbo0"
_OlI1Ol0I0I = "0xnDQ1Ftr3hcYj847qWUBtJTB2zjS3YyQG+Sd3mbGfAlHQ"
_OlO100OIOll = "seL0pH0raS6eE9CCpNIc89TNbJUMmt6a5557C01Nr"
_O0OI01l = "PeprQU6/kQtg/nBy6BPG55T7qWc+0VP7WcY+fTwwZKE2RMdLLcBtLgl"
_lIIllOl001I = "4yu+f8Ds6Agr3sQVvh1hxgbOYU5ee+9ZAU"
_l0I01IlOO0 = "DFmegyutv4SIWTNwZMswqeUzNkLDVv2Jwb5WYa5avWNQjNF6R9syY"
_OOlI1O01 = "ObhN8aQAKyydX7odfdzG1yvvLBNIuCqlqQI737Ujx7PJoc8C4IqrSTgZ6"
_OlOIIlI1O = "r16IOvGOXU8wAGAUGGENMH0hWkLXeoJ1oW96g"
_O00OlI00 = "Z0vMGtvUtvjb6JWGQI8h1puDqwr2b54bVr"
_IO001IOO1I = "7a/oxgpn2WGp+641y366OhAzGWsF3ZbP"
_IIII0IOOIO0 = "dK1fxTIObXWd6A+DROBLPCwawkZlrEl5KVtLgW"
_lIOO00lO0 = "8we8Omxy69ZbVbZoUNe7bqJ5i5ue7LJyK51CzvoW9tsmr/K4OQ3"
_l1I11IOlIO0 = "FQ9cAFseE6MhqMqZRCT0bVfT006GwbEi1nnmKEe6Knmt3lTUq"
_lI0IIl011I = "/UY3a1fzL3ZM5mSHMmO/IxyHFJEKKz3JiF/euoGv"
_I101010l0 = "TRCMl7WOA0Br8pHf9QPZHdt5L+8bnmuQ9m3fPDWVVbKLTrQs0NDTpCd210grW"
_l0IO1IO = "tlyhG3W1qAMTOm0KWkACe9DGpTNgAPTWDMNm"
_O1O11IO = "vtoHjM7H/rOvdD4eok/LOS0K5I/3M67fzpptxHLIJ3rV6sks"
_I0I00I1Ol = "lTZeNS7v2Cx0GIlE3ZrC1aAJCd8UOOTEeWSVly4Hof/yM/3gCoR0hw5Qd"
_O0I1111O0O = "ftOoH++W3OW00Cvo1mx7t/Zsob8cF5"
_lIIO1ll = "qWseEntP6iwI0izDEDN3+McADaVsrfhaErRQPmpLnz6IwcNcbLz4w29y+JV"
_II00Ol0 = "qazVs5yAOslvzJlT72NyTsuB8"
_IO01llOOO = "sJ01TMtzubEahOuQaAg9fS5kwIg+p/XppBcVdm58CQS05ehMkn8x9EeNmUeUx"
_O1O0O00l = "FY17rNVLMGqaWScrnLeho0LgiZmvjSOtg"
_OO1IOOO0l = "vbll4F06h+tftMx2XTxNdvpYF13Up5g7XtqY2VzRWu8B0EWbxcRiBeKf1F"
_OIl10IlO1 = "+9gUDPiVngZuOqF08gy3NIgxQjhqBs"
_I0O1ll1 = "CIXBtalaxSnnc3MDImHeve0ij0C/wjAIgPlRb5ThArF4QQgO4wR7dUiyAfBoCe"
_OIl1I0O = "ugSRH7Fp+J8tZqZhvcyKMQtrWZGBCcHAr31"
_l01llIlI = "1AVX6uysKlasR1pNlr+mw8ZPIuQ/Dbwn67"
_IIO1O010Il0 = "j3H7FY1cAFoidE1wQra7vrgltcnYfCtk63qle7tsInt8MryM3lp1XvRR"
_I01IlI10lO = "FGoU55eqD57S0+Ajl3fcTyuVN7"
_O00I01lO10 = "YMBVE8d37MnYYoWSqMY21tHPf/SM3ln1x1WFKs"
_O0l0IOIlOO0 = "XDxv6KsnLnB+m+vqI90WUXbVXyNtANFvd"
_I1O11l0 = "ro+fK3yoZ7QRROGVC0yDjUp+w7pg9r"
_OI0lI10l = "18hwhK87pJTTXozdnLbE2E8mma2mZR8fAaZjOTyxi0n"
_ll00lOl = "ZDyrlG8y2s/jC2egSZlgde+D0H8akj9EuJK4t0FAEDub1MA8efk1oQFtsw"
_OO0lIOO11I = "BHavM5T21PP5mcgRrg64zOku"
_IOI0ll1IO = "CywdTBMs8pOMP0Y2EbGVgOu7b2jXpfQOJ8o"
_IO1ll0llOO1 = "gfG0Qg+pWhZhS/huwS4vg1gU0f5DL4+6wEIbagc"
_l1001OO = "KIXN5Pa7OiLdk8Ra3mYUYFsa7LFQJ2hWSaMr"
_O0OI1l00l11 = "g8r8xm0kRiJA5pnz4TNy1oEXL"
_l0O01OOI = "ZsyPeeFcVK9bNLg/Nkri/ej5R/WH/QuVaJoVXlayJRIHL8B8r7ggZ4"
_Ol1Il0O111 = "vwUtosIP924MhD94kykbR6pSY4He+vD9"
_lllO00OllO = "MVju6NiKLgZugPbwfYXpbJmie6ppNsv"
_lI0OI0O0O0 = "9TMK6T0scBUTT6ApwS44av8tyey0vVOTlnQetn8PbuMd5RK6xpAV+kbNt"
_l10l0O0II = "j2OcMyszo0SbHXCh96JSXx93PeX0Fg+IqLOm9kfYutT6CgI"
_l1l0I0OlI1 = "F/GCqYWnXSBAr8pRBsJjhAbvB"
_lOl1I1lI = "R26ESBlHhI8FOAhHDH26GOAbX8EHp"
_ll00OO1lI = "s3cos7r+Abc8yBZmi657U"
_I10I0IIlI = "ZGE3tL6rnszxl6OULNP9by/JTRWgin85YX4PICk/8HdyF3ig5NwgsAKe"
_l10Ol11 = "WKB/cToa2e2NAb9OtOonBy1EgggHf1zCjioixtgAU6u7nXrnh72BqBxPQ"
_IIOOl1I0l1 = "/IfAKxAbCNJroRIwkFPu5JVF9Y+OrqCjgbH2wXtfi"
_I0II1OlOlI = "AjB6WD9Ah1rhEAIzwlgEramPZ9bOIoF4y0P15h5IL3t09vm0JO"
_OlOll0Il1 = "C89HkSnOgHHhaF9Dk0dGZccXp3EaSmK24zZSVIMoN"
_OOI1I0IIOI0 = "Vw6xvWKv6aTOJ0ZlIRFWxIEBEbpZ+M6I6Akz4+CkilRUfydKc9Pre3oRdv"
_O0I1IOI = "EFtb7hkGvK4UFMRKBHPtdqJ5VF9cUAYmvg07qUp/2cVoUDP2"
_OI00O010l0 = "rfy2MAGPxg50z8VbACv3Em7ElY9R4hNAC8JxMRb3L5mkqsZtErfbtj+xJE"
_lI000IlII = "/DUyTdPjdjqKWEL1nZfC9sxacJQVULX7Jlqv"
_O0O0I1lOOI = "RPDF8NaXuIrXu3htMtraIXz+OIpIm1dXTN8bIyDVv"
_Il100lll = "HzoAPmaRFS5GecTJeBV/knKBD95edEUEh1LAPJ+D3T2gU8o"
_O1OIOOOl1 = "LxlMRLJEo5BRF3dCIo41ZdiIKdDlUDgiQTX/zh6O"
_I0OIIII0 = "B6WpVFq1LJKgX4w0JcsgCh7z9TMs/6HR"
_II0I1l1I1 = "vT2IBvHB9cwj8EDuSQCcWvwSAzCKuZ0B1nc5QI1oTgnKm0UaLYcrRzsSf"
_lIIIIOl1OO0 = "90qkcRrUG8j0anojLDSpqtPW+zZ60dITpfg6EZHcwGc9cgwrXDdsZ4z/u+cb"
_l0l1O1ll = "/EgIfyR1qReXTkuy0x/vzF+WS/OeNhfkfbWkT2OtOmXUS09jeWd"
_Ol0O00ll = "4UREvGDZjXMbtcY6ls3v1aWC"
_II0Il01OO = "rnI4qq/SgE6WoNI+hBReWqWpMyNjLL"
_I10Ill1I = "B6GntfAbhE+E9VvtVVrSdVB0DD8KPXrBrBc"
_IOl10110 = "BbvvSEcReXsi4M2S1YqY6lgI"
_lI1I1O0 = "ETzvCWo4EatQaNIx+Rvfb6vpons"
_lllO0Ol1 = "hzIed2g8qPn6TX00246hzn+iFf1HN637QoX79FS"
_I0OOlll1 = "kO+EGiwUQTAihVptzIShmPTKi"
_OI01Ill1Ol = "JRrtpLW32NgiTJ6K2MxxWdVliwttk0LYPBl4XzetapVS"
_O0Il010 = "d6MAx2KL9EnpHu+NN4XHbiRKrjDgJmeDpXta0OYtcDlS"
_II1OO1I11l = "KW2jb7R3GrqQQvzM3JFKYXmNxvKwv6"
_Ol1OlOl = "dEo3/+Ez/7XnPvbSPFSKsFFkERvTvD7dK3r6X2+ry"
_l10Il0Il10l = "R5gETqiuOqRpLnb5QycmRABx0+ry"
_Ill1l0I0I = "i03mv1VoTcXosDh+yAeBEy+D6ltDvm82BZsp886qJACTzuZJNarTZQ90zAtWCP4"
_l00OO10 = "oJLSsBP7jDwCI2BpmrZzBhzD0i1rJ28h4I+wjhYI2qG9Rc5Acbwi"
_lI111IlI1 = "kBZFdeAAwr5v96uHtppDfT/KA"
_II1lO01l1IO = "DRaiuSHWMHmQVkCCfZL/NtN/HcgWhf2SKIv0LCl4TfFTA2r7Y+gTuwbszC"
_l0l0llO1 = "0C5z5iU2SqpL5aZg9ivmlnVtYhFqL6E7ZfJjRFL"
_IOl1ll1l = "wtFQrr7mUqZd5AAQdRGtcaA09E0TklBafLDzz9oRUQpNDf1"
_I0Ill1I0IO0 = "QEt499nxsKoEpX0Dd0VHLk4r3yde"
_OIlllOOOl1O = "xcb3eCROW+GyEv6a+BIngu12tqGp3aOY+yM9oZ9wC4Wu5KAlmw"
_l01l0OI = "2wMqcZ7Al/eDC9odoNR1NBkE2jf0bFs+ofk+kjCefvG+jnvBscii"
_I1IIl0lOI0 = "Dv5ZfFc5pEbTCRtNq4BFNfBHy/LZX8CoE8rvk82O/BUh3Dsvvxl3tWwlv/"
_lI10l1O01IO = "5jbzlNxnzbe4IN6Kf8F8g1S0etqGxa78gMcFLcgVNxlT"
_I1I0I0O1l0 = "yT9fIv2ig8a98qvKZlEpAJjJ1z/wQj4"
_Il0O01Il0O1 = "hfixK+txx4vQUkbcJqQEQ14BFEaf3N5WHlhotl7vQdT76d8J9Gt3tD"
_OO1Il0O = "9q6mQFHENYvDXIzr1JPSLkv4uVUr7r"
_l1Il0O1 = "Ig/kqgT2WNxmDsJ1GlmZVPl9u0YPc+RxpTuT8WebOkjbBo1OW0H"
_I0IOIll1O1 = "6tFzocdtFjxLJ3h4YTsWp8/aCIj3SgVOEgiWUmF4N9hQtLvQKL"
_OIl1llO = "HEQ45FYYjhYdv62pVF6bFPTog4lfsj2QfToC+wt"
_O01Il1O0 = "1W+7cUSLy45Pjkc94Qba1104oET6Y37Jmk3huFzEFePf"
_I1OOO011 = "f2Y3h6k9NbKdn1qqkyFFR1dQyy49a4xm"
_ll1I110 = "m22fPsUkzRZefMtUFht4mcxo14muzb4IwoHiiuzDKh0i2yKEhloUQztS4qo"
_OlIOl1OO1O = "SdAzytdA3hwEASrc/cR+YQbBWQuYBum8Nz6NLS7kXAQ"
_lIIl1lIl1 = "m01EvElUw6zuxwB0SJTyut4g1ErM1lTP7ZqvTs1VEcsPc"
_l0ll1Il = "r1O/dojk2RrYSF/vtgWHvh7hTHM9Dkrv78HoPQ0rWnlD4oMZLR1I47J9o"
_OO10011O = "arJFO0JWZjvlwXFs6CJXqPa8L+oflssHuK3tkx/h5jikuJtropFrbDAhzMGpW2D"
_O11l101O1 = "TKuznKCgzdVSrIl2+MgACB5zArfjtRTDUwErTPMZr/eDvPc9p/haqDHJW"
_l110IlIO00 = "+OXCjTA8wgDS7zhJw7SNBvD9OZrE"
_O1OIOlII1 = "i3P5C1M4YIh9Li6Q1737VyCGWgfSOcgqCHh+n1nG1FA4hWCJUJ1pBj4Cd8QPP3U"
_OOO01l11 = "ReVLOXNKTHAR1NEJ+13P4aBkH0QrgANrKDAiqB88"
_IOOOlOII1 = "pL11ALlhuvzwxd5b6DmJYJeSzQOSkjXx5TBo93V6"
_O110I101Ol1 = "2/IR4nee/Oc33gjNpOz7d7NHP/7"
_I1OI0IO01I = "w5XfGVP2oRiEvLGR8s44DcRdGHfk7C7/HDrsKHslpP"
_IOOOI000lI1 = "rmuKEkl38/lyovXFEOxHMroFkI7gGVQDguQcarxps787NrJGikRN65NomgxN3"
_O1OOlll1O1O = "dooDMmRBSB44VaWq5akv0sOoncT"
_Il0ll10ll0I = "Emo36YU7PQz/VfgpSef+ScazZ4djGHoeYddrH5qAX6JN6EuyCo"
_I00OOIO = "ikH3wTUhDRjcoHXyXBSfoa88gaQvrr0gFH62JhkiIWwG5UmK5v"
_l1IlOlII = "h7vN0Pyky6xqd3Rp2y/tvE4S5fvJ1Wt+hUWg0UzLgoF0z+AhF8"
_II1l01000 = "5g8eTdTN7EBpMeFA3nQeDxMxsxcYU7vsTMttWqWOEc73RslbnaO8/cOjqDZrp"
_IOIl0O0I01l = "AmpEWhdSanm0zRt9jkOB2YoEKxXVqWOJbUWNeau1F9KqrVH"
_l000OOl = "xtgOCBU9hAzzVMSIM5LLR46ra7jEHw97/4gYYQuhlp1vNXn6i"
_OII101O0 = "JCe94qWpep2X0UwQZJcwRYM9RWHd17Co24b4b5hsGAhI9+t+T8Yd8"
_lll1lOOII = "GQPSXyRbtkR9naJKmigg8TAfMrAeGE7sngG4PWa"
_OIl0OOOOO = base64.b64decode(_I1OI0IO01I + _I1O11l0 + _II01IOI1Ol1 + _OlO100OIOll + _O10l0lOOI + _IOOOI000lI1 + _l10lOIO00I + _I0OIIII0 + _lOllIll10OO + _O01I01llOO + _I1I0Illll10 + _lO0lO1011 + _lII0Il01 + _OI00lO1OI0O + _O11l101O1 + _lIOO00lO0 + _O0O0I1lOOI + _Il0ll10ll0I + _I00OOIO + _lll1lOOII + _I0Oll0I11 + _lO0Il0l0O10 + _lIIIIOl1OO0 + _OO11II01 + _lIO1lI11OI + _OO0lIOO11I + _I00llII0 + _IOOOlOII1 + _OI1l0OI + _lI111IlI1 + _IO1l0lIlOIO + _OOIIIO0O0O + _ll1I110 + _I01lOlI10O + _II1OO1I11l + _IO1ll0llOO1 + _Ol1011OO111 + _l110IlIO00 + _OOIIl0100II + _lIIl1lIl1 + _l01llIlI + _l10Il0Il10l + _OOII0Il1 + _OlIO101110 + _OlOOI1lIOll + _l1Il0O1 + _O1O1OOl + _l0ll1Il + _I0II1OlOlI + _I0IOIll1O1 + _O0Il010 + _lIIO1ll + _Ill1l0I0I + _OII101O0 + _OIl10IlO1 + _l0Il0OO + _OI0lI10l + _lIIll00I0 + _ll00lOl + _OIlllOOOl1O + _OI0l1III1l + _lllI1l1 + _II0Il01OO + _l1l0I0OlI1 + _OIO10OOOO0 + _O00OlI00 + _l1Il1ll + _l00OllI1 + _IO1Il101 + _l111I0l0l0 + _IOIl0O0I01l + _IIl01llO + _I1OII1OllO + _OlIIOlII10 + _OOlI1O01 + _O1OIOOOl1 + _Ol11lII + _II0I1l1I1 + _OOI1I0IIOI0 + _I1I0I0O1l0 + _OIll010 + _I10II0IOlO0 + _O1OIOlII1 + _II1lO01l1IO + _I0OOlll1 + _IOO1OOOOl + _OIIIII10I0 + _I1O0lO10llI + _O0lO11I0IO + _l1IlOlII + _OlOIl0I00O0 + _lI0001O11l1 + _IOl1ll1l + _lI0OI0O0O0 + _Il0l1OO + _IO1llIII + _I01OOlll1 + _Ol1Il0O111 + _l00lOI0 + _l10Ol11 + _O1ll1lI + _ll00OO1lI)
_llOlOOllI0 = _lIOOlOO10l(_OIl0OOOOO, _lllIl0OlIO[0], _lllIl0OlIO[1], _lllIl0OlIO[2])
try:
    _IO0O0O0O = _llOlOOllI0.decode('utf-8')
except Exception:
    sys.exit(0)
_lI1O0lIl1O = {'__builtins__': __builtins__, '_lOIlOI01': _lOIlOI01, '_I0OI0O1I': _I0OI0O1I, '_OllOl10': _OllOl10, '_lIOOlOO10l': _lIOOlOO10l, '_l1lI0IOll0I': _l1lI0IOll0I, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': _OI11O0I}
try:
    _I0II0IIlI = _lOIlOI01[0](_IO0O0O0O, '<s1>', 'exec')
except Exception:
    sys.exit(0)
_l1lI0IOll0I(_I0II0IIlI, _lI1O0lIl1O)()
#PYG4E
