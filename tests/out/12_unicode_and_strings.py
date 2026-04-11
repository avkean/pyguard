#!/usr/bin/env python3
# Protected by PyGuard v4 (pyguard.akean.dev)
_OOlI11l = bytes([193, 111, 234, 175, 1, 241, 176, 222, 133, 243, 57, 169, 2, 105, 116, 187, 63, 208, 82, 179, 186, 125, 7, 236, 210, 157, 233, 224, 37, 194, 153, 86])
_IIIOl11 = bytes([148, 101, 60, 210, 20, 182, 44, 2, 252, 109, 63, 15, 234, 177, 244, 174, 183, 82, 188, 139, 111, 53, 131, 164, 129, 91, 182, 143, 85, 6, 208, 84])
_OI0l11I11l = bytes([160, 176, 148, 119, 31, 138, 234, 19, 176, 198, 165, 57, 206, 133, 194, 2, 150, 134, 149, 81, 23, 90, 152, 225, 119, 35, 38, 3, 45, 223, 21, 67])
_IOI1010 = bytes([129, 212, 233, 177, 237, 255, 50, 215, 104, 157, 98, 214, 42, 33, 218, 241, 208, 114, 31, 39, 112, 89, 220, 221, 219, 234, 74, 152, 95, 230, 239, 235])
_IIOIO00ll1l = bytes([89, 68, 52, 47, 43, 118, 37, 214, 96, 82, 49, 62, 51, 80, 212, 41, 65, 127, 145, 149, 168, 243, 117, 81, 147, 105, 4, 233, 85, 106, 75, 136])
#PYG4S
import sys, hashlib, base64
_II00OlO = type(lambda: 0)
_OlllO0ll = (compile, type, open, __import__, getattr, exec)
_lO10Ol1 = _OlllO0ll[4](sys, '_getf' + 'rame')
_O1010Ol0 = bytes([47, 113, 55, 27, 101, 110, 53, 99, 169, 133, 233, 0, 46, 68, 138, 4, 158, 222, 128, 245, 105, 168, 255, 23, 21, 145, 119, 153, 98, 241, 186, 236])
_OI0OO1O0 = hashlib.sha256(bytes([106, 216, 155, 101, 41, 166, 56, 98, 71, 45, 84, 67, 205, 76, 76, 186, 23, 233, 129, 180, 223, 37, 184, 158, 182, 245, 240, 243, 93, 43, 15, 248])).digest()
_lOOlI11 = hashlib.sha256(_O1010Ol0).digest()
_l0OOOIOl0O = hashlib.sha256(_lOOlI11 + _O1010Ol0).digest()
_ll001OI = hashlib.sha256(_OI0OO1O0 + bytes([92, 227, 37, 22, 235, 122, 234, 134, 45, 185, 209, 218, 56, 172, 241, 238])).digest()
_l0OO101 = hashlib.sha256(_ll001OI + _OI0OO1O0).digest()
_l0lOO1IIO = hashlib.sha256(_l0OOOIOl0O + _lOOlI11).digest()
_lI1O1I1I00 = _l0lOO1IIO
def _l0111I0I(_OIIIllO1O00):
    _OIIIllO1O00 = bytes(a ^ b for a, b in zip(_OIIIllO1O00, _lI1O1I1I00))
    _O01llI0 = []
    _O0OO1lI1O0 = _OIIIllO1O00
    for _ in range(7):
        _O0OO1lI1O0 = hashlib.sha256(_O0OO1lI1O0 + bytes([62, 225, 185, 253])).digest()
        _O01llI0.append(_O0OO1lI1O0)
    _OOIII1IO = [(b % 7) + 1 for b in hashlib.sha256(_OIIIllO1O00 + bytes([129, 45, 218, 85])).digest()[:7]]
    _l10I011lO = hashlib.sha256(_OIIIllO1O00 + bytes([66, 248, 122, 90])).digest()
    _IO0lI100IO0 = list(range(256))
    _lll0I00l1I = 0
    for _l0OI11l0IlO in range(256):
        _lll0I00l1I = (_lll0I00l1I + _IO0lI100IO0[_l0OI11l0IlO] + _l10I011lO[_l0OI11l0IlO % 32] + 130) % 256
        _IO0lI100IO0[_l0OI11l0IlO], _IO0lI100IO0[_lll0I00l1I] = _IO0lI100IO0[_lll0I00l1I], _IO0lI100IO0[_l0OI11l0IlO]
    _lIO1l00 = [0] * 256
    for _l0OI11l0IlO in range(256):
        _lIO1l00[_IO0lI100IO0[_l0OI11l0IlO]] = _l0OI11l0IlO
    return _O01llI0, _OOIII1IO, _lIO1l00
def _OOIO10lO(_l000IOlOI, _O00I1lI1I1I, _O1IllOI11, _IllOl0O):
    _lO1l0101IIl = bytearray(len(_l000IOlOI))
    _IIO0l1111 = 7
    _I000I001O10 = 0
    _IOOI0l111 = 0
    _l1l1OI1l0l = 0
    _O11I0O1OlO = 0
    _O1lI110 = 166
    while True:
        if _O1lI110 == 72:
            break
        if _O1lI110 == 166:
            if _I000I001O10 >= len(_l000IOlOI):
                _O1lI110 = 72
                continue
            _O11I0O1OlO = _l000IOlOI[_I000I001O10]
            _IOOI0l111 = _IIO0l1111 - 1
            _O1lI110 = 45
            continue
        if _O1lI110 == 45:
            if _IOOI0l111 < 0:
                _O1lI110 = 252
                continue
            _lOlIlO0l1I = _O1IllOI11[_IOOI0l111]
            _O11I0O1OlO = ((_O11I0O1OlO >> _lOlIlO0l1I) | (_O11I0O1OlO << (8 - _lOlIlO0l1I))) & 0xFF
            _O11I0O1OlO = _IllOl0O[_O11I0O1OlO]
            _O11I0O1OlO ^= _O00I1lI1I1I[_IOOI0l111][_I000I001O10 % 32]
            _IOOI0l111 -= 1
            continue
        if _O1lI110 == 252:
            _O11I0O1OlO ^= _l1l1OI1l0l
            _lO1l0101IIl[_I000I001O10] = _O11I0O1OlO
            _l1l1OI1l0l = _l000IOlOI[_I000I001O10]
            _I000I001O10 += 1
            _O1lI110 = 166
            continue
    return bytes(_lO1l0101IIl)
def _lIO0OII(_O01lII11OI):
    _O0II1l1lO01 = hashlib.sha256()
    _l101l1110OI = [_O01lII11OI]
    while _l101l1110OI:
        _OIIOl11 = _l101l1110OI.pop()
        _O0II1l1lO01.update(_OIIOl11.co_code)
        for _lII1llI in _OIIOl11.co_consts:
            if type(_lII1llI).__name__ == 'code':
                _l101l1110OI.append(_lII1llI)
    return _O0II1l1lO01.digest()
def _IIO01l10ll(_II11Il0lll0):
    try:
        _OOI1lll00 = bytes(a ^ b for a, b in zip(
            hashlib.sha256(_IlOIllI11 + _lIO0OII(_lO10Ol1(1).f_code)).digest(),
            hashlib.sha256(_IlOIllI11 + _IlOIllI11).digest()))
        return hashlib.sha256(_II11Il0lll0 + _OOI1lll00).digest()
    except Exception:
        return hashlib.sha256(_II11Il0lll0 + bytes(32 * [255])).digest()
try:
    _lOlIOO00I1 = __file__
except NameError:
    _lOlIOO00I1 = sys.argv[0] if sys.argv else ''
try:
    with _OlllO0ll[2](_lOlIOO00I1, 'rb') as _lOIlOIO1I1:
        _OO01l0Il1O = _lOIlOIO1I1.read()
except Exception:
    sys.exit(0)
_OO01l0Il1O = _OO01l0Il1O.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if _OO01l0Il1O[:3] == b'\xef\xbb\xbf':
    _OO01l0Il1O = _OO01l0Il1O[3:]
_I11l1OOOl0I = _OO01l0Il1O.find(bytes([35, 80, 89, 71, 52, 83]))
_OI0lOO1lI = _OO01l0Il1O.find(bytes([35, 80, 89, 71, 52, 69]))
if _I11l1OOOl0I < 0 or _OI0lOO1lI < 0:
    sys.exit(0)
_O0111000 = (_I11l1OOOl0I + _OI0lOO1lI) // 2
try:
    _Ill010O = _OlllO0ll[0](_OO01l0Il1O, _lOlIOO00I1, 'exec')
    _lIOIO0I1I1 = _lIO0OII(_lO10Ol1(0).f_code)
    _IlOIllI11 = _lIO0OII(_Ill010O)
except Exception:
    _lIOIO0I1I1 = bytes(32)
    _IlOIllI11 = bytes(32 * [255])
_O1Oll0lOOI1 = hashlib.sha256()
_O1Oll0lOOI1.update(_OO01l0Il1O[_I11l1OOOl0I:_O0111000])
_O1Oll0lOOI1.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(_lIOIO0I1I1 + _IlOIllI11).digest(),
    hashlib.sha256(_IlOIllI11 + _IlOIllI11).digest())))
_O1Oll0lOOI1.update(_OO01l0Il1O[_O0111000:_OI0lOO1lI])
_l0IOIO0 = _O1Oll0lOOI1.digest()
if _OlllO0ll[4](sys, 'gettrace')() is not None or _OlllO0ll[4](sys, 'getprofile')() is not None:
    _l0IOIO0 = bytes((b ^ 229) for b in _l0IOIO0)
if compile is not _OlllO0ll[0] or exec is not _OlllO0ll[5] or getattr is not _OlllO0ll[4]:
    _l0IOIO0 = bytes((b ^ 47) for b in _l0IOIO0)
_OI0111I0OO = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != _OI0111I0OO or exec.__class__.__name__ != _OI0111I0OO or
        getattr.__class__.__name__ != _OI0111I0OO or __import__.__class__.__name__ != _OI0111I0OO or
        open.__class__.__name__ != _OI0111I0OO or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        _l0IOIO0 = bytes((b ^ 188) for b in _l0IOIO0)
except Exception:
    _l0IOIO0 = bytes((b ^ 188) for b in _l0IOIO0)
_I0lO1OOll1 = sum(b for b in _l0IOIO0) & 0xFF
_IIl0l010Il1 = _I0lO1OOll1
_l0IOIO0 = bytes((b ^ _I0lO1OOll1 ^ _IIl0l010Il1) for b in _l0IOIO0)
_I10IlI10II1 = hashlib.sha256(_l0IOIO0).digest()
_Il0lI1I = hashlib.sha256(_l0IOIO0).digest()
_l0IOIO0 = bytes((a ^ b ^ c) for a, b, c in zip(_l0IOIO0, _I10IlI10II1, _Il0lI1I))
_I0IlI1OOO0 = bytes(a ^ b for a, b in zip(_OOlI11l, _l0IOIO0))
_ll01IOll101 = _l0111I0I(_IIO01l10ll(_I0IlI1OOO0))
_lOII10l0lO = "jkY8ds+fyqDWIGs3nbdmWF78J2"
_OlOO1011l = "OYUsmnlJ70yIe/nC4PIuNGuuZ5IvyF0dGaXRPmCl7j4lu1rWxWP1gINQn4"
_I10l01I0I11 = "/P6fEC5FaEkNXIBb9R7tX1ib+3Ku2qbvGBm"
_I10O0IlI0I0 = "c3uw5l+5YTAMT/DmK1RIyWgbu+CVxVAdjcQN6Ib"
_O1lOl1lOll = "XvBbP0oz3tPQAjUQgcUMcb4L"
_l1O01Ol1l = "z67u/GYUbHZYMyxl93d/MzQdycUcx+sMVO6lXRbqgOx"
_OlI10O1O = "d+QNSnWqKbx55a3UUrsWm8C+p95S60X38ajyUy4qaCWCEsOLTYaJGtQ2Tk"
_lO00IlI = "dptKXmxJ4bcrQuTVirddL7lj/rJHufS2yJYcbxlEzB1AE9HnRmwyQ4fsgK7ml"
_lllll01 = "rzp2jEmhg994njOgrKWNEP0L"
_OlIIlIO0I0 = "iRHUgzQfhPJIc7zkANkJvw5dSgqcYBfxDqvpZumk"
_l11O1I1 = "AXOX/wUJ6W0BHlSSTA2pY0VJgn4jDjqqiJcu1ECYYK3ZDHxqK"
_IO1I0I0l = "T/kJEnNnpsciSBrBwyFCgtTkdBhxUBppokb46KRAJLL+NJibc4e13/"
_Oll11OO = "gcDoL4Azl17U4Py8Feq/WaTXo5pBoh2yL2ndwZbhKQe"
_OO1O01l10 = "KI42hEstlsRU6zjdRYM5fGMabD3zZ6nFiICVpTs70SCT3"
_IOOlOI1O = "HxgjpqewJVTLTpic+ixcPfT0DxiHsmcPqAd"
_OOl101lIII1 = "RPOU6dFAn9MmINW+zJB0NL32"
_Il0IlO1 = "cAmjUcFqKEO2GYiJq3Sm7PtfIQr4tdDFPqIZo519"
_IOO11ll0 = "+qy/Zyw0s4yHmtlYabMwXwye1YCffJY5EIFNeuUVw6aPx1Q5W"
_I10IOI0 = "AkDDIskm08710qUaL3jsWolMqNZFpyGSrn1ToxAX5I4S4EL4bNTtU5ltcha"
_I1l1I0I0l1 = "5x2PYYm7XdTZIq5PR1fpVibVpsdkJxjqRtLl"
_IlO0l110l1 = "G0yXsvazkwV9L921uQZJ40RySgW5DccrPHTT+OBakDeJ"
_Ill1001OlO1 = "PKZacBYfgHOFrThiQ28wkYTw+lF30M"
_I01OlO101l = "jPUhSrbEP//KhnlWrYkit0kxDfGm8Af51KfFayfi4mzM"
_O00OO101 = "OZRSWJD4qxSX7Ur66gzadFTC3oObTk0sf0v2u"
_l0lOO1IOI = "XKo5nRz6sADn8n/iKZ3Q307SjSvSXMPiFm3Rk92sO"
_I1l01101lO = "aLYBm64mrrCi06MTWbl6ujK8QWP0nQsMpoWpla790/iqcDi66pcvJdRhCQ+4"
_Ol011OIO = "pB4Dw2nKBZh4WlImR/hNmZ/8vcFzPa"
_ll0lOIII = "WiDDuZLKGaYCLbpO15oDpxC+bIfcwzm7YmZ7Dk"
_I0I1O1lI1 = "GgNeRTBiA/aaJzQG2a/wjpNSBp"
_l1l01O1O0l = "klrIO6DEw7pLNOdAZM6S+Dcs6HCT/swBuH4g0Gke1zThW6ARrpUlZP"
_lOI0O01 = "cpju1uJLFe4CkxXb7yIv6+IgxqWMbmNDttSyGrFNVS1oT1q9RMcSSfZJ4l2"
_lllO111 = "EQlDjT1HkY6Olk/grjkDlAtPsGUGHwbDYY1jKNApdoyK08DpgktvZAPDEh4RM8M"
_Ol0IIlO = "se8znUhN4P4IUqNaj2QSL85BWmaUJIawdAuaEw+Lz+aOpc8F7sEW9Y"
_Il0OI1O11l = "NtSxrATTArXXbRcCFIFGP5HcwU7/Be1BlllwSEzAimY0"
_I01l0ll00 = "eY+WTIMYFMCGNL6oxyrf0YCdGE"
_Il1I1Ol1 = "HEczqUllm1Ca4xfs/U7pBLCGw0jymCZc"
_OIO0lI0lOI = "qnZG53eYxjbpSkN2bwEfhYlxZQd/ak5s7nt8u+0x6ldk0u8h3WPxk5fdSS/9gG7"
_I01l101Ol0O = "aziLmL6My8mJhb3srS7XRflG1O7U72Gq4lpR0El4NkwYoy5SHoFQV"
_IO0OlOI = "77VcttA8XAZedAmO9kHLIkEiBWHOmU/iGAc4cWjoSX1Y3lfm5E"
_lIO0OOl = "uohp5Fmi2z2bakTVLJ3ICQ/oMjcN9dUy1Y+m0AY5T3nL"
_lIO0001O = "QZdwyi+IxY/zGHI+Yzl48TUrkK"
_IO00lIlIOl = "CR3XrDSbmbrU/HsnCu4K7wsIGRnRSqqU69"
_OOO10lIl1l = "nKuz1sEvZOPyrp4t6xQvtEoRBHc+rBFrSF8QjA8"
_lIII1Il = "oB6TVrsxL6D0UuXG8nO7ZeB4I8ZnEWk"
_OOIIO0l0O10 = "PLWQoKs0+598KjHkXky4GgXapP52Ga6"
_Ill1lllOO = "iQDoKyijK0i7tieKhjBrNfo0dvJKlOibiZuunR/H7l1JJKfFCIcwk1Xwi"
_lIlO00I101 = "YSuOOK30uOnYjudBDJKfc9etrCywIGj"
_IOl1O0I1l = "d+G+Dqom02ARjo98F7nhNdWzE5GzuGob+yjIIK7zKQRZqsQq"
_lO011lO = "tweM3NSY9S9639CTBIsSZhDZiboiC3r1"
_O0OOO1IO = "UGa6XFIIiJvyOGnZhmxEnAyv7mdy"
_l1IlI01 = "FHlhhMewh0VlwlE0JBhT56ew3ECvtya6GwUHCpbBoIjxRsrlUobwLQ0+e"
_O10I0Ol0OlO = "CVnUfrEt3Pi+uXRGhxcBZ7Twj2JXqIxG1u7z+VJPmRqaxvI6DF5"
_lO1l1OllOO = "c8tI/jNxC1CrPPBiH5NgPgCtN/UXIfte9TPI++fk2tmt1sP"
_lIOII0lOO0 = "akKOyOA5/SzLJntCZDU8jC43MLAi"
_OIOO1OlOl = "cHCq+YB8zEyo8JVBUJSWNOsaDLRtrgWvoTWdm7ny5IYjAKx"
_l1O1OlI0I10 = "pZvvfwkwh6OZbK88UTJdOmNMMNi+4qo+a"
_IlI0I10O01 = "pBRzUqgM2QzPu8xY1gAgTdFRDrN7RD0XhYD"
_O10l1OIl0 = "p1vriEO/8dQG5FE3glnpz3m0JemU4BvVoISqxu3nHxJFxkN"
_OII0000llI1 = "8IM8o21idAvjsB3M8faZu4tMdCaibbZyGIND8BcapHx"
_Ol0l10Il = "hJ4sfsY2b3Xmym7Fn0L9G0+JcD7XEmfcv8MurHnYfh4KhoVexSs+3C/mCSGLXe"
_I0001I1Ill = "yoriq5Zpb0QORtNN7Qdd8JkPmE8l9MyKf1v2ivZfrmoF"
_l0I0lIO11II = "Co4dqcsxK4SDTPhy3G5ecr5Ht8DLESCT5YZr6HmMW9YQnBv"
_OlI0000I1O = "jjoat1F3ur1TxL1JaRgHwxVllW4Oqlj32xjPCNzsdVyGbhzG3uxvXiYJTNut"
_I1lOOOO = "XvuuySqokYjmUfoiHjiel8o9M"
_IIll001ll = "o3B0gOr+jji8BH919Ni5ZWW5YWJCN6VZScp9RdKHC596KytYXYNlr1PIrEiRtEr"
_OO1OO0IOlI = "/8kZv8zpNPoyFz2RyMR+MJdlH90WH8tx"
_O1lll00O = "8SUrkeuRDCDUtc/HWDJcbDTsEbEDxeKvuptk/arq6inp4l"
_I111O11OO = "GBnCYL3iq5FHWDINJs5pWr3OZGTc8UgcY"
_IlI0llOI = "XP4+sMygr0W+giSNC94fhtUI1XzYIj+wPCDq0ecOVkm+bdfJ66zfyfYGeE2GQFS"
_O1IOlI00111 = "2RyAnjgQzxR9rAj3sm23vHm5duP70tfLIESK7t82K1"
_IIIO1IOI0 = "hfjZ8Ggu+pFKl+n3b8j/s0PIhClCSYxjUSAOIh4JGnCvY8H6ouuLR5JwL"
_O1l10O1lOl0 = "u3CHFChRQ4Y2AVK26EMv6lCP79pN26rvP7Z+gq1HG35HY/x4DZiQV03dw"
_ll1l1OIO1II = "AyG6PE+yNvU9qy7pdA1y0kkheG0U50wuHJyTi6Q6wH3QD42hJDZgy"
_OlOl0O101 = "smYknaE0o4IY0lRxWM3FK1NhSk"
_I1IOIIO1 = "mjgS53c8yuzdyTZxl35RwyE0c/kQEHrvvTwPMlSHhWCG3U2YdzzUzQ"
_O1l011O = "9j7D065hhmsrN0GqpE74DIyCKMzfU2EZeZVj3X/1yWkKfUWx41k0qo"
_l10lO00I1 = "Eb0dOxwBs+RBpyidx9zp9pXxObjTHHVDg0GVaEWLjhgxaOyG"
_IIl0lOl00 = "QjBzabWkbo5TKBgRZVRYxbtmqG8WO5i+iiONAyHqQnB77s"
_ll0OlOl0 = "k9S1DXRISa2H14K1h6l1KFbdrqFNWGoeSWVKyYgKRgymSDAP8OcQ"
_I01lOI1O1 = "ioSxrhjXwaUM2aF0il+HrFrAV7dirQQh88FPS8l"
_Il0Il11 = "Ev2cgRXmD2ZO2kqffcI3AYRR"
_OO0O0lI = "fRgTIeulaCLaYmX8J/rB692pQ1R/1itYziYMfXb7tT6TvkxSD"
_IlIOO11O0I = "9uAJlI+lunJYbz8rfJAd1YID3JitG0jdbCL6Fn"
_IIl1O0l = "YGgngnVl14Aak9SN+JHjLWQYyL3otg1baUi4uxl3tTlooYzkB"
_IlIIO0lI = "9imqZ3/NXqP7/gor6X+nAJyxbJN2sSVSbYya4kI4vzVA04StF0rA3HQwmNKezKw"
_I1IlOlI1l1 = "bczTwk2VKLMw7bQje6dtXOYj5676UuG8janwh+cVeZmg5"
_IOI0O01 = "1MJZ4NdGSTD/guy7NXEOw9XSE"
_Ol10010II = "EbJqd+jA/Zj/L7oBGItkLfS+QnFqV"
_OI11OOIl = "GXusLVae/v1jBSs5bw=="
_l0l0OlI1 = "drOmZH5LyNQga5Y974SlhosG8g44+30yaQqpP5MIfLc"
_OOI100O0O = "I8pkTymDm25ZJBfImO+dEESdBJozlJgZXOwedfklVhn"
_O0Il111O = "nQrCljm+4+6G8JbJdCrdjIyEGNdXVGbOhKgyVQz1"
_I0IO1IO1OIO = "nUCRy6rniPSF+8AYRxKzsIeWXuhh679M74X"
_l1101OI01l = "J3SkNpaH0cYgYk0yUHX/J39VRPMMvfPP9cMhHUyKuhK"
_lOllIlI1l = "kxpTt8jg9W8ZVylBCfCmqRtE1HG4sxDeMFCK0Koo0R/nEuuyTeIzgEZibr5a9N"
_I0O00IO = "2xBPmHc2NArh5YvOVpqSnHQ5UgLDrFtSvhpPIWTyUplYDB5zocu+oX67"
_l1l100l11l = "2R8Culont9L9IcPYpba5ZgF4VVVz4f2rQIkgnFzIVspw+EiLVU8"
_O00lOlIl1l = "613iZ6vBELW4sI2wCVG3g5VhYYkRl2srnjknoUdSh6i3IO88r"
_lllI0OlO1l = "TbkX1pdYNgdzmSaaLnVWPTFNtoNgTvsG"
_l00O00I0O1 = "iG4BzNHOPbgsXMaKOeQJXbpOqdmmCAOr3uVLX+M22lF22878CYmuvOkuIc"
_IllOIOIO1lI = "BPqIm+/+ov1uX8Pf+aTKxW1rfsmC4kONhoa4x/U8aT"
_O0110l1l0l = "gzGlwTY0WTcjAurEF6gL2F48"
_OO0I101O1 = "FkDnsWxNTZ6zrf4eKVmAtHFbqj1N2NHsf2RIZTjtce8vtCu9eD"
_lIO0llOIlOI = "uhuZAZJ93zWW5jKN+0JyPU6TDfx9HCMjOCoftiWT7e9PcOYE+k26"
_lOl1ll1 = "RbJiigp7N4dhv0P//zKRijXaLvNNHs9wUOCH"
_lOOOIl00l = "iZEvGftbKKKCMetWN5ChCBhc9OBfq8CJ9wf2evM5kZgwqEANJXo+YdGbi8XU63K"
_llOllI00 = "gXwYjwlbFf9TcCDY7ZbxJFHZ5NkEQBtdETkfgPFPf8AWqXHOc0uBbUPQogx5i7Q"
_O0l10lO0 = "aA7qnvCtIsVya4C2OYYj5i79gyzo7HaVF4EuDkKnd9QGyeCL/mvwzsH"
_IlOlOO1lOO = "O9RXH6zPZ/vVF2sorpXayj3ZB6SZH"
_lI1lOOOIlI = "4YeszZ/jz+IqStJTjgYELchPgCxVDSY"
_l1Illl1I = "rW6NqOL6t99Cu4quxU/iZ9LvrR"
_O1010OI00I1 = "pRAQTueCz+obc4DCz4c/e/uxaHJLzwn6ZqWH5JIL53fH"
_IIlOllOI = "XIsKr2qkN/Jbz3l6hd345wq5SfwFeEGkow6txsJHJZ"
_l0l0IIll0 = "rhnFoW+x30lQBJtxCF/31RaC1k"
_IOOOII010l = "l2e56CLENh0VjegGaw9lkmU71oSV1HYb+VRL0u05"
_Il1OIIO0l = "CEJKOU3iuYw+ztgYR/4FWlQUKS/QloUfTpT4l"
_IOI111l1 = "gBBUXaNcFMkXTctvRK90vgLA2eVh4YAciecZyl01IxXkYR3b"
_l0OI1lOO00 = "Iv8N1gkPIsysYvdGxXg/QS2VFSLrvsRiQ1"
_lI11I11 = "2A7+UfLvfOHQaQXYkk1BTTKNY/O3xyqvTkbvtiTlO"
_OIO1I1lI0O = "QtYgHhjFEaR2k95ZqWF63W+/+/HdnvqQZ2fvr+evLB4Y"
_IIlI0IO = "R4ParFi/DsvqPM+EuESusiIo8"
_O00IO1O = "ozbQCaji5Pbd7DVhH22oobP7WJqM"
_ll110IOlI = "KAqwOE7MZB0Lku1gMkXTQ6JwYiJZvfHN3d6s7nmOzlB4ELFnaf"
_I0IOOI0ll = "xmFU8HUOVKTvSjndtvcXQDiUzMbwJiKQE3GW2yBr/1gy+JO"
_Ill0lllIO11 = "AqlIDpTICXzlGIdVzez+/sW/+bVyRYYhe3wkRdqr"
_IlOl1OO1l1 = "jB28v/jWnOBnfkCAH9yybHw2e2do"
_OO0l10I11Ol = "ecyEp9gybW7+32rUkhn3FH1aY/gan/L40S5lzqiA8bfqC1LjdT"
_OI10l1O = "3xAd54brRmVKYvwHhjcoI9eVyHwbj54L/pEa6JSpt"
_IIIl111 = "2XXqeQQSvr0805tIdpxnxaR0JB3SwyFfMi/VgPb5oW49N8Oygob"
_IlOIOll0lO1 = "rR+KzHkgScjUmh6Z7R+TVstwdeKuM7OV5W+IC/t5WM9QNJUG"
_lOI0I0ll0 = "nhhcrzZaSBrGc3+8RKjNnUCAbq8D1FBd8XpwLVLg/syQfEyvWt7rPxwS6SI"
_OOO1lIO01l = "ggsFy5Y79WNQ01C6Y0ALhPUHjyi"
_O10O0IlIO10 = "P48P/mlvQnpQqxYaTA53LJuWY3xUH+7SE1bRPsTJxzvKvFeWT1Kw3H"
_OOlOIOOl1O = "VchiuQ+uxBJXfFmMWesZu6fCPfwm3DHYH2/saHo5"
_OOOII0ll1ll = base64.b64decode(_OOI100O0O + _OO0I101O1 + _I1l01101lO + _ll110IOlI + _O0l10lO0 + _O0110l1l0l + _Ol011OIO + _OOl101lIII1 + _Il0Il11 + _I1IOIIO1 + _O10I0Ol0OlO + _I0I1O1lI1 + _I1IlOlI1l1 + _IOI0O01 + _IIlI0IO + _lIOII0lOO0 + _Il0OI1O11l + _I01l0ll00 + _O1IOlI00111 + _IIIl111 + _lIO0llOIlOI + _I0O00IO + _IOOlOI1O + _I10IOI0 + _OOIIO0l0O10 + _l00O00I0O1 + _O10O0IlIO10 + _lO011lO + _lI1lOOOIlI + _OO1OO0IOlI + _Ol0l10Il + _O1lOl1lOll + _Ill1001OlO1 + _I01OlO101l + _I01lOI1O1 + _IIl0lOl00 + _I1l1I0I0l1 + _O1l10O1lOl0 + _lIO0001O + _O00lOlIl1l + _OlI0000I1O + _Ill1lllOO + _l1101OI01l + _ll1l1OIO1II + _OIO0lI0lOI + _lOI0I0ll0 + _l1O01Ol1l + _IlI0llOI + _O1010OI00I1 + _IOl1O0I1l + _IOO11ll0 + _Ol0IIlO + _lO1l1OllOO + _l0OI1lOO00 + _l1O1OlI0I10 + _OOO1lIO01l + _I10l01I0I11 + _IIIO1IOI0 + _IOOOII010l + _Il1I1Ol1 + _OI10l1O + _l1Illl1I + _IlOIOll0lO1 + _IlIOO11O0I + _IlO0l110l1 + _OI11OOIl)
_l1O00O01lOI = _OOIO10lO(_OOOII0ll1ll, _ll01IOll101[0], _ll01IOll101[1], _ll01IOll101[2])
try:
    _OIOO1II = _l1O00O01lOI.decode('utf-8')
except Exception:
    sys.exit(0)
_IIOO0Ol = {'__builtins__': __builtins__, '_OlllO0ll': _OlllO0ll, '_I0IlI1OOO0': _I0IlI1OOO0, '_l0111I0I': _l0111I0I, '_OOIO10lO': _OOIO10lO, '_II00OlO': _II00OlO, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': _lOlIOO00I1}
try:
    _O1IlOO110 = _OlllO0ll[0](_OIOO1II, '<s1>', 'exec')
except Exception:
    sys.exit(0)
_II00OlO(_O1IlOO110, _IIOO0Ol)()
#PYG4E
