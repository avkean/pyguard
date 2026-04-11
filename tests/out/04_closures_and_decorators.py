#!/usr/bin/env python3
# Protected by PyGuard v4 (pyguard.akean.dev)
_II0l0101lll = bytes([169, 202, 182, 68, 56, 5, 57, 125, 202, 62, 0, 9, 234, 249, 10, 197, 227, 95, 208, 170, 150, 215, 82, 192, 29, 247, 9, 199, 24, 92, 128, 191])
_O1lIlI10 = bytes([187, 10, 58, 102, 245, 163, 154, 188, 80, 21, 122, 87, 188, 55, 254, 128, 55, 205, 219, 66, 103, 172, 97, 11, 68, 58, 120, 228, 255, 133, 73, 21])
_IIO0lI1O = bytes([143, 225, 172, 184, 197, 86, 195, 141, 147, 102, 204, 237, 132, 193, 0, 89, 106, 67, 120, 100, 85, 27, 141, 41, 221, 43, 25, 212, 132, 200, 82, 135])
_l1lll1lOlIl = bytes([154, 251, 50, 94, 149, 170, 202, 222, 65, 172, 222, 43, 15, 104, 111, 203, 190, 7, 70, 220, 9, 244, 130, 151, 218, 161, 21, 160, 173, 6, 124, 244])
_llIII0l10Il = bytes([210, 224, 36, 63, 61, 138, 253, 214, 252, 239, 239, 220, 209, 218, 138, 240, 244, 2, 5, 239, 79, 87, 123, 40, 35, 83, 228, 156, 209, 82, 229, 106])
#PYG4S
import sys, hashlib, base64
_IO0O1OI = type(lambda: 0)
_IOlIOl0 = (getattr, __import__, exec, open, type, compile)
_lI01IlIOO0I = _IOlIOl0[0](sys, '_getf' + 'rame')
_O0Ol10IIO = hashlib.sha256(bytes([128, 176, 82, 4, 44, 142, 252, 113, 123, 46, 164, 212, 243, 158, 5, 175, 164, 248, 97, 233, 231, 232, 148, 242, 180, 205, 96, 38, 253, 122, 158, 187])).digest()
_Il10O1011 = hashlib.sha256(_O0Ol10IIO + bytes([133, 132, 215, 72, 68, 57, 52, 12, 247, 92, 63, 63, 196, 15, 184, 56])).digest()
_O0l10OO1O1O = hashlib.sha256(_Il10O1011 + _O0Ol10IIO).digest()
_IO01lIOI = bytes([188, 74, 106, 104, 175, 130, 81, 62, 159, 253, 234, 79, 3, 191, 78, 147, 174, 102, 159, 90, 228, 118, 236, 236, 73, 19, 100, 166, 125, 153, 39, 142])
_I0OIOO00 = hashlib.sha256(_IO01lIOI).digest()
_IIIII0lII1 = hashlib.sha256(_I0OIOO00 + _IO01lIOI).digest()
_IOll0111 = hashlib.sha256(_IIIII0lII1 + _I0OIOO00).digest()
_lOl0I1OI = _IOll0111
def _IIIIOI1O(_O1lO11l):
    _O1lO11l = bytes(a ^ b for a, b in zip(_O1lO11l, _lOl0I1OI))
    _l0011IOll = []
    _lllll1I1I1I = _O1lO11l
    for _ in range(7):
        _lllll1I1I1I = hashlib.sha256(_lllll1I1I1I + bytes([187, 84, 41, 49])).digest()
        _l0011IOll.append(_lllll1I1I1I)
    _I0I0OIIO1OO = [(b % 6) + 1 for b in hashlib.sha256(_O1lO11l + bytes([136, 201, 238, 230])).digest()[:7]]
    _l10l1l0IIl = hashlib.sha256(_O1lO11l + bytes([232, 123, 73, 199])).digest()
    _lll1OIlO = list(range(256))
    _I0OIll0lI0 = 0
    for _I1IO0O1Oll in range(256):
        _I0OIll0lI0 = (_I0OIll0lI0 + _lll1OIlO[_I1IO0O1Oll] + _l10l1l0IIl[_I1IO0O1Oll % 32] + 101) % 256
        _lll1OIlO[_I1IO0O1Oll], _lll1OIlO[_I0OIll0lI0] = _lll1OIlO[_I0OIll0lI0], _lll1OIlO[_I1IO0O1Oll]
    _l00I0Ol = [0] * 256
    for _I1IO0O1Oll in range(256):
        _l00I0Ol[_lll1OIlO[_I1IO0O1Oll]] = _I1IO0O1Oll
    return _l0011IOll, _I0I0OIIO1OO, _l00I0Ol
def _O0I0l0lI0(_I0IIl1Ill, _ll1lII0, _llIll1O0, _I0I0lO011I):
    _l0111O11111 = bytearray(len(_I0IIl1Ill))
    _O0Ol1Ol1 = 7
    _OOIlIlO = 0
    _OIOll1l0 = 0
    _III0l1OIIO0 = 0
    _OIl1Ol0lIl = 0
    _I010OI1IO = 199
    while True:
        if _I010OI1IO == 50:
            break
        if _I010OI1IO == 199:
            if _OOIlIlO >= len(_I0IIl1Ill):
                _I010OI1IO = 50
                continue
            _OIl1Ol0lIl = _I0IIl1Ill[_OOIlIlO]
            _OIOll1l0 = _O0Ol1Ol1 - 1
            _I010OI1IO = 13
            continue
        if _I010OI1IO == 13:
            if _OIOll1l0 < 0:
                _I010OI1IO = 196
                continue
            _O0l01OOO0O = _llIll1O0[_OIOll1l0]
            _OIl1Ol0lIl = ((_OIl1Ol0lIl >> _O0l01OOO0O) | (_OIl1Ol0lIl << (8 - _O0l01OOO0O))) & 0xFF
            _OIl1Ol0lIl = _I0I0lO011I[_OIl1Ol0lIl]
            _OIl1Ol0lIl ^= _ll1lII0[_OIOll1l0][_OOIlIlO % 32]
            _OIOll1l0 -= 1
            continue
        if _I010OI1IO == 196:
            _OIl1Ol0lIl ^= _III0l1OIIO0
            _l0111O11111[_OOIlIlO] = _OIl1Ol0lIl
            _III0l1OIIO0 = _I0IIl1Ill[_OOIlIlO]
            _OOIlIlO += 1
            _I010OI1IO = 199
            continue
    return bytes(_l0111O11111)
def _I0IIO11(_l10011OI):
    _lO01lIl0 = hashlib.sha256()
    _O0I111I1 = [_l10011OI]
    while _O0I111I1:
        _OI1O0O0OO11 = _O0I111I1.pop()
        _lO01lIl0.update(_OI1O0O0OO11.co_code)
        for _Il1O1lll in _OI1O0O0OO11.co_consts:
            if type(_Il1O1lll).__name__ == 'code':
                _O0I111I1.append(_Il1O1lll)
    return _lO01lIl0.digest()
def _IlO1lIOll(_I0IOlO1I11I):
    try:
        _lOl0I1llOOI = bytes(a ^ b for a, b in zip(
            hashlib.sha256(_Oll1OO0I1I + _I0IIO11(_lI01IlIOO0I(1).f_code)).digest(),
            hashlib.sha256(_Oll1OO0I1I + _Oll1OO0I1I).digest()))
        return hashlib.sha256(_I0IOlO1I11I + _lOl0I1llOOI).digest()
    except Exception:
        return hashlib.sha256(_I0IOlO1I11I + bytes(32 * [255])).digest()
try:
    _O0llO0l1 = __file__
except NameError:
    _O0llO0l1 = sys.argv[0] if sys.argv else ''
try:
    with _IOlIOl0[3](_O0llO0l1, 'rb') as _I0111I0llO1:
        _IlIO1II0l = _I0111I0llO1.read()
except Exception:
    sys.exit(0)
_IlIO1II0l = _IlIO1II0l.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if _IlIO1II0l[:3] == b'\xef\xbb\xbf':
    _IlIO1II0l = _IlIO1II0l[3:]
_Ol011OlIO1I = _IlIO1II0l.find(bytes([35, 80, 89, 71, 52, 83]))
_OI0lI1OIO0l = _IlIO1II0l.find(bytes([35, 80, 89, 71, 52, 69]))
if _Ol011OlIO1I < 0 or _OI0lI1OIO0l < 0:
    sys.exit(0)
_OO0OOIIl0lO = (_Ol011OlIO1I + _OI0lI1OIO0l) // 2
try:
    _lOOlIOIOOO = _IOlIOl0[5](_IlIO1II0l, _O0llO0l1, 'exec')
    _l00IO10O1l0 = _I0IIO11(_lI01IlIOO0I(0).f_code)
    _Oll1OO0I1I = _I0IIO11(_lOOlIOIOOO)
except Exception:
    _l00IO10O1l0 = bytes(32)
    _Oll1OO0I1I = bytes(32 * [255])
_I1IOIl0 = hashlib.sha256()
_I1IOIl0.update(_IlIO1II0l[_Ol011OlIO1I:_OO0OOIIl0lO])
_I1IOIl0.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(_l00IO10O1l0 + _Oll1OO0I1I).digest(),
    hashlib.sha256(_Oll1OO0I1I + _Oll1OO0I1I).digest())))
_I1IOIl0.update(_IlIO1II0l[_OO0OOIIl0lO:_OI0lI1OIO0l])
_I1I0OOOl = _I1IOIl0.digest()
if _IOlIOl0[0](sys, 'gettrace')() is not None or _IOlIOl0[0](sys, 'getprofile')() is not None:
    _I1I0OOOl = bytes((b ^ 145) for b in _I1I0OOOl)
if compile is not _IOlIOl0[5] or exec is not _IOlIOl0[2] or getattr is not _IOlIOl0[0]:
    _I1I0OOOl = bytes((b ^ 61) for b in _I1I0OOOl)
_I1IOOl1 = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != _I1IOOl1 or exec.__class__.__name__ != _I1IOOl1 or
        getattr.__class__.__name__ != _I1IOOl1 or __import__.__class__.__name__ != _I1IOOl1 or
        open.__class__.__name__ != _I1IOOl1 or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        _I1I0OOOl = bytes((b ^ 42) for b in _I1I0OOOl)
except Exception:
    _I1I0OOOl = bytes((b ^ 42) for b in _I1I0OOOl)
_l1I0Ol0OO = sum(b for b in _I1I0OOOl) & 0xFF
_O11lIlO = _l1I0Ol0OO
_I1I0OOOl = bytes((b ^ _l1I0Ol0OO ^ _O11lIlO) for b in _I1I0OOOl)
_Ol101l11 = hashlib.sha256(_I1I0OOOl).digest()
_IOIl10O = hashlib.sha256(_I1I0OOOl).digest()
_I1I0OOOl = bytes((a ^ b ^ c) for a, b, c in zip(_I1I0OOOl, _Ol101l11, _IOIl10O))
_lI000ll0 = bytes(a ^ b for a, b in zip(_l1lll1lOlIl, _I1I0OOOl))
_O0IIIl0Il = _IIIIOI1O(_IlO1lIOll(_lI000ll0))
_OO010IIl0 = "qbuWKfEbH3vK9qNrPfoxfc/3zb0WAf4i2wbD6"
_O0I011l0O = "xand18/1nGNv4qKcBxqUhgZDjH"
_O1lI0I1 = "LDwnzW1I9MfOqo8COgM7iEq6rMpCs/PKHVI6sVe0Wnqol"
_IlII1llOO0 = "EzNnQgbm5dfQWqWD2PYZWvh4FeNaLZBkqU6VcNGgyQJj2N6LXHwJ"
_I1I0IlIIlll = "hLvCeaexys5MHnW2m6Q9SHtASIqbtsYfgyNaWfeSyoYaVC8iAR2Wu/WCpz9e+"
_I1l1Il1llO1 = "d7agdKFFS5XBJhK1J4u5naj+UrJjNfziIUQ4lpNLA00ISWyfIgLRS"
_I01lOll0 = "QNs16HqJPBAu6RYfFrMRy45hsz4YwEDG4eq"
_l1ll0IO01O = "yavTSReJjfAZfDwk6QqPe9/bZN0glH6A"
_lIIOOIOOIlI = "GxHpWlb1zb4aFMvv4x34WlLzbfbaGluoTx/mRal"
_I0ll00l1 = "ZU5bjUgrhzz5ESRbuP+CY2kEhjCsPnLZtozGv2"
_IOl1I0Ol1I = "p0DSfT6zFXTl3sb/FQAaoCisPSoO38zXafYNgMdOozam"
_OII0ll010OO = "lHy2abRwPVX5x9aNUFJBwDvSg/Z+VP5bOSxcdRwou3EzM1kM2Y"
_Il011OO1l = "ZUcNL2c7G/RMHTbCFcM1EXmG"
_IO1Ol11lO = "Uj/8nJhtipfBRe/i++J6NnWMCDu5m/VIyhq4ukqSh21MauMavTUM"
_IOl1II0I101 = "HL3lHiYcqpeYXvnHx4S+hMkZ"
_lIlOOOl = "J5pzj6UCRKnbkk2FeU+dArtBQ+68jXtB2Rf7r86U9KMXSl87db5pnJHksdWJyH"
_IIll0lO = "WtCAQlYnx3tc/nLCe0sFOl9GfH"
_OIl0llI1 = "7nufdYYjw9KdQivvREVZDavSdt9"
_lOIOOIOl = "TIJkM06d1ayQjBBzi9SLEym3kaFS8YZewFeJ2DEh/4h5hHsJdWBymcoh16rl3eN"
_IIIlI11 = "UKyvLUPHN97qSxj6bL5l4/BOOUVqs58e6HSeb/YusCLX5z5bIdOykMqaY"
_ll11Oll111 = "fgB20ZTU4krqHXhhes4apcHSJJJsTW3McxPJR+85af0mNpbTfUIFQ"
_O01IIl1 = "89YHosgqhpEqS4qsgs1NvVMIl5nLDFSFg/BFxWg5o0VNHPxylxRq4XYGthP"
_Il1IIO11 = "YPVwhYMXX4bPUaG10celZat4l2PBkcBD"
_I11111lll0 = "81o2frs1uwqoWYCIQ9XshmUGYooAMv0YFUWSkB6XeIkg61/F"
_ll001OI = "o9thw0IjxHnUHjs2j+3vF/43"
_O0l0I01OI = "Yhi9bYEKODdgUckoZTKy8mHFbVGkVAHaW8"
_OI0lIOO = "/kT47CkQFry7+hs7L1HXfi/28A3F4i90BD+N"
_l01I00I0111 = "ZZxY6qgUPA11feG59yYD8vLASByf+"
_II0O00O = "uLiwHBuNy5WKjRgCIXU49tRiYN3laUfpgntRoLNpzmXLNIr60kginO"
_OO0I0O1lIl = "fSUrtjQ4JOZrCRNMTWcNyJ2+SLSjwBWRcNNV4+UkXa"
_lO1010O = "9gXPOAV+XpGfcFOd2kwIcmxn23Wr4+rhf3"
_OIlOI00 = "CmbgGJ1TvTQbW4s2k0JFRls+urk6MKd2mrt"
_I0O010l = "O7zNTNfA4GfK07+Ef+LYd7ODSEMwRJBD/"
_l0IOIO0l = "tXS+6XOopMb4oBfHG9NUg9fS"
_OIO1I1I1 = "CFEwQsqNDsFOHVZ4gHohTcybQB3eJbg/Lx25kyoNM2bZv5Q"
_I11l1llI1I = "gAJRGWfzLRK63mHrKtll2wq/I+Y0fjNVB1YQQwe+7dgBqXJXmP2o9PVUlamcDeb"
_l0O00l1OII = "dFpeyW0/Gf/tIrORaVbJqCq8Vee/Elq+ysMvVTrVj7O3CZ4jlL4Uew5bcXMj"
_OI111l00 = "/6XKnBhVIVFtxBgW0LeMBB+dKzflgW37I+RJF3wBNTHcgqXhfIGZt4p"
_OIll0ll10 = "l11t/YHM0FufJR8j6pzufQfkMikgUqBEs5UvSDykYwfCIC79moWLMU"
_IOlI1IOOlO1 = "Q++QnXb7Sg0oxSHioyASEwFt"
_OIO1I11IIO1 = "pj571+wiglS79KL4I4rRYfI8azweDKO3/UTQz71Gng5eVfc2xKwwq"
_O0OO01IO = "zpe1Svc4avLws4n0PWZNI+sfWVycWbO9Nj"
_lIIO1I00O10 = "EOfaKrmXXCmizB1EkQMo+4Np+y4orId4"
_OOlOIO1IOO = "YK5mjgoFZczXLVTGKbO1i4UyRczkLJQ2K5"
_l0I1lII = "6o1fpfn/ht+W+heOsvGXNxx/aY"
_l1OlIlOl = "DkReR7LXm+EmJglLTi33IYW6WFXAOddN/x"
_O1IOIlI11l = "vgccGRDvvOi2EEGxjD9j2NsNgXYlx/boKdbV1TpbdC185W"
_O0l00101I0l = "EF+YGbzFL9zFWYxMwIk5PTg0T"
_OI1100IO1 = "TW5TCdTvhqeLJgc8Sbn+dpveQYohU7ew0+"
_OIIlIlIlOOO = "55NaEdeOFbCnYvPYoLzWW9hpvB3vyfvnXblBsQCOzvl"
_lII0001 = "BXQUqS24jGkqsUtOc2Vitx+eFcgbFg5nH0GZRcyymMeBH+dkZWUdnHMHa"
_l1IOll00I = "WNqOhjn5FeIDPWtUahkcVgE74jgDdGJFz4"
_I1OOll1100O = "fMnK4zkKsEXPgh52P4S5809EI7i5k9VeRztidIYGZxPklNF/U"
_OOI1IO1OllO = "62eTGkCCS+ziRallhHT17nlYQkD"
_llIO1lOO111 = "LJg6/NPYQzInIWnhRzKCG+YggrbE5RXX4KUNTzVhYnMzxb+IxQCLzLkeAfL"
_lOOlI1ll1 = "8vY7icT2nTWaTe2DXimxEF4pCOpRTfieFiCCexRxztznXAX+fHMxt"
_IOO0OOlI00 = "FASyS347J/CFsGm/HsP9b4LGouRFQNO8TtCt730ehd"
_O0011I00l = "9xjPg2CB6qUI7rsC92sTqdwrfRPwk+8eBDldq9eUe"
_l11l0OlOI = "ETNrNYC3sAsIpwu+DyPdlT+efkz79"
_I1l0l0IllIO = "6kv4vmUbBtTP2b2vGm7XgMGzuTOTWv6"
_IOO01II1 = "xYeZZ8fenA4zJvazQeCPE4lHa"
_O0001O0101 = "OwteSQt8MoHLkBhMKlS3TpSrM4io9YollPTZ8W"
_O0ll0Ol1 = "Sl6WJDRDAM/nAmRrvY7uiDe8gDvwkv6OmH5KHm"
_ll0IO01 = "FKzLdiYmbiapKkiAHfU4IKf5yv9o1S7uzko1MT0anO"
_O10llO1IO = "fyXVuoGs6WND5XddwDWz7PiVE6itPJ+"
_IOI0OIOO0lI = "G65QRFCuZtz5qHPoQgE5LOgbW8pCq5ZXF3pvUkD+zkFifOkni"
_lO0lOll1 = "9g"
_l00lO1O0 = "yP1cJePaJnyxEWSW1BwacZd3I"
_O110IOII = "Ctomc3FICisAup3hbvYc1R+pdx+vREJIjN/h7kyRpl/1cjDZxZ2wiJL"
_I0001IlI0O = "/+rBzbXMRD6gU+Mcw3QXuPyOk19hUBJvSFfp9BIWIb67NhWQUD"
_Il0OIIO1O0O = "hTqCJSP1hAvtxQKV4d0fB5+RfyiZQ3BI2Uigzf/ZzIdM"
_IO10l00O = "iWtwTS8BSiUzwenpK612pc3iHuJVl54cFVE04Nyu6wffxvFjx08npCM4FVBY9"
_O0IlOO0II1 = "ZyrkyQm6lzsyO2bThLhASOZZjhOWcEYdONCC1BHR/8rppJ13"
_lO0IO100I = "Gx2MZ0gsgb4NQ2AdT0vCKIus"
_l1O1Ol001IO = "9aPOWbACflOZVBGvarpoWkp43coY/WhA"
_III0lO1 = "KlMRlR7xgwS2h+f90FalzXBbPkq6ZhpMQ56IVDWqLlI"
_OIO00IlI011 = "6vseiK4hHNCoACLDnEG4RNsfQVX6ZARIeVw"
_OIlllOO = "smjcWDJYu1ZCDAxqKxk+0z1J72UZQpAcPqnrubP8Hgxki0/pxlr68nRwqZE01"
_OO1I1l1I = "AR18EcowrkWbrWetlUf1DYIG15vjAqaZ3gUset0xK0gvHxPmo454j6CvPbI51GA"
_IOlIl1OIO = "zNBkJFfMRcQdTwLGbQkUwt2973"
_l1II0111OO = "W8Qhzdi00SlFv3bAp+zvnoXd+61ULEVjsYRqAW8u"
_OlI10Ol1 = "VsX/yiT6b6mpp6p/5/5BkjLodh0Yn"
_O00II00 = "Xzga6NdkDwm4vGClMPP+uiEEdSiKFEo1d"
_l000lOI1l11 = "XbCnEgHOfVi7W59bdqOxcHNvRNyyd"
_OI0O1Olll0l = "ImuBDx3oOwckG2TBYIXx0FXNIlw9j7e"
_IOIO0lOO1l = "qU18NMBYOvCHztx0b1xukYfkJfiOrqfcHBVlw808r"
_IO1lIO0 = "YqQpYtK6ZioLQK+BPE00qA4Mz"
_lIOIOll0Ol = "xEAry5iTDn7mf8Az4RVwU3jBiyJ7vg7dSN3w"
_l0OO0I1ll1 = "a1G01Npz6/oe71YpcGMp2fx5XQ4uCSf"
_I1I010Il = "OVhGYxUT/3QX/WWBQpRqr8VRvY2UL"
_O0l100OllI = "3EmbsScsKSDXMkj6Bd/xSMFYYsB3xBb39W1wC299dDMIvWkPlx6/hL5f"
_I1OlllI1Ol = "ehjA7bm7c43PBRMeuBvdG0bekxuTcSx7wB//RpO4T/+9l5eTphq6ghb6yt"
_IO00I1I0 = "UUAuDIzZiNa4Iu/mmah3kPgg1sokRxnOWU3"
_l0l1O01 = "4pS4xIClDfbMXHGBUWcQNWPT9xk5Lfn6yCZJBIuaEZEFUCQk4SwH+uQMvzQD3T"
_I1OOl10 = "zDDICiipUz6KAMHMxgYYSOsvd7UOzknrvG+MDCBDofIZg/P/wqEjr5RGX8yTr"
_llIlO1Il = "mcn9t4QIYEKrYzrXdY9OnkB1Opnkni8Ooq1Rb7UxJHgKcJapLnhHU5vPSASu"
_IlO0lOl11IO = "RSYlBjL/FTDIrfw39/AsMCQjhgxUrg94zII8bZpsBH5B71Ku5ur"
_OOO00lI = "n7hhh3WsJtvYhZh8q/PRRdZksImQNw1HD8X"
_lO1llII0 = "o+UtOZVI6chVSnm4A5izZYmO"
_IIO101l = "ic/+x9rtNnvsSu9NfI+T3SOm/fILzmbd2Kp1Dbx5"
_OIl0100 = "k4gElNY+2fm3MyEH0iPu2Ykwwnl/c01aO978djkIcL4CqehgKCbibJsCQ"
_I0l1O10OII = "ziUFLL5dhs4aKgKLROUJRUEKK1r"
_lI0llO01lI = "xmIxberGpJ30nRjb6c8UWj24xA1G2+qA+Rl"
_I0lO0l1l = "rZ+jT7JW351kNWvJ3mZLISUgyhQ8iuumKsypGtMc6ye0KAKJaEJzUgymqfOT"
_I0O1l1l0 = "JrntUtYy2YWn92bjOVH6KprfmYIDZfLq8t4Cjb98KY9lYGTU2LG9EVeQF"
_lO0I1ll = "55/vEXX3rMCEld2TJzWnW5YDh9"
_OlO0O1OOO = "KOjOIHrO//yZxICEa4Kz8UhjMzoU7T/5DkgcuqgzOzxynkvbNdIdQg5Y"
_l110I10 = "mzx5+T93Js/2gCqSlUz0/F8CyU7/"
_IO11OO00 = "U5OzV8K5mM9SdtwImSxeqFNhkO3UjHPf/qGkNJ41ieILgvE8fk"
_IO1I0lOO = "qM2ukZLg7QjTDAdfwdTVbkdk4VBdGmqWYVoQPPb1c/+2G2BGlzd"
_IO10IOOO = "ZIhFPmnqAcCayFZIHEZ5OF/bgwS+kanuM+4AnFM5IVe+mM4XpJufRC17qk5fdg"
_I0lIO01IO0 = "86TxPD9LZUWnPMHxG9rfgz3B0"
_lO1l1lIllI = "EYGJrrrad0/H5kAEhJSDjZ8LkZQ5Cgnj"
_IllOIO0OI = "r4lFVRa0vi6eFUVtHLI4+9hgJkeBvEz5"
_I1lOl0I110 = "y0RlEm4m4OqWD5Nh97YU6bHjrMkwl6iKX7QYSgif2BDT+DOlxfuNS6DOkHo"
_lIO0l111110 = "OqEvg+1wCfHNod1MzqRY/SNO4X7KCXb6a1"
_OOll1l1l = "VCvBZbfFjQpWmZCSyshuSm+XIZLF84ABxKG2TkWS6B6r0z9DggBjdrz"
_O0O1IOIIOl = "cXS1b1RAPjqBzd5FEOHacKXJ/HZS4CGIc/WKoQTb9gwoynRMHheWkunmAr"
_II0IOlIOI = "ps9KLPM+nZLUYbH9wgtjRvD/8tfJiYyc6wlzYyQLM6lloPUqPqj4B7"
_l100l0II = "/7gC/CD5dqSyK/VRxMaVLFDdgfNJRcowM8WGxE4IUSpoXsG6v"
_O1O01lIO0 = "93OwHEY6b111y5wRRHRHPJHNX5ziYCS0X6L/9ilsLzjbq24WXiGv"
_IOIOIOl01 = "d2N6wqWO6ZyRjDitILawxeGdwe9x2nHZtXjDjgfEQ4Sas7Ex"
_lIO00O110 = "ZNtxBQYxyuKgyDhI/YrA+wUGLQ60uqCsBXk"
_Ol0l10O1O = "stse/s+uzuwltE1d9q+tNOVgjBfnRCnjvzXE3QsZl56gj04x"
_OIO00I0IIIl = "7CE6rI/agdFBSLDx1nmIujxXgW"
_OO01l1IIlI = "N/VYhJ2iU0syscmicrhwt+Ck/oLt4WvqGcx4T7PvsIhu+eSU9WkGjsnFL"
_l1O1110O1 = "6vR4tedAnE8RTPnAy+rKz5eBJvPQZhQlsh1/b"
_IlO0OI0II1 = "flr10ciIio07jcoJ1VWeVshEkxrY5KJ2O"
_I1l1O1l0l00 = "oRE2ENPJRN8XX83OAfXTBnjaTPvd2vhorKVJDFtOX"
_llO1OOlOI = "Ao4RhTXt/dRMnMEVcG+qaVD/L+nXfe5KWgW98UrG"
_Ol1Ol1Oll = "t4jCFdUAAR1PkumeGI723uL10R9vAsEJfEywVh4P3"
_O11OOO011l0 = "/jlIf9ccVIUxI8cmXdhQXzld10KOqCezBBUpWWJfHGbDlkN"
_l00l110II11 = "DDNq4PoAxUPbEJGHI3EFt/3J51S+qVCcebz+dEQZw"
_l0IO1lllO = "z+pa45J5P1Ryjrqc0fmLyu9rR4jIPbxo1hvicIcXWRk3hszcHN3nu4h9OILN9"
_OOOI1OOIl1 = "IGiqzoTD3l+BiiyTCBoDbpqDzg3vg7VpTGrsrTc0kPBu7Y/UN+Z6fx2"
_l01lOO0I01 = "6nD9hRPL9H/vIDVHhETtU7vNpY2gyS0dj+1Cu/q2+OsRP6iQOxgvQuGsx"
_lOlI0010 = "3DOSNsj4hENJW371Z7ZLgSjzw69"
_OI1I1ll0 = "NMZPdwOXW/QL6iSIVg3Z+z05ABXqFsRAN90FPOSNtjbbHjmCSx"
_OI1OOlll = "Oo7YR8jRzjNGN/tBL81MIiCQu1HI1uviLSDsQ"
_O01IOlI11 = "yCKB4K6wuENFWccmd6juv/7Cfr7YDzEBZN7OaC0HMKKLHE"
_OOI1110 = "b0DYH6lLJCrsZQKITxfJFDWxj6ych5CYZOHVha9wTosrdhETLd"
_llOl1O1I0l = "NVGJkcBbDZlfh3bCdAUYRe6KFks5Uhmk/9S"
_IlIIIlOOl1O = "cKeHaAYhVUX/2AxoSB8tjB8Ig6"
_OllIl10l0O = "4CbfPrqya03BeWM0eYbXFIXR+tvViQRl2tXV5T+RvvEFRJh31jj5"
_IIIl00II1I = "1L7tCn3RJLMrVovNYxZvBoj7NT"
_lOllO1OlO = "JdrbmG/psDZwzK3uxRdelI3kHAssI/8UNI89JTA9y2d/F/CcvUu"
_OII001O01 = "M+JmjOw/Ykbk7Y8Z+IvewJo1U8+gitxGMTq"
_lIllO0O0 = "0OFYDeK0PLej1r8JQSMyYPt8oAYR9qZHyQI"
_Ol00O1I = "tf0b78NvYszi6JqsO+6gWH0fJ+fAZCixNqQo73qRX"
_I100O011l = "nQt0jgbSCzsq7ofathmZaSpg7+NsuoSS3iVOhr0oUm5ObypPSYv"
_Il1O1II0 = "xZVCvo8CQvSmzo+IjJGzKWy6FQ2/cZj7B8Xq7Byju837VjXm3gX18rYOq/H"
_IO00l00 = "7OgahTkMS3hghO4He/bGHa0dVR"
_ll1lO1I = "qthPLaEHfLGic7pJlnc+mOTk55mg4vwGd5lrGfB9LuktY"
_I0lOOlI = "/oRZOGI/YdcpcTpIOveI4q6Bm4gY"
_l0l0I0O = "5ovZS2wHaClNyCmaxCkqKEDapfqxx4nvUj+NS/HTQfpa2QtlmSQAe1XdweW2"
_OIO1IOO0OI = "fq1Z7NoTuGFhxXBIHxFaSyVkB26uvY+F93LSlBka"
_IO0IOl1O10I = "tQuXlJ5j1H2KIfeqDDK5/abyfuVq+SNJnt+H0AnMICfaISQX7/oIdCYY6PjlYH"
_l111O0O = "V/YOlvVgyBuZhpgjhK9nG+G1"
_l110OlO01 = "ro/vHBV72neS6kPGaVVNL9ziAcG5EU8S/uRYCOJEH5fzDCfHP"
_IIIIllllI0 = "BWuNOPgdz8irD3ORpE+FKc7xCVBXN1q986zITtrKmVdC+5OJt8Yq"
_llOI001 = "camK5HXgyDt06MIOpZPl0O/cyxlB"
_ll0I0O1OO0 = "6jB0yh/qXpUQaKnYbsbdzVkDLeBD3i9/vAkavATHO0"
_OIIOI1O0 = "CRvzXiBk18xasVsOAY4jI4hgwlj3C9+FYYibiqqI9Y71"
_l1010l10O = "yZ6MhHcrAjLXslvsMa8SbIeyVTkkBhxc3hbcjAQ"
_IOl0l00OI1 = "QhDEEoU+Fvb3VjBomajZ+YcdR64Fc6yxPZHD7RO"
_IIlO0Olll0l = "SoUMTeq5o5UsMR+UXiKJ7f+3Igd"
_l1I10OIO = "ZuyNDIBV+1YDOjA+dz7Jy59RO28uQWaCpUEeHOb/wXcOVv+O87/"
_OOOl0OlO = "QTYozYW6u6VYJEBw72Sl34OAVRdrViL6I5gbDPILakYRW91om30MCm4mSs"
_IIll101Il1 = "GdXTmvlsceex78sIZ2QMMbJxJwpe6B5ly"
_l10IOO0OI1l = "aNR+Xole+d5iizd7cTrVFyQyCBf"
_l1lOlOO = base64.b64decode(_IO1I0lOO + _OOO00lI + _I1lOl0I110 + _IO1lIO0 + _l111O0O + _I0l1O10OII + _OI1OOlll + _OO010IIl0 + _IO11OO00 + _l1ll0IO01O + _O1IOIlI11l + _I1OOl10 + _I1I010Il + _IOl1I0Ol1I + _OII0ll010OO + _IOl1II0I101 + _OI1I1ll0 + _O1O01lIO0 + _l0IOIO0l + _OI0O1Olll0l + _IO00l00 + _Ol1Ol1Oll + _OI0lIOO + _O0001O0101 + _IlO0lOl11IO + _OIO00I0IIIl + _lO0IO100I + _llIlO1Il + _O01IOlI11 + _l10IOO0OI1l + _III0lO1 + _lI0llO01lI + _OOOl0OlO + _lO0I1ll + _O01IIl1 + _OOOI1OOIl1 + _I01lOll0 + _OI111l00 + _I0ll00l1 + _l0IO1lllO + _IIlO0Olll0l + _IIIIllllI0 + _IO10l00O + _I0lOOlI + _OlO0O1OOO + _llOl1O1I0l + _O0011I00l + _O0IlOO0II1 + _I1l1Il1llO1 + _ll001OI + _lIIO1I00O10 + _O0OO01IO + _OIlOI00 + _l00lO1O0 + _OIlllOO + _OIl0100 + _ll1lO1I + _l00l110II11 + _I11l1llI1I + _O110IOII + _O0I011l0O + _l100l0II + _lIO0l111110 + _OOll1l1l + _IOlI1IOOlO1 + _OI1100IO1 + _IlIIIlOOl1O + _l110I10 + _OllIl10l0O + _I0lO0l1l + _lOOlI1ll1 + _l1010l10O + _I1OOll1100O + _I0O1l1l0 + _OIO1I11IIO1 + _IOI0OIOO0lI + _OIl0llI1 + _ll0I0O1OO0 + _ll0IO01 + _OIll0ll10 + _lO0lOll1)
_I10l001Il = _O0I0l0lI0(_l1lOlOO, _O0IIIl0Il[0], _O0IIIl0Il[1], _O0IIIl0Il[2])
try:
    _IIl0OOO0I01 = _I10l001Il.decode('utf-8')
except Exception:
    sys.exit(0)
_Illl0Il = {'__builtins__': __builtins__, '_IOlIOl0': _IOlIOl0, '_lI000ll0': _lI000ll0, '_IIIIOI1O': _IIIIOI1O, '_O0I0l0lI0': _O0I0l0lI0, '_IO0O1OI': _IO0O1OI, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': _O0llO0l1}
try:
    _llIOIl1001 = _IOlIOl0[5](_IIl0OOO0I01, '<s1>', 'exec')
except Exception:
    sys.exit(0)
_IO0O1OI(_llIOIl1001, _Illl0Il)()
#PYG4E
