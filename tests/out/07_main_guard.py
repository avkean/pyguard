#!/usr/bin/env python3
# Protected by PyGuard v4 (pyguard.akean.dev)
_O1I10OOIO0 = bytes([115, 210, 114, 85, 52, 202, 50, 180, 121, 13, 159, 201, 145, 190, 195, 236, 227, 114, 56, 138, 194, 73, 107, 168, 252, 144, 33, 159, 68, 111, 45, 210])
_I10O1I01 = bytes([206, 222, 73, 162, 72, 119, 65, 178, 35, 202, 86, 227, 183, 193, 145, 222, 135, 10, 81, 81, 220, 67, 218, 150, 121, 100, 22, 21, 2, 99, 231, 59])
_IOI1OIIIOlI = bytes([115, 46, 84, 214, 55, 179, 41, 125, 15, 186, 143, 190, 91, 158, 72, 147, 93, 42, 172, 213, 84, 10, 127, 56, 156, 154, 212, 71, 199, 138, 19, 195])
_llllOl0I = bytes([213, 237, 33, 215, 218, 129, 190, 162, 161, 156, 66, 147, 179, 199, 31, 80, 44, 140, 147, 142, 51, 240, 203, 120, 69, 46, 7, 129, 60, 121, 155, 63])
_Ill0lI1Ol = bytes([38, 202, 44, 73, 233, 86, 12, 34, 2, 156, 173, 239, 66, 17, 75, 4, 35, 142, 124, 191, 101, 231, 57, 242, 194, 209, 244, 96, 174, 105, 166, 200])
_Ol000OI = bytes([96, 206, 213, 209, 136, 128, 75, 171, 32, 85, 220, 125, 245, 160, 176, 5, 229, 52, 190, 129, 49, 231, 195, 182, 0, 199, 151, 12, 106, 223, 249, 20])
#PYG4S
import sys, hashlib, base64
_O00IlOO = type(lambda: 0)
_lO10OII10 = (exec, __import__, open, compile, type, getattr)
_IIO00O0II = _lO10OII10[5](sys, '_getf' + 'rame')
_I001lI0l = hashlib.sha256(bytes([207, 25, 242, 92, 15, 46, 31, 164, 249, 163, 81, 195, 249, 168, 80, 252, 203, 176, 106, 32, 215, 48, 219, 124, 148, 228, 196, 160, 79, 171, 153, 179])).digest()
_IIl11101Ol = bytes([136, 254, 135, 241, 193, 207, 12, 211, 165, 59, 67, 144, 5, 226, 154, 119, 47, 35, 58, 148, 223, 30, 254, 119, 74, 68, 116, 165, 24, 229, 166, 252])
_OlOOOl00O01 = hashlib.sha256(_IIl11101Ol).digest()
_lOOlOOO01O = hashlib.sha256(_I001lI0l + bytes([228, 127, 137, 146, 151, 87, 175, 181, 42, 117, 192, 210, 226, 131, 225, 225])).digest()
_l0OllI01I = hashlib.sha256(_OlOOOl00O01 + _IIl11101Ol).digest()
_IlO0IOIIlO0 = hashlib.sha256(_lOOlOOO01O + _I001lI0l).digest()
_IO11OOI0 = hashlib.sha256(_l0OllI01I + _OlOOOl00O01).digest()
_Il11OO0IIO = _IO11OOI0
def _OlO001OlI(_I10Ol1IO0):
    _I10Ol1IO0 = bytes(a ^ b for a, b in zip(_I10Ol1IO0, _Il11OO0IIO))
    _l011IIl = []
    _I1I0OO0l = _I10Ol1IO0
    for _ in range(9):
        _I1I0OO0l = hashlib.sha256(_I1I0OO0l + bytes([23, 93, 72, 127])).digest()
        _l011IIl.append(_I1I0OO0l)
    _O1O10IlI0 = [(b % 7) + 1 for b in hashlib.sha256(_I10Ol1IO0 + bytes([88, 236, 196, 155])).digest()[:9]]
    _OllO1IO1lII = hashlib.sha256(_I10Ol1IO0 + bytes([209, 0, 143, 152])).digest()
    _OIOll1I1IIl = list(range(256))
    _OOlI1O00I = 0
    for _lIOOOl0IO1I in range(256):
        _OOlI1O00I = (_OOlI1O00I + _OIOll1I1IIl[_lIOOOl0IO1I] + _OllO1IO1lII[_lIOOOl0IO1I % 32] + 184) % 256
        _OIOll1I1IIl[_lIOOOl0IO1I], _OIOll1I1IIl[_OOlI1O00I] = _OIOll1I1IIl[_OOlI1O00I], _OIOll1I1IIl[_lIOOOl0IO1I]
    _l00ll01I = [0] * 256
    for _lIOOOl0IO1I in range(256):
        _l00ll01I[_OIOll1I1IIl[_lIOOOl0IO1I]] = _lIOOOl0IO1I
    return _l011IIl, _O1O10IlI0, _l00ll01I
def _II110llllI(_O001l0O, _I001OIlOl1I, _llIl1Ol, _OO00l01O):
    _O0I1OOO00lI = bytearray(len(_O001l0O))
    _OIIO10lO = 9
    _I100I1l0 = 0
    _I10I1lOO = 0
    _IIll0I0lI0 = 0
    _Il00III1II = 0
    _OI0I01lIO = 48
    while True:
        if _OI0I01lIO == 31:
            break
        if _OI0I01lIO == 48:
            if _I100I1l0 >= len(_O001l0O):
                _OI0I01lIO = 31
                continue
            _Il00III1II = _O001l0O[_I100I1l0]
            _I10I1lOO = _OIIO10lO - 1
            _OI0I01lIO = 72
            continue
        if _OI0I01lIO == 72:
            if _I10I1lOO < 0:
                _OI0I01lIO = 108
                continue
            _O101O0I = _llIl1Ol[_I10I1lOO]
            _Il00III1II = ((_Il00III1II >> _O101O0I) | (_Il00III1II << (8 - _O101O0I))) & 0xFF
            _Il00III1II = _OO00l01O[_Il00III1II]
            _Il00III1II ^= _I001OIlOl1I[_I10I1lOO][_I100I1l0 % 32]
            _I10I1lOO -= 1
            continue
        if _OI0I01lIO == 108:
            _Il00III1II ^= _IIll0I0lI0
            _O0I1OOO00lI[_I100I1l0] = _Il00III1II
            _IIll0I0lI0 = _O001l0O[_I100I1l0]
            _I100I1l0 += 1
            _OI0I01lIO = 48
            continue
    return bytes(_O0I1OOO00lI)
def _I1IIl1l(_lO0OOOO00Ol):
    _O001I1O11I = hashlib.sha256()
    _lO1O1l001OO = [_lO0OOOO00Ol]
    while _lO1O1l001OO:
        _l1O00lO0l = _lO1O1l001OO.pop()
        _O001I1O11I.update(_l1O00lO0l.co_code)
        for _l1IlOI11 in _l1O00lO0l.co_consts:
            if type(_l1IlOI11).__name__ == 'code':
                _lO1O1l001OO.append(_l1IlOI11)
    return _O001I1O11I.digest()
def _I0lOIO1l10l(_OO0l11l0l0):
    try:
        _O0l1111ll = bytes(a ^ b for a, b in zip(
            hashlib.sha256(_I1lllI0 + _I1IIl1l(_IIO00O0II(1).f_code)).digest(),
            hashlib.sha256(_I1lllI0 + _I1lllI0).digest()))
        return hashlib.sha256(_OO0l11l0l0 + _O0l1111ll).digest()
    except Exception:
        return hashlib.sha256(_OO0l11l0l0 + bytes(32 * [255])).digest()
try:
    _I1OI1OOOI11 = __file__
except NameError:
    _I1OI1OOOI11 = sys.argv[0] if sys.argv else ''
try:
    with _lO10OII10[2](_I1OI1OOOI11, 'rb') as _ll010l0:
        _I0I1IO0l1Ol = _ll010l0.read()
except Exception:
    sys.exit(0)
_I0I1IO0l1Ol = _I0I1IO0l1Ol.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if _I0I1IO0l1Ol[:3] == b'\xef\xbb\xbf':
    _I0I1IO0l1Ol = _I0I1IO0l1Ol[3:]
_lIIIO0IOII = _I0I1IO0l1Ol.find(bytes([35, 80, 89, 71, 52, 83]))
_Ol10O11l = _I0I1IO0l1Ol.find(bytes([35, 80, 89, 71, 52, 69]))
if _lIIIO0IOII < 0 or _Ol10O11l < 0:
    sys.exit(0)
_O011l0O10 = (_lIIIO0IOII + _Ol10O11l) // 2
try:
    _OlIl0l0 = _lO10OII10[3](_I0I1IO0l1Ol, _I1OI1OOOI11, 'exec')
    _l0l1101l0l1 = _I1IIl1l(_IIO00O0II(0).f_code)
    _I1lllI0 = _I1IIl1l(_OlIl0l0)
except Exception:
    _l0l1101l0l1 = bytes(32)
    _I1lllI0 = bytes(32 * [255])
_l0OOOll0 = hashlib.sha256()
_l0OOOll0.update(_I0I1IO0l1Ol[_lIIIO0IOII:_O011l0O10])
_l0OOOll0.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(_l0l1101l0l1 + _I1lllI0).digest(),
    hashlib.sha256(_I1lllI0 + _I1lllI0).digest())))
_l0OOOll0.update(_I0I1IO0l1Ol[_O011l0O10:_Ol10O11l])
_OIOIlIl0 = _l0OOOll0.digest()
if _lO10OII10[5](sys, 'gettrace')() is not None or _lO10OII10[5](sys, 'getprofile')() is not None:
    _OIOIlIl0 = bytes((b ^ 130) for b in _OIOIlIl0)
if compile is not _lO10OII10[3] or exec is not _lO10OII10[0] or getattr is not _lO10OII10[5]:
    _OIOIlIl0 = bytes((b ^ 2) for b in _OIOIlIl0)
_IIO1OIII01I = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != _IIO1OIII01I or exec.__class__.__name__ != _IIO1OIII01I or
        getattr.__class__.__name__ != _IIO1OIII01I or __import__.__class__.__name__ != _IIO1OIII01I or
        open.__class__.__name__ != _IIO1OIII01I or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        _OIOIlIl0 = bytes((b ^ 98) for b in _OIOIlIl0)
except Exception:
    _OIOIlIl0 = bytes((b ^ 98) for b in _OIOIlIl0)
_IOI11IO1IIO = sum(b for b in _OIOIlIl0) & 0xFF
_OO1llO111 = _IOI11IO1IIO
_OIOIlIl0 = bytes((b ^ _IOI11IO1IIO ^ _OO1llO111) for b in _OIOIlIl0)
_lOOl111I = hashlib.sha256(_OIOIlIl0).digest()
_l1lOIII0I0 = hashlib.sha256(_OIOIlIl0).digest()
_OIOIlIl0 = bytes((a ^ b ^ c) for a, b, c in zip(_OIOIlIl0, _lOOl111I, _l1lOIII0I0))
_l11101O1011 = bytes(a ^ b for a, b in zip(_Ill0lI1Ol, _OIOIlIl0))
_IIlOlIOO10 = _OlO001OlI(_I0lOIO1l10l(_l11101O1011))
_IOI00I10 = "acoYKhg94P8L95KT72ZTO+bDKolxQyECCz/kPOH"
_lO1OI1l1 = "BBOp/m8OIWH5vSxMBEgt0kmsNyU"
_OIl100O01O = "mCk10JEeHVQPlak5F2gdaFUDW"
_I11000100Il = "eXVgHRZmRQuWc1Ee0bw5yq/7Lt8jaGCrWZW8eS8ZbqowxCRE"
_I1IO1111l = "eccHxnstO3dpXtQDq/w3xfrxP/6D9weFHRIhcmD/XXD0f"
_OI1llIIOO0 = "bYu1n9QHFjcjYVIG2gghkQO1WMjitR/ukVm70qlYZpZAzj9Rkf3fXsa"
_l00O01lll = "L8o/yptx8XPxpoIZZMoNvS66BxPDwNngDxe5ZAn"
_Ill010OlIO1 = "XfQvMzxuh+JNGO+B3E0FKHj7WThDfwfYXRLbhPC1iEoo9WiQMzvS+TtwO12MB"
_IO0O0O111 = "Xsw2z0nVSMZpwM+ovfeTcyKbWTI8S3O9VD1xRXaF3n8X5x7nDgBeERis"
_lIOl01l = "V2kNznLJk+f+7tzvPoWGYEdGHQJ"
_l0OlOO01 = "SvqtZDNRqOG/5hJrcZUbleJPqsHUnkAT"
_Ol1OOlI1 = "NMDEnqZfpFgGxiqK2tF9D+zoC5RtwXGAOxbU13"
_ll01Ill011 = "Q6y4WmGC+PS6d3MhGuHCYzpayZAIUKLn68koqqomACF4UGKk/+v5xkf6+aZO"
_II1OOl1Ol0 = "iu8/nyHw7VjAXNOSD7ULvNB1DVS24zHJSPMm4vOJEEcD9s"
_O010O0l = "0bRKkscIXTDt5OdtSyAxZksc"
_lO111O00l = "698HHSdNtOAK/u0zSR0DgFeYtt7JlktJ6Qt971U"
_O1IlO011 = "Bi8UjUeVfI05N3e4MLE35DeR"
_IOlOO1O10lO = "Nmmc4k7GFSEN0fDIYgkNsbdRbJNCiLu+ypeiM8fmBvIQVXteMLSWYx8fHeAbsCw"
_lI1O0OOOI1l = "g+s7QA1gVAUtqtjnPnoTDNbCKu"
_OI0IllO = "omqQbDNc45gnIrYH3tGesESVuceM1dzJ7dZHbQZBmYW6VpehQKlcHkgGQBvPZkh"
_IOI0O0ll0 = "oXX9p+QQwUw1z9mceVnt6Wq8GIo09xaIqjtkdaM3fdsHw1nPO+"
_IlOO0l1O = "9ibbSGoqqj/qn5l0kRM9jnbRoRbjyFs0z0XXJjp"
_ll0lOl1O = "2/MqnjI7pbHZ+cggO1lpSglNcE="
_II1IIII0OOl = "m5uxVm3p8g10drfNaYXOt02JR7DutXQwDuJQlTcMiHhHPSvSBTIiP9wPZ"
_lOO000I = "pkvdjYBBfv+pXJ5u1hNJ47Iwqyng"
_Il1I0011 = "pNu0AJWT1aoEMg8C1Zp2ttP42D7BS"
_O0I0011l = "Zqbkh27OScfIfeViMGzifaei0/qM7Uwm2jJwp2WOQsEnaVv+vGT0m"
_l0lIIOI = "coJm2CUPQWBPfe2RqRoi3CDUeGAyKjxtSE13cdbYPJeNf"
_O1O10l00I = "9R7zi9SoXYalVRbSz1p3NdI85rRR09qLyDk4h+fJQmoRIbfaXvzG4PjEm8O"
_lOII11l = "ZyjDHFEbOl1I6FI0QTi/kl/fX3cQ6OLDHf46i"
_O0OlIIOOl10 = "2Tb06faKo6hlrdT4aXs/vgq25wvFZ"
_IO0O1OI = "XVRwo6rK/P6vP/zHZUZB8flJuhAaBwb0nj9T0G/GfUy"
_l01l11I0O = "3PsVS13Wq9ieEsVawTyqth0bhyUaCicLK0wbHIm2sU+HrT9IpHQizz"
_I0lOlOO0l0 = "MJmyFjUR2abbRJa9wZ28zbCMteUp2UY7SGLbkT6vCeG4m34"
_O000I1IOO = "0Fd7oFTTTrdmvSdINARe5YoWNngIhpRHAnD5DDkO6ZiS5xMy55Ewi"
_l1l11O0l1OI = "Opz/eug0hT3EpNK+u8tFyXenG+uJOv0ZK8"
_IOl0I1l1 = "0i286NePA6mwdLjTui3ownjuC"
_II1l0IO1l = "liKPVEz0wsh5izDB9zRfmevkBwj"
_I0001l0 = "RODDgJ2h54ywipfa1t9nkVrPQjmQs/8n/eX8glNl11Bg1TXWs1pIVkcgo"
_Il1IO10Il = "oEJ+mjr+yWolaC5MZqKfoKsPvEOr8HnRTtgc3NPP"
_IO1O01l0 = "uexEg60cA1T67YoteRyHaH117SoWGXgdIlndcThVW9cIww"
_O0OOl011 = "hG3LpCtz9MsODkas9nKgwwFGQuy"
_O1O00Il = "bx+xdSaiMY4bOVZVRO7GcZI8bR42UkA3uG"
_lIOIl1OIO = "9gZChhSFL9OaMFZWgc4+epxKrhu1jIcM/kKdvBB467n/ApxFQ+"
_Il11lI0lO1I = "MkVU7Jh7WUmIFsr1ByOS39gGoQec8ww7gvM70n0os"
_O1llOIIIl = "zFCArKsaH27Tk0LIgn8drZFQ"
_O111IIO = "UckVUN/LB9uNBF+ybKr8s6GW0PLzabM2tf+QXcVE2UfItU5M4xtUnyH6ec"
_OlOII1O = "i47l+FokahpQCpu/kXqsm2jE"
_OO0OI1llOl = "SvdG34+lMCJMsQcywqOycQbxVsBcYuuDt4ofXybq64mlDJosajjdvXTrNQRuq"
_O01lOlO = "YQeZS7UvmLpv9YuT9lPBKl1+r5jLGcR"
_llI1OIIlO10 = "lT7qOKT9w6HswJrNuBTqss6hw"
_lIO1OO0 = "fmPuAlCC0xhv6MMlHS8tvGKNyzlRRzALxbGFn65T6gYz3ldOqr6sSeBwtuwzu"
_l110OI1111 = "JyoBDRhhljam+5BkQlZBIz8UEjXNgGn6w7RoOg"
_ll1IlO1IllO = "p6e0DiT8n6SxzSl2Y/IzCOqYf4imd2AblrQv"
_I0O0l0Ol = "7cObUqoL3YC+a9EFwhVbpxnnEQHoESnSIi0Q+"
_IO010I01I = "ko5XO9fEUV/vRCYMG1peYTd9lcEPL0o/2Wt2HFSrWd8cVtrYt/"
_l01OlI010 = "ZiB7txRRvklw8nhzlQtys2ILlcBRVKz8MbDEGcSy1wI7WrrQg"
_O0lO10OO0 = "pTf0nho7cGcD/GiM9FexnonV9yTQRlyZvNZ6f"
_ll1l11OI = "tk+M7Va8UEYV0d3evlpKw6xesFtS6JSo"
_I0I10I1IO = "9CUID6ERqjNadTPO4+1xTg3gvdAibHBOdU02q0fRsf+MrHlpR+9VIyUjlWmE"
_O0llI1llO = "2hvHn+fP6YZGIIrYwJYEI/6D2Xv35FIIvR7F5dxS5x5"
_lOlIOO1l1 = "NH/8dH2JDyD6V//D5aZkZuOwU2JS4arGz4a4OZPuTeaB5pgzbanQakz9"
_l11lOOO = "/Q3NlYuz0TTvCGnSSxfNk5T2R69Y73ZH4568uuI"
_lOO00IOII = "tpo3hvbDS4Y09g5/sQxyY75fw1fSOY/mqbIY+0X3twHf"
_l1l11I00O0 = "0tDWd7rzyqMZgI2FIfIoderO3zbtrtZSu4lxObBXVJba"
_O0I0Oll01 = "d+1+ULiWkZeSfFk3TNDwMOVx6Rb5MqWBUBxkKcKa3RrFWazCBz"
_l1lO01I0O = "cMyBPMmK/5j1LY7+exd/hlgs70uMhZxMYlFSOvu"
_O1O1lIl = "jrSotJQRwM7mGtS29T+NSrtYCKt4Cs9IhPACic3/RnEEMhz4n2mpnhpw7IvOps9"
_IOO1lO1O = "m5YCtB0APwnz8aEy6zsLbncTphf8wb4crzKu4oQQZfBQjkMKcmmiBGQWT"
_IIIl0IIIO = "rzlNhGQbwji30vZU9v3r0k6twhzuL/DbGW5OCzEzb244b9+KLUnfhwPe3/"
_OlIll1IOIl = "FN98sCnU27fJBI50eGiVsUR7254f5WDCPzqg/7QUTEHL"
_lOlll0101I = "AjNoDlcWtjOEbheEmLIUfu6dsde0u2q39EdkYl5LwB2xWqEqkpMvcbnRtoha6Z"
_IIllOlIO1 = "qaDNBILr5bQa2TxnlNGVLclC18V/My3X3LBH1GN"
_l1Il1lO = "DSnHZ4Z9J+1xbEPVVm+XWiD6mT3iJJwU"
_Ol1IOOO = "LUFO6wqGL04GgssfPsyDqNi4eeGimY"
_OOOI1I1 = "mAul9AfL2pEjv47mPgo1+eUOUXt9otur7nmn7lMIn2h"
_I1l0OOI01 = "IAkMvNjj2L6saMz+KTnzVyoVB2k"
_lIlIOlO1 = "nHyFfntGa2NayYzd4oXzuxAvVBJMBAFMqCPCgOD0RQ18RvrBYkgu"
_II0OIO1 = "h15O2awtWzBMVxAmeRbli8HN2J/kWsrBfmZf0r"
_l001lIl = "OJwHpv2kKyfNxs1gftsEWvky0g3Vt+"
_Ol001l10ll1 = "mdLYEWKhy4o6d1O/Hdp41I9yqqMyO5r4AN5eEYN9920xjUvo/127IeT+NevJS"
_I0l1l01 = "GVaU1ltVRITltUFLn3Z2qyg30n5P"
_I0I1O0I1l = "5ZwG/2KHkn7Fm3GGJAtVc4CtLCyc"
_O1l1O0l0I = "ZoXKD5UguVyUqwku+xrXukGtomnVh"
_OI1lIlIO = "eo/uQjo9XmpX3tFJB6zYLfA/ggaidaQew"
_I11IIIO = "9QcOXKUWPs+N/u3WYAy+LJnfgClK4z5o0"
_llIOIIlIll = "Om9NSMrjnycJnodddzZkQSEU8DT2SNpxko"
_OIIl110I01 = "nTtkllyOuKOO0yZHeFURtXmULve"
_I10OOIl01 = "w2fWqOuMnLaPbXr9oFeoMTSaf/LcxvlhSdkvV"
_I0lO1l1 = "rj5Ejkxnoj0roP9LvqyxIlaaGv9JQpodV/7JKbcnmb6T79cC"
_IllIIlII = "fdfmuUGE2Hd16nyTfFo0GhuZdEnYKEMV/HGOZlksGC1nj+36kaa2"
_IIO0OOOI = "VM/3TRz0y5sYM+Ms/VnBSRKBt"
_Il0O10lO1Il = "ugs40b46ob1hjO7Gyv6BEEUwJx5"
_lO1OIIllI10 = "B6r4dFgG75TcVjdzM+T5g7qE4JYdSYMAo2JGrhIp6fGteuPDbRvczAEJ"
_IOOI0I0 = "chvP9dFuTBp3lf/Qb9a6+v52DM4AKEHn6sz1MDjC5A+kEoxJHuf+nIQaig9OOx"
_I010ll0 = "d9hflELTIBWJTAVoXEANb2wLC8L+Dkw72yI"
_O10O010I = "UvT/demIM78CYMxo1xLtYIJH4/oBq7nJm"
_llOl1100l1I = "0wESGJZyM9GhM2V5cqZGQQKSnj4lV3iD3vnnp7BljWhRHARaUSV"
_OIOIO1lOOII = "c9KXi5CgONMa0giBodXwGNlQ8KtWvaDlR7B"
_O000OOl0 = "NGdUfvKXNr6tVKZMjzPc9JNYcyF03+"
_llOO1II = "vlOmVBjy1X7GvMR8OVuBWM5HbTnivHYbLnc"
_lO0I010l = "36LfNeyVk6YYl9KFruxAPgyOlIWmecg"
_lOO00OOll = "ynnYjzQzKF/TnTvWKMPPrRHk+AR4K2Sqf6ZPKJXTHDYNAnV9"
_OllOII0llOO = "kwJfl8PukA81dBH0Scpn1zRNcmirl7xO"
_O0IO01OO = "Bm9o7J7eoMR8ftIdSGNJkHPmsaI2SljQsNNeAkllL0UWFSTn/kwcMT8oWC"
_OOIl0l0 = "Ls4oju1xfF79xWTdVyy8lYLp8/xuFX"
_l1O10O0 = "S6DJl+AHbVMc4a7XfdzAJ7U3n9MDL"
_O0llO0IO1 = "fYXj4Os3U940/nEQQul0Xim/v2ZEmgwJS5vxLJ9xMP"
_Ol10I1l1I0O = "KYRwLnE027mjVIcCUwXOG3vIY+rVk4WCkJ8o6MNMbUwmpRlFS+"
_OI1IOIll1 = "2B+7ky8z6YKkNdNu87WL7H2SfGXAFl2Yzl1xTN"
_l11Ol0IO = "BgOnm3KH3x0DpRWRd58TQDIUlFjQm1ysI8zGfdLTeZ"
_l1lIOIOl = "6C0ht/cxGx3Q59MdkBFu9FdiIzC"
_I00I0IOI0 = "F2HXqm/XiyldZvRw0TUzVNOjKP2pP5bHhF4iLAOp3nw19prvf86puK"
_O110lI0l1l = "rHHo3q+3M9pIadeC178L+SuOI1v7HyKfV2gm+bf6G"
_l10IIlOlIOl = "sHBv20rfoElaZcFHYOVRdwBzJkopZzTTN"
_Il1OOll = "Cfy+6idHjQY1+h5ExRHa3pboHo7GmLNTIGXc4asUW5dNzmpFWXohU"
_l10l0lII = "ulJka1zxX8sxMHzX+6T44B/USpys3e2b5ABcZZIUG89R7mbewhfdWKxH8HxvWY"
_Ol00O1l0lI = "ySbUKSpbgp/h9Mv9ggIHhB7S+RzfRokQ5J"
_llO1lOIIO0 = "XPIxAKvG3DjtbgJRLT1egpScG0g7Q560An9znHGLEEJBnGtT"
_I00001l = "MGlIBVeTX2J+6w0y8NoRJ60Z3Tob"
_lI0OlO1ll = "1+KdPk7jacsbYV3Ss606JZuvCS31Z/EooAp5vPAj"
_I1lO1l10 = "XWY+It8pfC76RlLmd2+6vn3kL54ujANVfERJv9+vExtkh"
_OI01lO11IO0 = "v3qwDNI6pKeLPt6E82iBCfTGz7KHpKUyKl"
_IO1IIIO00 = base64.b64decode(_IIllOlIO1 + _llIOIIlIll + _O0I0011l + _I10OOIl01 + _OIIl110I01 + _IO0O1OI + _l11Ol0IO + _l01l11I0O + _lOlIOO1l1 + _Ol1IOOO + _Il0O10lO1Il + _IO010I01I + _Il11lI0lO1I + _I00I0IOI0 + _OllOII0llOO + _lOO00IOII + _IIIl0IIIO + _lI1O0OOOI1l + _Ol00O1l0lI + _O01lOlO + _O110lI0l1l + _O0lO10OO0 + _OI1lIlIO + _O111IIO + _IOI00I10 + _lOO00OOll + _O0OOl011 + _lIOIl1OIO + _l1l11O0l1OI + _l01OlI010 + _ll1IlO1IllO + _OO0OI1llOl + _lIlIOlO1 + _O000I1IOO + _llO1lOIIO0 + _llI1OIIlO10 + _OOOI1I1 + _OlOII1O + _l1lIOIOl + _IIO0OOOI + _Ol1OOlI1 + _lOlll0101I + _OIl100O01O + _Ill010OlIO1 + _IOl0I1l1 + _I1lO1l10 + _lO1OIIllI10 + _O0llO0IO1 + _l1Il1lO + _Ol001l10ll1 + _O010O0l + _O000OOl0 + _lOII11l + _I1l0OOI01 + _II1IIII0OOl + _lIO1OO0 + _II1OOl1Ol0 + _O0I0Oll01 + _O1O10l00I + _IOlOO1O10lO + _I0lOlOO0l0 + _IlOO0l1O + _IO0O0O111 + _I00001l + _ll0lOl1O)
_I0Il1l0 = _II110llllI(_IO1IIIO00, _IIlOlIOO10[0], _IIlOlIOO10[1], _IIlOlIOO10[2])
try:
    _l1I0lO110 = _I0Il1l0.decode('utf-8')
except Exception:
    sys.exit(0)
_I1lI111 = {'__builtins__': __builtins__, '_lO10OII10': _lO10OII10, '_l11101O1011': _l11101O1011, '_OlO001OlI': _OlO001OlI, '_II110llllI': _II110llllI, '_O00IlOO': _O00IlOO, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': _I1OI1OOOI11}
try:
    _IOlII0lO = _lO10OII10[3](_l1I0lO110, '<s1>', 'exec')
except Exception:
    sys.exit(0)
_O00IlOO(_IOlII0lO, _I1lI111)()
#PYG4E
