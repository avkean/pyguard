#!/usr/bin/env python3
# Protected by PyGuard v4 (pyguard.akean.dev)
_l1IIlOOOl10 = bytes([124, 8, 194, 252, 140, 71, 13, 220, 196, 147, 80, 97, 150, 254, 200, 42, 151, 103, 45, 103, 120, 213, 77, 198, 125, 75, 60, 128, 0, 223, 39, 98])
_Il1IIl0Oll1 = bytes([83, 189, 251, 11, 187, 39, 30, 250, 44, 68, 41, 165, 132, 97, 73, 40, 58, 22, 130, 156, 71, 37, 179, 66, 79, 194, 76, 215, 234, 72, 121, 52])
_I00l1Il = bytes([131, 53, 118, 204, 73, 179, 241, 7, 27, 8, 223, 177, 213, 161, 64, 52, 165, 199, 166, 129, 214, 183, 79, 192, 173, 199, 192, 204, 82, 10, 193, 222])
_II11O1I1011 = bytes([95, 251, 126, 3, 231, 222, 6, 205, 240, 5, 108, 20, 234, 188, 30, 170, 244, 24, 0, 21, 239, 108, 158, 187, 183, 201, 66, 72, 64, 174, 178, 45])
_IOIlI0II = bytes([72, 206, 245, 132, 71, 117, 105, 139, 87, 232, 212, 63, 141, 71, 105, 192, 92, 236, 13, 24, 41, 6, 156, 93, 82, 227, 43, 176, 16, 126, 116, 40])
#PYG4S
import sys, hashlib, base64
_l0IlOl0 = type(lambda: 0)
_lIlO0IIII = (open, compile, exec, type, getattr, __import__)
_lIIlI0IO = _lIlO0IIII[4](sys, '_getf' + 'rame')
_lIIOlOOO = bytes([26, 3, 22, 68, 191, 27, 43, 110, 14, 110, 121, 198, 140, 41, 101, 76, 197, 105, 114, 144, 217, 29, 90, 209, 35, 236, 75, 59, 12, 11, 177, 139])
_I11I1OIl1 = hashlib.sha256(bytes([157, 31, 107, 131, 99, 211, 25, 3, 24, 128, 99, 122, 135, 238, 87, 63, 126, 186, 176, 93, 154, 110, 77, 245, 21, 104, 196, 169, 114, 96, 92, 15])).digest()
_O1II1Il10 = hashlib.sha256(_lIIOlOOO).digest()
_OOIIIlII0l = hashlib.sha256(_I11I1OIl1 + bytes([46, 99, 62, 81, 253, 40, 133, 169, 147, 200, 96, 111, 135, 12, 152, 7])).digest()
_O00IO0O = hashlib.sha256(_OOIIIlII0l + _I11I1OIl1).digest()
_lIO00lOOll0 = hashlib.sha256(_O1II1Il10 + _lIIOlOOO).digest()
_I0lO0I0lII = hashlib.sha256(_lIO00lOOll0 + _O1II1Il10).digest()
_lIIO1IO11I = _I0lO0I0lII
def _l0l11111(_I11OOII1Il):
    _I11OOII1Il = bytes(a ^ b for a, b in zip(_I11OOII1Il, _lIIO1IO11I))
    _lO0Il10lOOI = []
    _O101110 = _I11OOII1Il
    for _ in range(9):
        _O101110 = hashlib.sha256(_O101110 + bytes([15, 35, 136, 168])).digest()
        _lO0Il10lOOI.append(_O101110)
    _lO10O0O1l = [(b % 6) + 1 for b in hashlib.sha256(_I11OOII1Il + bytes([242, 150, 131, 45])).digest()[:9]]
    _OI1Il11Ol0 = hashlib.sha256(_I11OOII1Il + bytes([7, 94, 177, 239])).digest()
    _O1OO0O1 = list(range(256))
    _I0l1O1OOO = 0
    for _l0110l01Ol0 in range(256):
        _I0l1O1OOO = (_I0l1O1OOO + _O1OO0O1[_l0110l01Ol0] + _OI1Il11Ol0[_l0110l01Ol0 % 32] + 158) % 256
        _O1OO0O1[_l0110l01Ol0], _O1OO0O1[_I0l1O1OOO] = _O1OO0O1[_I0l1O1OOO], _O1OO0O1[_l0110l01Ol0]
    _llOOlI1O1I1 = [0] * 256
    for _l0110l01Ol0 in range(256):
        _llOOlI1O1I1[_O1OO0O1[_l0110l01Ol0]] = _l0110l01Ol0
    return _lO0Il10lOOI, _lO10O0O1l, _llOOlI1O1I1
def _l011O0Il0IO(_O111011lO1I, _OO00010I1O, _I11I0Olll, _lOI1OIOOO1I):
    _I1IO11ll1O0 = bytearray(len(_O111011lO1I))
    _I01l0OII = 9
    _IlOl1Il = 0
    _lI0lIlO = 0
    _IlIOI00l01 = 0
    _O0I1I0Il110 = 0
    _O1IIO0I = 87
    while True:
        if _O1IIO0I == 50:
            break
        if _O1IIO0I == 87:
            if _IlOl1Il >= len(_O111011lO1I):
                _O1IIO0I = 50
                continue
            _O0I1I0Il110 = _O111011lO1I[_IlOl1Il]
            _lI0lIlO = _I01l0OII - 1
            _O1IIO0I = 31
            continue
        if _O1IIO0I == 31:
            if _lI0lIlO < 0:
                _O1IIO0I = 99
                continue
            _OIOlI0I1 = _I11I0Olll[_lI0lIlO]
            _O0I1I0Il110 = ((_O0I1I0Il110 >> _OIOlI0I1) | (_O0I1I0Il110 << (8 - _OIOlI0I1))) & 0xFF
            _O0I1I0Il110 = _lOI1OIOOO1I[_O0I1I0Il110]
            _O0I1I0Il110 ^= _OO00010I1O[_lI0lIlO][_IlOl1Il % 32]
            _lI0lIlO -= 1
            continue
        if _O1IIO0I == 99:
            _O0I1I0Il110 ^= _IlIOI00l01
            _I1IO11ll1O0[_IlOl1Il] = _O0I1I0Il110
            _IlIOI00l01 = _O111011lO1I[_IlOl1Il]
            _IlOl1Il += 1
            _O1IIO0I = 87
            continue
    return bytes(_I1IO11ll1O0)
def _lI1Il0OllOl(_OO0Il1I00l0):
    _OO1O010lI = hashlib.sha256()
    _llIOOOOlO0I = [_OO0Il1I00l0]
    while _llIOOOOlO0I:
        _IOI1I0O = _llIOOOOlO0I.pop()
        _OO1O010lI.update(_IOI1I0O.co_code)
        for _I0O10OOOO in _IOI1I0O.co_consts:
            if type(_I0O10OOOO).__name__ == 'code':
                _llIOOOOlO0I.append(_I0O10OOOO)
    return _OO1O010lI.digest()
def _Ol00OI10l1O(_lO0lIOlI0I1):
    try:
        _OlOIOIOO11 = bytes(a ^ b for a, b in zip(
            hashlib.sha256(_OOI01Il + _lI1Il0OllOl(_lIIlI0IO(1).f_code)).digest(),
            hashlib.sha256(_OOI01Il + _OOI01Il).digest()))
        return hashlib.sha256(_lO0lIOlI0I1 + _OlOIOIOO11).digest()
    except Exception:
        return hashlib.sha256(_lO0lIOlI0I1 + bytes(32 * [255])).digest()
try:
    _I1IOlOIl = __file__
except NameError:
    _I1IOlOIl = sys.argv[0] if sys.argv else ''
try:
    with _lIlO0IIII[0](_I1IOlOIl, 'rb') as _l1lIO1II:
        _lIIOIOII = _l1lIO1II.read()
except Exception:
    sys.exit(0)
_lIIOIOII = _lIIOIOII.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if _lIIOIOII[:3] == b'\xef\xbb\xbf':
    _lIIOIOII = _lIIOIOII[3:]
_lIllI1Ol0l0 = _lIIOIOII.find(bytes([35, 80, 89, 71, 52, 83]))
_lOO11lIOl1 = _lIIOIOII.find(bytes([35, 80, 89, 71, 52, 69]))
if _lIllI1Ol0l0 < 0 or _lOO11lIOl1 < 0:
    sys.exit(0)
_llO10IO = (_lIllI1Ol0l0 + _lOO11lIOl1) // 2
try:
    _ll1lOO0 = _lIlO0IIII[1](_lIIOIOII, _I1IOlOIl, 'exec')
    _IO11lI0l = _lI1Il0OllOl(_lIIlI0IO(0).f_code)
    _OOI01Il = _lI1Il0OllOl(_ll1lOO0)
except Exception:
    _IO11lI0l = bytes(32)
    _OOI01Il = bytes(32 * [255])
_IlO1OOlO0 = hashlib.sha256()
_IlO1OOlO0.update(_lIIOIOII[_lIllI1Ol0l0:_llO10IO])
_IlO1OOlO0.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(_IO11lI0l + _OOI01Il).digest(),
    hashlib.sha256(_OOI01Il + _OOI01Il).digest())))
_IlO1OOlO0.update(_lIIOIOII[_llO10IO:_lOO11lIOl1])
_O0O1O0I1l = _IlO1OOlO0.digest()
if _lIlO0IIII[4](sys, 'gettrace')() is not None or _lIlO0IIII[4](sys, 'getprofile')() is not None:
    _O0O1O0I1l = bytes((b ^ 62) for b in _O0O1O0I1l)
if compile is not _lIlO0IIII[1] or exec is not _lIlO0IIII[2] or getattr is not _lIlO0IIII[4]:
    _O0O1O0I1l = bytes((b ^ 80) for b in _O0O1O0I1l)
_IIl10Ol11 = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != _IIl10Ol11 or exec.__class__.__name__ != _IIl10Ol11 or
        getattr.__class__.__name__ != _IIl10Ol11 or __import__.__class__.__name__ != _IIl10Ol11 or
        open.__class__.__name__ != _IIl10Ol11 or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        _O0O1O0I1l = bytes((b ^ 44) for b in _O0O1O0I1l)
except Exception:
    _O0O1O0I1l = bytes((b ^ 44) for b in _O0O1O0I1l)
_OOO0O0O = sum(b for b in _O0O1O0I1l) & 0xFF
_lO1000OI0O1 = _OOO0O0O
_O0O1O0I1l = bytes((b ^ _OOO0O0O ^ _lO1000OI0O1) for b in _O0O1O0I1l)
_lO1Oll0O = hashlib.sha256(_O0O1O0I1l).digest()
_OOIO01O11 = hashlib.sha256(_O0O1O0I1l).digest()
_O0O1O0I1l = bytes((a ^ b ^ c) for a, b, c in zip(_O0O1O0I1l, _lO1Oll0O, _OOIO01O11))
_O1O0ll01 = bytes(a ^ b for a, b in zip(_I00l1Il, _O0O1O0I1l))
_O001OlOl = _l0l11111(_Ol00OI10l1O(_O1O0ll01))
_OOOOOO11I = "tzRZ6Ar9m/nRRnYCv2LbO6w37UIgmcx9UhDaFDwGFcoUsMJtDhcPX+6bE"
_II00IIIlO0I = "i7ByvEgSS+wq4hnZGMQu9V9E7"
_OOl1001 = "onWzYrAi4BS7clzlMXeZRloD60IPapl"
_O0O01O1OI0 = "XG3O82EkTOQ7BH+O2hczVWSSvAe37DDreyL49PUaBbj"
_OI0IIOIl1 = "CXUZj8kHb+FZQnpiYKAPkPXDV7"
_lIIl10O10ll = "/5ix4hu5ykteYGYIa4ITuh6ztB5GaIK3AcUNMA1Dqqa6sbGBvssMP4rV1W2I"
_O0l010I = "/hEmVJsWXjSGBTK0c4Q7uuoCNNsNLmCCh0a5hPxb8YmfwaN4wBr7uAXK47X"
_llOOIlOO = "FgQfFzgoYllZ381MZPzQNQA+rc9JVhf"
_OlIIl11l = "D3VUKvrcT6AJaHCMAqOxUWMWKboMFU"
_l1O01l0 = "GjVlXaDPaRLBshFElzY8Hqja8qKyh"
_OIOIlII = "QvhseHdHerkneFmoMY9Pax3N9YA7gDM"
_OO11O01I1 = "Rh06cJYt+tEfnrCTYfUjAHtVT0/A0tqN6waxBow3y0w7cPXm2c31Kqe0tNP8"
_lI0OOI0I1l = "E8sv6tCkr4yVslO3dT8AHo6FuVDP3"
_I1I01IIOl = "nSweBGuCzKRFe2MNwq0hYVqzrOyt+BopfF"
_OO10lIOll = "hVofwiG2KJzh18KJrEqglPdca7kkl9RvRQEDetSZ/CB1sL5ri+v2h"
_OlIlO1OI0 = "Fi1lWAi3wcDYteWoFYFn2JI250fPC1ZJkwg2eREe+VD/OdY3tE9mM/lhlf"
_Oll0IOI0OO = "28EkSP+b2+YYbNx3HkjPh2GJGLy/"
_OOI10Ol1 = "NDQeSdsv8FgZ1/fcDOssyUNBFkaAV"
_OlI00lOlll = "U9+dGsD1PAtZFg4vio9hdRVUCoeE6EDVZ3+RdfnD7tW"
_IO0II00O = "sSJigWGGHf6Dt0dpBWtsse6NL7Yh6w03q0+jD0w36CF"
_O0OI1I10l = "wTVkaNffqvwU68aIvK+uo8F11SqOjuM0u"
_l1O0O0101 = "HBnQjM9UZaKO+AcvwGJ7bhfj4acVxsYdiUzesombPezoYI+DHzzxf7"
_OlO0Il111I = "q6qcWwI0CCjw7iWhdHwtedM7sN+apqLUkW6FUKnVLABASSvI75GHmb1Mn0OUUfT"
_l1II10I = "5BgAfCgvu4fbod4PRWin6r80WFdTBxpwTRG+1miwyp3oJ"
_lO0IO1lI0OI = "IODGm545wJeYby8YWF+qOCfgJ"
_I001I100 = "8YgMGtrI5TOKmawHXOCRLWT2mhH"
_IIOO0O0OOl = "33Cg5vq6vVC/aMdKw0p02/W3Cl4NmmOIvy7fbC+SD"
_I01I0OI01 = "pJSpe27D6msv3SRAahhDLOUOCQtP6rFwWPg2KM7HR2TKah3e693qaOB"
_l0lI0lO = "YlRwX7nZ1XZfJtnCDUnIFRf4ayqvJPuzfjM98f1DDamWp/+ZgQUAgZb"
_IOO100I = "TS5/wrS08p/AtBffqWYGDN2hapt7dFQDuc0Zys/qGsaPpYAX02"
_OOOI01OO = "42wTI3XKAH6I9fMCMDEgm2QXmfE1nmbBVip6QXTS59Z/sY74aB4RjX2"
_I0I111I0lO = "X89fjmnnVOCkj1FVk8IPrdmRoX1t+HngaXtYPSJeDXVLiBx9Ats+x7"
_O1Ol00l0l = "0Q/f2m06zAsbTSfxeIqbpxtsEKv8SZr/lVkjbFbpZsXo1eX3"
_Ol11000O1l = "aXIq3g5KqkbF3XqCvIy3bY16uxT33+JxYV2Mm6rfE5zLT5DlXksaM66f/e"
_lO0OlI0llO0 = "xdjSwZ5HZoLpigJNC611YfFDD8iS1OEvELxP8BldM+BAW4vJOMW"
_O101lI1 = "0amG/Pcp5qTerxdnuuHu7ITJZyZj+vldXTEeOe78tZMkY/9O"
_IOOOOllO0O = "OKbeuN/hnHHRQVOUDN5JikD45IRAOAJtBdn"
_OO0lOlI1Ol0 = "bhs2xx8XH1RF5PcENILkCIFMVo2"
_O1OIIOI = "/mAtU4214ZmiBf9W6ZTSR+gQ6T8QVdOtrH7HJKOf3NNHIkAaJnry"
_OIll0lO = "SoAoe4RSzpAJSuTAxoygRYjeqHQfDL3M8o0FbUfd2Y5lqjeOwWYP7"
_lO0lO0I = "2HIxiU8B08wLaQHSn6sWrHmubqlmnDawpYNNnaJXjLsY"
_OlOI10I11 = "patp569lUjEORtQntyo1C1x6wdGEvMtCk4MSW8PagdgqC"
_I1O1OI0II0 = "h8gBqwehCvoBwPZLBA1fHgHuEDa9K8Ms8+F4WKPUFkzz"
_lIIl1l111O = "fdgFHYxoYVROVaDaOmixW1mH"
_IOI00OII01 = "F47aVWpQuESF63dOP0NpqnU0k"
_I11OI0IO0l = "Adx1gbTpsC1YNIvw0aMFs6e7F8Qa81qHkdl"
_IIlOO1Ol = "j7bmeVrB8R1YGUo24K8kTUiE33pRKY47dF66TMAoxHZW7AXlgQ"
_llO1IOOlIIl = "ogjG8TBmIaHy0YruSxUKvhy/ePfV9DXuzIk/A"
_IlllI0I = "d+IRhsgw5OM2S251C5Bz9JBoFPxEDEnR3k+nqFzgHflUJjfZLK2hvSZnBZ"
_O001I00l00 = "i4tMWAyNa9DS44IWGYNE7GUbj8Xkrjlc5O9My/I"
_I011l01 = "P4ePByqkNuEQ0KSAAeveS7VhedLuNTQ0U5dyzSSnqSep8ShdtRNCK5gT8Ull"
_OI111llOI = "dRMrWXp2FgryfILYaNDiu27d9"
_lIOO00O00 = "vmMnYd5/K8pMHjppFkT58faOkz/b/iXacr9XYzL5X04TxEi"
_lI01I0O = "H7PHWGsGkGaoZWgE4oVnp0CeuYc+z"
_lI11O01l11l = "0GsV0="
_I1III00 = "xo84BGS+4DbXEZPbwHW1/h8NbzJuFet4M6PHjTMK"
_ll0110IIO = "0+Fhs/XQyTUPp/t07tWjXXFmaUgNCf7gpS5i7VCh53zIPVMI/Pcp"
_l0Il1OIl = "59+7eh8fYiZSQQDXOPr5TI2WPC"
_I0Il0l0OIIl = "KAPfSDhDxCpC8b5fxP/45XOcNYh/Nm7aTccQh"
_Ill1Ol01O11 = "tCIYpdwbWZ0R8E9SAwFeG2L5YL6qnuVDzTxTbOZdmAFc6y0XL6"
_lllllII0lI = "2OMBA/a/2Cr6PyPE11yStdxVIMwt2m6N//ZwzAwME2G+LeezH"
_l01Il01IlI = "KFWE6ZoaRDf13ytYTSy4Sbypo56oey0PbPOEzPp"
_O0l1OI0ll0 = "sOAFC4ZxV/JiVjsoHZ5X7l63iOGo508Zwr/e6j293dusY0Ett1Ef/iLVEmc"
_lIO000lIIO = "z8CQ26YMzHttbSevQ26KpC9z9sVq37PG9E4Vg7Bov/FBLu5sVvI5c1r3xUtUDeX"
_IOlOlOlO1O = "t04hCn+UmjBZcsXC4Ksgv5B8"
_OII000O0 = "NMGWiEo0tJxyvMjAnxk/wpmUGnQmQfU64jM40y7yjBn2ZB4"
_lII001O11II = "cDf2CybqAEomJ5PpDFkFNyjEJJuj3+Mtr81PF72W6u0klE"
_lI0l00111 = "k9SzXtrGIpmfbxNjpGE1bC+03z4dQMQhnvpif"
_II0ll1IIl0l = "TqqyH/fgk/b1HlpfPwnlomE1AvnyEUB+Qr"
_O1lO0l0 = "f9czZjGuMS6G4ziFNiVkPf5NFBvN"
_lO1OIIOO = "yQXuM3qxMZpfyftWqGNipDGoN8f/v6OBB+74Q9yKWGy3UtcSDp71P62M+J"
_IOOOO1IlIlI = "fFXO7suW9J4Sf1z3AdXL4O2/gV/u3"
_Il11llI1l0 = "G0nkh7IDa7RA4KbelSHLCuTjxCH9"
_O0lIll0 = "TTq++e7kG2h7Yvb7EdFAizcVSWlg4+QLWJb1rALtdiy09Pfafe1bP5UShD"
_Il1Ol10OO = "GrZ8EqdguDI2IsWY4Yr42uAu0oziknsmRXCNALWa4HoRFq5nGl"
_O1OO1OI0OOI = "Uc3NjH+r655RrkeFKWinEk3OwsqBMMKk"
_lOlOII11I1 = "yDXztL6bOAQYrI85tJehiSe0r1sG0YYa"
_llI10Il = "SxpWQC/lT03e84b8VySGwaFVc77uwEbmBrlJSMjm1BNe/b/R5"
_O0O1l1O = "IMne5llLd/d918DDEI/jzbWReNp6KrADCzWNEg/84KKjNz/5A1jhTEBg5wkSI3c"
_I00OII1IO1 = "57qYjWtnkKMqs39SC35bWyiZbDpat1hUN/3QvkHvQOq"
_OOIO1O0 = "EJ6yzOzWjFnt4bMuob9BECUTx5t55Lgc0a"
_IOl1llIO1Il = "zx38hPzgYW/gfhthvzeXPdjVuN"
_lO0101O10 = "NJHMXlI95yDlr+tltvcgZVWfvjuLdzXae4t"
_OllIlIOI1 = "XiOg0/ZdfArKK6lbYvaqmmEVQkPQG"
_OlIOOI1I0 = "WFitz/xKzXtKShRzW6UKZgf+U2oD39MAHHGZgsmS5NTKcDps7ENBaI"
_IlIIOOl0l1O = "07E1XOkxGRjvE+oN9iB6hu4SaDD84mVVXBBtxJU/GSQ+jA5RnaRmh"
_I00IO11OI = "Y/VbD/f4N2WqCx2IX/v44KQd2TOSklGEOxrSw0sfFPVTCTqHom8/Qs0Y"
_lI1l0IlIl0 = "AzaeATqyu7aBDVey+FWxkJVJR/3vFySmes025zl3"
_l1III010l = "nA+ZFisR49/86e1dB06djGD/DSgJIf0w4RyxjEjXx9qmGjwZOf"
_IOOI11lOlO = "eNwsD+MrQAgdLsSNVTcKe5IDZ2JbFaX0zHdco7w1F0F4R2o"
_I0I0IOI0IOO = "1WeRKgq+xM4hqqFs5c6IpKJqY+K"
_I01l1ll = "yCYUuiFsvlLM5fs9+fhCK6sD83j3+madB1cox8PS3isDin"
_lIIOOIIII = "9b7xeVbS7enkTBMpSBmxY7waEHmXigKwmTeS8jMhbaRp5P0cp"
_I1I0OlOI = "rQQDDzA0/QrMRoA8JwSyDmV646dvPgElJqRdvABgAt8Ge9DWWdG"
_OI1OI00 = "WackUByJoTENRKURzsnuEAkj4C86LaBnqHoBUz/o/K8O1ZjYXlvB+7TaQcdGC1v"
_IO11OIl10 = "ylSJ0uJlbk5k2JuPGXNUeUL1jCFnVJiG3/tR51yWVGGO2"
_OlIOO1O0O = "lbJU9i+kbFqEEvz8H6dsynmTqxe5XfAJ98SZpjq39"
_llllO0IOO0 = "p0+LZaSenth+bh/ZRGVSGMNzFwuTAc"
_O0l1Ol0O1 = "PTbkt83E8eqcywaNJOOXdya8s+P83Nj0/g7e/TAn3QtItN"
_IlOII1l = "kx+mNgN7OCi3TPe+MLpa7p+ToDwajTmUmmfAienQ+VRh"
_IO11IOI1l11 = "FYFki70RjZERPcb/zetrTiC3rKzQVZhAZFSVEZk7gbzXGzl3VCVCvPfdPBq"
_ll0IllO1OOl = "WL9p1twpPXDt1gJq50Zh3kFRa8vstqCcgaBjxaMBTkQDZseqYkCDYBDyKc"
_l01II11101 = "7baQ/4RqCkhjug/G7nfUcPAeMEWsYeon5ECUhHYvhcP4fSNlBJjo7m/7P0KC"
_OlIOII01 = "RKFAV2tAtqXN9Irae6G1Bm4hl2"
_I0Il0lOI0l = "2lLtn2/T5Rn9PoMixFlt/3WL"
_lIlI1O0Ol10 = "wobuYXQn568lQ4b65fGSUERRX7a1OKwYs5CFzlC4pVJjPm"
_l11llIO0I = "ydoVNk7qEog4sApkAjFd4rY7XPhWXymhRt"
_IlOI0Il01 = "fnMcTu2GBeQ9dMyCjB4lHUkh3CT"
_OllI0lII0 = "9sAaUm/aivvYVOGSigsjQ27H+M"
_lO1l00OOIIl = "hJfR+dhJ6fZ1OwFexH6GcOGj94kJBQJfoDlDR"
_OlIIIOO1lOl = "KspNohFn+C9FLwhOXEpy56wiRltRZ0p7lgRDYaLULEOKEKfikx8FWd5V"
_llO01101OI = "bmYBwL+tUhLvLvdmw5+Ak5HK6TYIL"
_l01ll0O0l = "xaQ4WnfUQBb1i97na89IGsnsYs"
_ll01I101OI1 = "q9P1/77M1Nob/38+Al8TJQNFf/yWlBWThWWRFyD1I4cm4vI9"
_OOl10IO0 = "ACKw8XtQkdY5/5JeLJ27bCdEzk4411IbLgo"
_lIlOl01l = "KatPHIuIx0eITUO6F9b2dWKaOiI135Fg5s/CBUar0/Oe/ptWoGX8J"
_OIO0l1IIO = "fS6Wd6iwAmogm/AmGQOZGOoz0HlP7/PLcC5QbMzKzwyCIDuR"
_II0100l0l = "IEirBUYrhKwX8PJHuqEultf/Bb4z8wlC"
_OIOlllOlOIO = "L6sxfRrmX4TlcNEsbjvRzkF+1rPgjI0ILP9AfhkeI5J2Soo4GUD3iN/Bvx6oB"
_lI0I0l00 = "rG3KliuLd7V+1OqTreBT1fUO7JvWP+aDf/FddE3gTTeXR"
_IO0lI0O1 = "q3eet7Zru55sHIsx9830ftDjnZSPtdj"
_I11O0OI11 = "OSEfjooRIR1hoopIidZR+jT9K9xNmYCU+wHojvXjPSPAgD"
_OlI0l00I1I = "QOWutGSrnPXTKR4JMP6/Of9yQAD2CZva8pZSaAbwUyZrFNUJz8Ow19BeS5Nip"
_O01llllO = "r83P0IPr373WCC7WBdYxlXXAp2rsA6hrK0M7r"
_lO11l1OI = "g+e29xlQDI/OQ5YGeUpX8oc3Gs4+VK1JWE0GSAGMsY7+/T1mR/g"
_IIlOO10l = "hqDe2HJpR1FO2FVdGl62vqcMwbCA"
_OOl1I1lI = "gD8ESEQZoWV7JHUckmEx3Xoiws+20Hqg4EEtSvEqWJGT"
_I1lOl1O1OO = "UmHc6v6E3iTVC6q49kGG2gqX8OMaBx/X6iLOlj0D854gigyDDXqiMe"
_O0II0lO = "kIzTezgqc2TZ0xcTPuu23iJ1htnPQxxEHBy2gy7bmlQZrDrytQlPwtDGzRvBsUz"
_I1OlI01O1 = "GzRZf9EyTTnbulz+yumrRG+ECqGHyyqKSBC1Nb7pd1vR"
_IlOl001Il1I = "tP0403jwdrFrrjDntn8Cp5pE9Q8lmTUhAHvAuJauTBPo1b"
_I0OIOlO = "+IguWLIhCZs4X0ECKWUA5FOrebhi6ZAdctuoRTkj3wU8/mf"
_O00IIOO = "erBikdsNEwJvSDDkfCxoPE/DNN0v32TMmRsuTPua4mVqfYhe1+JIErY"
_lOlO11Ol0 = "c4L+bv/6lN120lPrTxs6EIVgXtT3Bic6NM2j0MqCgnymJI/mYxYGm"
_OOI1IOIOO = "0rHa3mJppnWLiUKQAKBkGUghQFdaBDYl"
_IO0IIII1 = "MxKeYruisu9dvR9pcfC3X9iA30"
_OOI1OlIO01O = "0WfDTnzlF7eMibqphzhEfJG1l9/73/"
_IOI0llIO110 = "caAmmKg3zkL1LrFYefZKrw6oOlH/ZY38jDoIkEYl"
_I101l10 = "agSulHiw3xhJGPd6qVkFWrLFcMGnzSTI0F+aQVoK34H7X0WNKmRSx2dFL2"
_OOlIl1I = "kZ7gkDp0bqzNrvcrofNtT5JVa90eUSW"
_l01l110O0l = "1iOYjh5RxBz8IgcfaWEGxL7jisHqkbKLjZ726fBs"
_I1OO10l = "mWDqEvVhFA23Cz+sVmZ3c48WIxFeWoq"
_I1Ol0OI1 = "M4h+bqAWDu3PP3fsOKxJvRkU/gwdiWbUSTvDX2lfU2FpEJnmoUW"
_l0IOO1l = "5rkUJ0Mt3KMqeXYU5V7QtK135uDfI3Y9cQcOXI3"
_l0OllI1OIOI = "wRJtkdKp6C/e4jBkNl2LcruF6scAKJQfFrU6wdVUdmR9SIk+zNgdeye"
_l1OOlIlI1 = "gVe4Ssb/jsHRvfuuIt9uhf9gUtrHVKa4woZDMtiNsObVAMFfUfFRDQTYiExPdhv"
_O1l1l01OlI = "mmyX5EZUZAjn/aS33P5wjzygl2HsZn29HveHY"
_O1O10IIII = "ErHjt8Yj0gC35k4/+gb58eltBYzNeQVwLFwaeVsLXljbZEn6k0jgh"
_l00II0O = "CqopI4CjoQYOtytBTaB0Z8BicwXKbXkPOnaWuJuHNrZt"
_O0Ill1IOI1 = "X+by1JVq1I1jCEd9JZBI8W0fgvZMkoEHKwkpgpmUc9TeNTJGi+9O93Zl9Px"
_OO0OIll0OI = "0jq6TY7bT6TzEjBQmZsNEjMh7OFxLPCFeOd"
_O1I10I1 = "+vkFUcrbTYdu6PrbnaqDFMk/1SzzBae9GuDNS8ep"
_OO010lOO0I = "PA8xmpH7vqi9Cf1iQ4TILwov8fYA/qOYoA0TTgC/pJV7y6aJv+M5"
_O0I0Ol0I = "D9Nc1VU6PC6BJBq3IKZlhqlnEr23UnYDfFVVPwPX2roUM2iGaLkIfBTXPMSN"
_IO0OIO1 = "MF9bCemyprA+gKAuJo7PbP/U"
_O1II1O00 = "33SmWuKdzlQAeeMcnfZK4XnbZl3AQQTQJFWDu6ednZ/"
_llOlIl1I = "m3iPPuqr1ebJ2knsWFU9JOlJA4"
_l1O1llOllOl = "JbshE7ZbNBsIQLG2GTmMkPiBpzwlW4K3tesInZj4mOkuReum7"
_O11OO0ll0 = "tVex9acAwHIQZfER09/JyeINxXpz34uoGaHFVTpWVmkUn8Dm"
_IllI1OI = "+zshDHx1gBPwMwdyPuEwEmPgqtFck8h2BoYVqOV"
_OOOIIOO11l = "KqyvylJrF9SNnhsjBJXprezIxsRuHZF5q0fYkmgwVBVvpRwrKwlwkI"
_I1ll0I1O0 = base64.b64decode(_l00II0O + _O101lI1 + _IOOI11lOlO + _O1l1l01OlI + _O0I0Ol0I + _I1O1OI0II0 + _OOl1001 + _Il11llI1l0 + _IlOI0Il01 + _I0OIOlO + _lOlO11Ol0 + _O0l1Ol0O1 + _I1III00 + _IOOOO1IlIlI + _IO11IOI1l11 + _IIlOO10l + _O1OO1OI0OOI + _lOlOII11I1 + _II0ll1IIl0l + _O1lO0l0 + _OllI0lII0 + _OI111llOI + _O11OO0ll0 + _OlIOOI1I0 + _I00OII1IO1 + _lI0I0l00 + _I00IO11OI + _IOOOOllO0O + _llO01101OI + _OIOIlII + _OI0IIOIl1 + _O1II1O00 + _l0Il1OIl + _I0I0IOI0IOO + _IOI0llIO110 + _lI0OOI0I1l + _I01I0OI01 + _lO0101O10 + _l1OOlIlI1 + _lO0OlI0llO0 + _lIIOOIIII + _IlIIOOl0l1O + _l1O01l0 + _lIIl1l111O + _OO10lIOll + _llOOIlOO + _O1I10I1 + _O01llllO + _IIOO0O0OOl + _Ill1Ol01O11 + _lO1l00OOIIl + _l1O1llOllOl + _I0I111I0lO + _OOOI01OO + _OO11O01I1 + _OllIlIOI1 + _Oll0IOI0OO + _lI01I0O + _lIIl10O10ll + _OIll0lO + _llllO0IOO0 + _OlIOO1O0O + _I1I0OlOI + _lIlI1O0Ol10 + _l0lI0lO + _lIlOl01l + _Il1Ol10OO + _ll0IllO1OOl + _OlIlO1OI0 + _IO0OIO1 + _lI1l0IlIl0 + _IOlOlOlO1O + _O0O01O1OI0 + _l01l110O0l + _O0O1l1O + _l01Il01IlI + _I1OlI01O1 + _OIOlllOlOIO + _I0Il0l0OIIl + _OOI1OlIO01O + _OlI0l00I1I + _lI11O01l11l)
_OOIOl0I = _l011O0Il0IO(_I1ll0I1O0, _O001OlOl[0], _O001OlOl[1], _O001OlOl[2])
try:
    _Ol0I00l = _OOIOl0I.decode('utf-8')
except Exception:
    sys.exit(0)
_lIOl1lO = {'__builtins__': __builtins__, '_lIlO0IIII': _lIlO0IIII, '_O1O0ll01': _O1O0ll01, '_l0l11111': _l0l11111, '_l011O0Il0IO': _l011O0Il0IO, '_l0IlOl0': _l0IlOl0, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': _I1IOlOIl}
try:
    _OO1OIOOl0 = _lIlO0IIII[1](_Ol0I00l, '<s1>', 'exec')
except Exception:
    sys.exit(0)
_l0IlOl0(_OO1OIOOl0, _lIOl1lO)()
#PYG4E
