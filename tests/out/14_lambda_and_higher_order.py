#!/usr/bin/env python3
# Protected by PyGuard v4 (pyguard.akean.dev)
_l1IO0OO1 = bytes([38, 231, 183, 32, 253, 34, 245, 129, 100, 246, 128, 209, 89, 36, 49, 84, 12, 102, 164, 169, 9, 69, 187, 211, 26, 90, 224, 171, 114, 144, 204, 201])
_lO10lIOl = bytes([82, 95, 104, 94, 14, 41, 133, 87, 119, 67, 236, 163, 47, 16, 186, 140, 246, 21, 121, 141, 27, 97, 154, 216, 139, 111, 85, 63, 5, 206, 31, 181])
_l0lO1l0I0I = bytes([190, 83, 133, 234, 117, 228, 234, 153, 209, 222, 189, 160, 221, 227, 32, 165, 0, 186, 240, 53, 171, 95, 193, 139, 170, 134, 170, 207, 98, 94, 112, 110])
_lO0I1l0I10 = bytes([201, 46, 209, 70, 33, 198, 7, 102, 217, 10, 102, 11, 163, 42, 68, 115, 253, 34, 157, 219, 114, 79, 174, 239, 8, 42, 103, 240, 171, 57, 54, 11])
_I0I1OOl001 = bytes([147, 201, 246, 218, 128, 244, 110, 220, 217, 16, 173, 80, 129, 24, 246, 35, 188, 99, 173, 184, 136, 6, 233, 10, 120, 50, 215, 102, 18, 146, 116, 208])
_IOI01I1 = bytes([36, 14, 253, 49, 244, 147, 11, 19, 60, 91, 186, 199, 28, 23, 119, 108, 221, 190, 205, 53, 213, 29, 184, 232, 37, 120, 121, 97, 99, 75, 227, 232])
#PYG4S
import sys, hashlib, base64
_l11l01I = type(lambda: 0)
_lIlI0OII0I = (compile, getattr, exec, __import__, type, open)
_OO0lOO0llI0 = _lIlI0OII0I[1](sys, '_getf' + 'rame')
_IO11lI0IO = hashlib.sha256(bytes([69, 221, 124, 160, 27, 172, 75, 87, 27, 195, 184, 21, 60, 227, 13, 200, 245, 253, 72, 250, 1, 29, 9, 129, 82, 38, 154, 36, 226, 234, 126, 114])).digest()
_OO1OO1lOl = bytes([110, 117, 71, 236, 101, 36, 231, 34, 149, 40, 128, 59, 35, 151, 21, 53, 1, 193, 151, 38, 121, 48, 153, 137, 200, 138, 22, 44, 168, 237, 93, 180])
_OI11OOIOl1 = hashlib.sha256(_IO11lI0IO + bytes([216, 148, 36, 222, 159, 209, 44, 27, 75, 185, 48, 39, 255, 106, 253, 111])).digest()
_l00OOI10 = hashlib.sha256(_OO1OO1lOl).digest()
_I0OI1O1 = hashlib.sha256(_OI11OOIOl1 + _IO11lI0IO).digest()
_OOI00O1 = hashlib.sha256(_l00OOI10 + _OO1OO1lOl).digest()
_l100O10O = hashlib.sha256(_OOI00O1 + _l00OOI10).digest()
_l0II0II0 = _l100O10O
def _IIIIO1l1(_O1IlII11I1):
    _O1IlII11I1 = bytes(a ^ b for a, b in zip(_O1IlII11I1, _l0II0II0))
    _Ol00lIOlll = []
    _OO010O00I = _O1IlII11I1
    for _ in range(7):
        _OO010O00I = hashlib.sha256(_OO010O00I + bytes([169, 35, 157, 77])).digest()
        _Ol00lIOlll.append(_OO010O00I)
    _IIlI1100O0I = [(b % 6) + 1 for b in hashlib.sha256(_O1IlII11I1 + bytes([67, 124, 244, 103])).digest()[:7]]
    _OOl0IIIll0l = hashlib.sha256(_O1IlII11I1 + bytes([192, 59, 26, 216])).digest()
    _OII11O1 = list(range(256))
    _Il01l10lO = 0
    for _Il1OIIOl in range(256):
        _Il01l10lO = (_Il01l10lO + _OII11O1[_Il1OIIOl] + _OOl0IIIll0l[_Il1OIIOl % 32] + 19) % 256
        _OII11O1[_Il1OIIOl], _OII11O1[_Il01l10lO] = _OII11O1[_Il01l10lO], _OII11O1[_Il1OIIOl]
    _I1OIlIOl0Ol = [0] * 256
    for _Il1OIIOl in range(256):
        _I1OIlIOl0Ol[_OII11O1[_Il1OIIOl]] = _Il1OIIOl
    return _Ol00lIOlll, _IIlI1100O0I, _I1OIlIOl0Ol
def _lOlIOl00l(_I100OlOI, _OIOIO0lO1I, _l1IIlll1, _OIl0lI1):
    _I01l0O0l00 = bytearray(len(_I100OlOI))
    _I10I00O1l00 = 7
    _OOlIOI00 = 0
    _I11Il101I = 0
    _OOII0OO1l = 0
    _OIIO10l10l0 = 0
    _lIOO1O10 = 11
    while True:
        if _lIOO1O10 == 148:
            break
        if _lIOO1O10 == 11:
            if _OOlIOI00 >= len(_I100OlOI):
                _lIOO1O10 = 148
                continue
            _OIIO10l10l0 = _I100OlOI[_OOlIOI00]
            _I11Il101I = _I10I00O1l00 - 1
            _lIOO1O10 = 33
            continue
        if _lIOO1O10 == 33:
            if _I11Il101I < 0:
                _lIOO1O10 = 135
                continue
            _II00llllI = _l1IIlll1[_I11Il101I]
            _OIIO10l10l0 = ((_OIIO10l10l0 >> _II00llllI) | (_OIIO10l10l0 << (8 - _II00llllI))) & 0xFF
            _OIIO10l10l0 = _OIl0lI1[_OIIO10l10l0]
            _OIIO10l10l0 ^= _OIOIO0lO1I[_I11Il101I][_OOlIOI00 % 32]
            _I11Il101I -= 1
            continue
        if _lIOO1O10 == 135:
            _OIIO10l10l0 ^= _OOII0OO1l
            _I01l0O0l00[_OOlIOI00] = _OIIO10l10l0
            _OOII0OO1l = _I100OlOI[_OOlIOI00]
            _OOlIOI00 += 1
            _lIOO1O10 = 11
            continue
    return bytes(_I01l0O0l00)
def _OOlOlIllI(_IIl11OO):
    _O0lO101OO1 = hashlib.sha256()
    _llOlllI00 = [_IIl11OO]
    while _llOlllI00:
        _I0010l1 = _llOlllI00.pop()
        _O0lO101OO1.update(_I0010l1.co_code)
        for _IIIlIOl0l in _I0010l1.co_consts:
            if type(_IIIlIOl0l).__name__ == 'code':
                _llOlllI00.append(_IIIlIOl0l)
    return _O0lO101OO1.digest()
def _O10lIO0O0O1(_OO10l1l1I):
    try:
        _lIlIOll = bytes(a ^ b for a, b in zip(
            hashlib.sha256(_lO0lIl10 + _OOlOlIllI(_OO0lOO0llI0(1).f_code)).digest(),
            hashlib.sha256(_lO0lIl10 + _lO0lIl10).digest()))
        return hashlib.sha256(_OO10l1l1I + _lIlIOll).digest()
    except Exception:
        return hashlib.sha256(_OO10l1l1I + bytes(32 * [255])).digest()
try:
    _l00III00OIO = __file__
except NameError:
    _l00III00OIO = sys.argv[0] if sys.argv else ''
try:
    with _lIlI0OII0I[5](_l00III00OIO, 'rb') as _OI001OO010I:
        _IOIO0IO1l1 = _OI001OO010I.read()
except Exception:
    sys.exit(0)
_IOIO0IO1l1 = _IOIO0IO1l1.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if _IOIO0IO1l1[:3] == b'\xef\xbb\xbf':
    _IOIO0IO1l1 = _IOIO0IO1l1[3:]
_l1OlO1O00I = _IOIO0IO1l1.find(bytes([35, 80, 89, 71, 52, 83]))
_I010Ol0 = _IOIO0IO1l1.find(bytes([35, 80, 89, 71, 52, 69]))
if _l1OlO1O00I < 0 or _I010Ol0 < 0:
    sys.exit(0)
_ll00IO0IlOI = (_l1OlO1O00I + _I010Ol0) // 2
try:
    _IlOl1OII = _lIlI0OII0I[0](_IOIO0IO1l1, _l00III00OIO, 'exec')
    _IO00lO0IlI = _OOlOlIllI(_OO0lOO0llI0(0).f_code)
    _lO0lIl10 = _OOlOlIllI(_IlOl1OII)
except Exception:
    _IO00lO0IlI = bytes(32)
    _lO0lIl10 = bytes(32 * [255])
_I011Il000 = hashlib.sha256()
_I011Il000.update(_IOIO0IO1l1[_l1OlO1O00I:_ll00IO0IlOI])
_I011Il000.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(_IO00lO0IlI + _lO0lIl10).digest(),
    hashlib.sha256(_lO0lIl10 + _lO0lIl10).digest())))
_I011Il000.update(_IOIO0IO1l1[_ll00IO0IlOI:_I010Ol0])
_OlIlOOIO = _I011Il000.digest()
if _lIlI0OII0I[1](sys, 'gettrace')() is not None or _lIlI0OII0I[1](sys, 'getprofile')() is not None:
    _OlIlOOIO = bytes((b ^ 182) for b in _OlIlOOIO)
if compile is not _lIlI0OII0I[0] or exec is not _lIlI0OII0I[2] or getattr is not _lIlI0OII0I[1]:
    _OlIlOOIO = bytes((b ^ 233) for b in _OlIlOOIO)
_IIOO0O00OO = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != _IIOO0O00OO or exec.__class__.__name__ != _IIOO0O00OO or
        getattr.__class__.__name__ != _IIOO0O00OO or __import__.__class__.__name__ != _IIOO0O00OO or
        open.__class__.__name__ != _IIOO0O00OO or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        _OlIlOOIO = bytes((b ^ 200) for b in _OlIlOOIO)
except Exception:
    _OlIlOOIO = bytes((b ^ 200) for b in _OlIlOOIO)
_Il0lIl1 = sum(b for b in _OlIlOOIO) & 0xFF
_I111l1O0I = _Il0lIl1
_OlIlOOIO = bytes((b ^ _Il0lIl1 ^ _I111l1O0I) for b in _OlIlOOIO)
_lOl11l0l1O = hashlib.sha256(_OlIlOOIO).digest()
_l11I1Oll = hashlib.sha256(_OlIlOOIO).digest()
_OlIlOOIO = bytes((a ^ b ^ c) for a, b, c in zip(_OlIlOOIO, _lOl11l0l1O, _l11I1Oll))
_Oll111l = bytes(a ^ b for a, b in zip(_lO0I1l0I10, _OlIlOOIO))
_lOlI0O0lO1 = _IIIIO1l1(_O10lIO0O0O1(_Oll111l))
_llOO10111OO = "8w0Eq+NT3HR7QiGuV0+WVW0a+t8wY1vuwUL1NL9ehkGlhaGu8"
_I10l0IO = "jyNIaxvvCZZtiEcOu13V8kYWCn6q7FHCumvbkdh8O"
_I1O01Il = "81ytN6O3yjmhwZswhO9ROD2G5qTcvsGqoBFEI"
_II0IOl1l1IO = "q60eslGOeQKnbc/LMRbVd3E+yzP5om"
_lll01lO = "KRn1wLbLoVSKq94vY0Efc6VGRep+CIxPlzZj0Cxh"
_l010lI1l0I = "tUod46el21CXpZft7TR7tRYONv"
_IIll10l = "0v/up1QeBcZrv8sgK6qDcZwWvNsNqYWE6IF2Uz6IduXPtSxeUKPSQcKpn"
_l010OIlO = "tlG0aeC1FLfBrFlUVUdYVLbQSaKS3w6G8huqyKk5IjTyxzVt"
_lOO0Il1Olll = "CLBXxA3X3gjq7rP/skl9Ry4GibavERhWV/roL9"
_OIOll1O = "jTP4fyCFysfCD31hPkdIqBKx0WtN3nCE1k"
_l1O1lI1l11O = "lKk5B9MYb1oOvGw+lihFDPVGC2M7/r9O8y40Y+Vnuk6"
_lIll01OO0ll = "m2S+CP8sjUkheV3x9SJKpxjQAy5Ghvgy5pm/WlVpp4bU0xwn5c0CqxSsYK1fCn"
_l0IIlO00II = "g5iW/LUWnF5quqtYnT5YudzhmB6ysDnLf6dL9hmfgkU/bAEnEUJrprjbxIG"
_OOOI10Il0 = "ljsGK6Z2btTmPTnIDcm7OW8jRsUKi4ymGBCu+5Nqxt8nvoXvs06WHS8ox"
_l1IIl1l0l1 = "e5q0Y4gHbSVYm/Iel9cl1CUNRUyakV0P1mgyd5d+od5cLQY06yTbL2A75M"
_I01l01l01lI = "aj6qLR0EqRERNd68ycxD4NJPrLS3obLPVTK"
_IOIl0O0II = "yiXRqTV9ERaIx8jCQVrighfhS7/T"
_OllI0III1I = "IH9Vn452u+bMqQqQCZH/wb9iOzlLRzAFn5l3q4g4a"
_OO0I10I = "alm5pnAvpieTQZCc2r563rHEan4wWJ5EI1FJMw5NutfBTXgpwK67UD8"
_l11I1OOO = "cWsevEHJShIWw4jfKKjJzz6cxrWM4wvoy"
_O1OIO1I1llI = "pZSU1lVQpqjUEE/cpeLxKdDj/LzswIqoMm7bRZCGV5kgzmY"
_llII1Il0O = "cI2yXPxJxR7RLlTrKiTp/Dd0qgx6v"
_OIlOIOOOI0O = "yBytcYbXuw/ShrofG5zxYJkuOhUp6"
_OlOI000l1 = "VJ6qkvSYO/1jGB1guQef2QYFTNSr9QEeqRQC"
_O10l01O = "ZM4uc9EWH+1DnZ6dlLLtZ6s8XasjiCjNcATDDjD5jJGLCte/TTvee14uq"
_IlII0l1 = "1v6kDKg98/PCWqVNhtkVsPbuDlrURj63GI+ErPZJYQXWiegR"
_I00lOlll = "cdwZ4v5rifBpy0ww65u836k45cyxHFx/Q"
_OO1000O = "d6GJ26ZQSPjLIogEdbmeP2//TnobyaiL5zB5S2ysRjkz7Jksvs"
_ll10llIl0Il = "Ovr2bMMGyTZM5drcf4/l+umdkkYcyV49ZRCza57ZtmIZ5jJjeme0a35g=="
_ll1I01l1 = "wl/RsAGAjFL2lJML7RdXjuPGfQlNA3jyt0JWFdHicYNFPBRG2SbWeTw"
_OlOl00Ol = "To9g3mwlBPjE0y32fisHNyV+1Ozuv1HknqDj8eHc"
_lI11II0001 = "cG9He9Ss6QYrXWrIdwB4GjtBVZijuNFDv"
_Ill1111l = "qjQOpkJP9KreIe3eH2DupTGh5S/UFuWD0xvHJFBkTOVW"
_lI1O100lOIl = "/TD8ocWfI+j0MV88Dd0KndTU5mK1LbzzPhpyhbP0AiXRVORLteHmo"
_OI1l0OOI = "+w9+0LM74X0N8HIhP/McJhWWQ4TQTwhXYDCSfWsk4FprPAzGPA+azZ84"
_Ol01II11lll = "50UuGVNsQtI+aH17DuxHZgvUWv6nFUxy7VXyZHMy+LMqmWSbqWhosNdrMt+IDo4"
_ll01O01 = "vxenCVKK9ecbskMAEOY0+hCqS4"
_IllIO0Oll1I = "uq5e9/F22DuaBFO/lTsUg4skZRkfc"
_llI1lIl = "VnBAYCoNhFZp2HBYUIMbHBYE0iDIkNNtWK2YCAIDQUqoPcyTdTLSIWWZs0"
_I1I1Ol001O = "fkKVwkQV4zRd7nAxoMmrsYOa"
_I1IOIlIIlI = "71BQiLHYtDIPxrxS3P7B+ZCbZf"
_O1l1I1l10O = "qIpmjVo/KunNXYmfuoZ4c8A9ZlsXNGy"
_l0001l11Il = "DVUhySSox7QAuW3ODcixrhyWdZMJf+wSy+IhL/SYaTK35483E"
_l0IlO0l = "jSKHglloywuNlfPZChfIOcZgYIl/zbHVB5xQ46"
_O1O0l0O = "A/l5Jva0+QE4UzRcJC3KjA7KIZB"
_IOl1IllO0I1 = "KEk9IUdU2xI45jwuJlRUaYqFa+vhylOK2buWsZhvvbk5Bpj6"
_Ol1lOO00I1 = "y+/DXuKEq0NDING8hDtAk8+DmQrtRUmqwndEvxZfh3M9wjYDVCKUl84Ws"
_l1lIIlllOI1 = "M8jxjek/1oRTpksiqS0GHbuQcgt+xpqKURJP7yx72ahMPfyaRD/ks7F4s+"
_ll1ll11OOlI = "foqBUcZ5sy5DEcr9YfSyArD9D6QpovrpY2RQEklGmSpkn249YUS0n94mwvIi"
_l0l110I0 = "2x2adYl5l1CQx/gyBN3KrI8QuihpEzKV396Fi"
_l0OOl0lOOl = "cQ1zjsmV9krc/NmyhYkk3EYhmBe1Oeq8BtxnHtIbeoI/b1oMr99E257XyklMBj"
_ll111l0 = "F3EOsxdH0exieOH02f9J0gPbxOzp8hzaqlSrgE10IQGxmoprDiQcnTaicXxj"
_O0IIlI0O = "av24niIzfwVfQw5PK2LB29kdi/G3cv9W4LrHQ5NXAvnDvHd0tkD7"
_IO1III01l = "xtEUjXFfzTOYPrAWucWexHfB+9PRirwCaR5DcTNU8/rGE/X8n7BG"
_O1II1O1 = "09F8DWpIUDt7YidVBu+q322Bp4m72qhtnHwhFDHJ3RCi0XxBzhkTj"
_ll0O1lO1 = "W0firEC1ehtBY2zPIyLKRE9rXOCM350XtRNv4R76"
_OlIOI0ll0IO = "jkyz5Eb79LBfioiLFlMMtkUAPI9yw11Qr"
_OIl10l11IlO = "FbWu8y9Hzztm4icriY/lsPOBe8wgmTm0z4YycH1nurwVrO7JLggxgUCps2Ij"
_OI0IlO01O1O = "OecWYiC1vYP/mAuV1YGLOHGZ+J14CuDDdQc4L9CtrgMx80ZMIkFo05ftiY"
_IlOOOI01IO = "QSyR9VMtbHek7A213yki7hsHcWMvH5tiSh6k7YUj5h"
_l001lO1II0 = "fuVCRJH+AmHEF37w4lHlceRjkmwcQ68iq3RqD52kef39/sRFHV9"
_O0IIIOl = "FvNu5XgwbWj/y/mJU+7dpZzyTOktRlk8qwFRpbaqs1Zbppg74"
_OIlI1II = "JMx0vwceatNJ0DmKn+GlmjFIB"
_lOIOlI01O = "MbZ2RuD2zOTDQkq58J22QQUOFHJ03oswIdqMSQ+tdz"
_IIO1OO0l = "517WXV7d5deD3HHfk9OtJXmdJB16NKUFsHfonVxNvlCwNl/9Mwf"
_OIIII0010 = "1ib2h4aMDAyLVLhXt+bZZ943JLwkGwpk5eA"
_Il11l1OOl = "UZ+iQ2jrI86VRltq0hdkML40XSlACB2OYBsPYqzg3"
_OOIOl1011l = "Z9K5gOpo71E6sXRpc9dvyX+MWSVfwoM92KJkVuK08QuDRTQZKBg7pBu3b"
_I010I0lO = "s+wI8EuJC6oD16uC1HwntJC68AiDrk0"
_OIOl00I000 = "t06oGjd3JoUj3vX8eWArVUlqUzXkol50MA0PQaNi9Hahra4/04SjI"
_O1OOO0Ol = "nI9qKJScAGJRYmk5/4agB3X1weVL71fjbQk75GR8BTz8JUWxpNab2"
_lI010OI11O0 = "GrzSUIAsqt+rJ2YQQf20VkygafpI0klylHhyUh15774Z6seGaMLGOU4"
_I11IIOOI0 = "nDiaevTHl0eGxjIrMUPwJkB+Uc6H1W58gzg7oqw+q+5w5CEUNOcrdvQei"
_l0llIl0lO1 = "H/qMzg9jiGgo2BNGSuvQGsT96Pq/SYnAEhEQU/0"
_lO0lIlI01 = "0mEWM6ftRkVeV7vVn7E7n22nss1/GTVgKLgTW/IoHznSqWn9w"
_Il0OOOOl1I = "Cfzw29Qgj5uD9fcPXjQtj/iJ8OgL2E"
_l10OO1Il = "x/IAfMo3ux25l5iE7zQbj50DdEYDI95DWUSB88U"
_IO1I1OOO0O = "VZPOTyZDfxLMe8gAy3mkgomWCFB4lZhFwTyXa6YAbnJEdBb5K"
_O10IlllO0 = "3xAybeYi+WrkT0ZxNxtFw/JvyCZPYNI3gMEm2C2n9d"
_IOOIO0IO = "MXJxbml/ivwPiZsfQc0LIAWS"
_IO0II0Il1 = "4vSw2ViUhB6Vdrl9KGI5CdYDTFxlqa24kvA7svf9pmWZAs0ybL7A7Oi9eRN"
_l1O1l1O01I1 = "Q4e0Iy1P3KPLxC7FHOMKfDQPG2lkNXrm3Q6CiwpiIyLHMfJmHU4"
_O0lIO101l = "jHaL+4h9+/1z6VJQyNk7pIiKXXqc"
_IO0O0100I = "Hu8Zk9DiAIbuV00nQvajk98iEwJW7OPR72IUXQ"
_l10OOIOO = "tE5bIG+A7KWQif1jf6faMwzMlnxEYiVMyHWaVyC8sI+qjrCIxuRHP"
_l1I0111 = "ICEGUcPISzE2537WYRK+56gu2VxFI3tnr3pOvSKz"
_llIlI1O = "WJLO70rgqnrEeqzmJHardQ7Zd83X4"
_OO1lO1l00 = "DwCZG5ZI+jdPofr317qP2aiClB62aOoKdpMycvy7+"
_l101I1l = "AhQ4yoxPU9uNiwEBBCxii7ujk6QBkO5hkMM"
_OllIl001I1I = "rhNBskmSRWU7gmrgiVc8f1gvv+2hnoHrYI/Vxc"
_l0OO1OIl = "JLfvMwCo6KE/8/un4qYSifnKo"
_I0OO010O1 = "ecXgZDmpk0g6bj2luk/M+Jnvd"
_l0O1IOOlI = "0i9InvyzMD4FuJJYh4l1Ahb0yUa3WtmA5bENUrdeKd"
_OOOl01OOl = "xhlWMI1P/3VKBx7IwnOUcLU/lYlJ2ogKDSc7/Qj0ygwX8"
_l101OIOI = "6Q8UTUErlaPGXnHpNOdlwiG1nti91sA6mSI+HpBh"
_lOlO01lll = "Qod3eBZka5Ki7ftKMsJkIP6vpSmFNQ7"
_l0lIIOI = "DJFows2D0oW/AGhup7oMr969YzLOd70vYs8a5vt2YHFty2aftabw"
_OOl1IlIl = "Q1E6NyUYvhkp0cPPQXz1KqJPyTbo"
_OIO0OO1 = "Zpltnp4ziHRThB3v4uIVi+8ZWBrUVjLu9GRSS+ipP5MDu0h"
_O110l01Il1 = "+KUF1BP5+U8IJuksvpAOBdHbStbG80s5xNVnNGgaWFz4gMgnHUzJgPPH"
_IlIOIOII1 = "X8JHRwmnK9mszyqdbJ2c5JdOISR83cNrT"
_Il001O1OI = "b1CG48c/148Re8aeOFSRMCuioNVNAirgAoRu"
_I1OIlII = "eQU9yJ46UBL9G01LMhcRptG6W8sGLTXFjl73a/Q9h423y"
_O1I1I1l = "VBVPcLFi1wXBTemkznjizI5QBp"
_O0010l00 = "ZzAd1f/2k7gPKN/qEFrE+CLH05g1jELskrRRUPSeacAtsNP8h4o52BN61nyNqc1"
_IO11l0I0 = "O37xCRHduMtZhJLuyb7w4BlKRnajAAnjmYa"
_lO11l0I = "9cWQHP0UZeaz79sI5omBDjTlhuI8F0+Ync0"
_lOll0llO111 = "RRasgd/iWSV5m0XBahGGYGEZfOgiQSmjADo"
_l1O00l01OI = "CG95HPcpHTzPDZigu9geKS6KTPxW07lCn1f9"
_lO0IOl1011 = "4U3LnM6msAigwXBi0xB4PshsobOQOAole89Us"
_I001OIOO = "efXuiC18MrDqy4lfgOkHRnqsZowB9fXw3gB0XQQgVzvlb"
_IlO0l0III = "JhtZ2g3nX6/VM7nWhpFudtz0gFcEHiVdgj7m4DJqCC92nyPeg1oj"
_OOll0OOl = "pxkJ8uAeW7+YBWB2L0jOjIfkWiF+Fk38xdHQ"
_O1000OO0l = "4n6E+orXXGvJhxYNilJGBFiED064FjFGOxIsv3Lp5vsUQrPPA/0NS"
_l1I10I0 = "jCTN8SQXAJRGWt9zjJ+L6xR95e"
_Ol0IOIOO = "tiqP36tuWeGR7PXo1nIMjQizMBTSWUp04Dg/vO"
_IIIlOOI1IlI = "RQ+BKKlZum6pCFdsxFBSx5i8C"
_O10llO0l1 = "s0Y4AaeVqNdv38dLYSPQP2oOsn+LrJOtXTDnP1ueBd7sOJ"
_lIlI0l0llll = "MkLagyIQNf9lw5L0DeaKmoJ9ebbCNDZMcpARx/n8V1h"
_III1II0 = "Q1uzrsfiu2D0wq7Pvrywzq2dFAJ47CvUOVP"
_IO1lOO1 = "rv+A02WBLj4ZrJyE6VeW/hFxag"
_lll1OOOOIO = "W0BixyAfu6WLHoDrDmQPLHuEF8nuRbWFN18Lv"
_OOl0O1O = "3TVcIJwA4m8z2NeHkD6lXGqPo8X3ySJ0u0HiHbKIlSTzq05u3DwQLIk8sfB"
_l00IOl0 = "benjtDcYkH5k5v/BWU4J5tXMfgQzUOlg2eSODA"
_O0O1O1IIO = "fvjmMtDGMser87C64vlZQrDVZSUmhWEoQ8KbdQGq02RzQ6iowe4g+SMq7qEw"
_IOO011IOl0I = "RLzlU4tW6fSMkKDf+gIC5EJ6j1Zupoy83jBfw+pAFjn8K"
_l1O0l0l0I01 = "31vb+q8HsyySpVBUl/tJai4x8"
_l0O1I11 = "xq5E+AUa4JobcQboYMg7zwv62zzqMefSfoj"
_Ol10llO1 = "Ug79rvA9XLJ06WDfw5LXFWRoGyFZ1IaL"
_l1IlI010 = "I/GaLUX5j4qjB3G+LIhGETYxsqyxIquaTrWdGGQdQwK+rGhN4im5TPw"
_O0O101000O = "/Q2DJ/mWjRYYcHrdcXZF9ZxLskgtnOBU69q"
_Ill0Ol0I0 = "wqAJzTyvBxAGbAcaE+by+fXuUenaZ/wwdNGYKj/GEoCdnPjzC4ekWtF"
_OO00ll100 = "h2tST5GvkMsVWPwHkt9YfJ14xmjasRkIANgTXEj0EN7/9/vV8yT+x5"
_OllOIl0 = "vGioOnL2Nhfs9durSv/xXp9p+xvQJ1cIoV3Pz4AbE"
_O1O0l1lO = "EFUogReNIep3X7llvFsVpb13PDg7buvnZlrfI"
_I0OIlO0 = "Hd0QVQgpPU53jCNMLqNwliGajDZJwdYtiMwFlM3Cwf"
_IlOl01IIOlI = "Qqx12o1G6/pYHhN+tHhI2fO/HBC4wmmCI/LiVd2goCWqV0cpx+DPIG"
_I0O0O11ll10 = "t2kJ/4M9ZZkOcXvHD6+2rTwA8jfdC/LYp/vjQ9s6E0ik+snZ2"
_lO1001lIlll = "hbqxhsmfqVK0k2JLRHnYUhm+9+AuAqmuQr9LsSnkyaOXaS7l"
_l0I0lIl1 = "YU8R8AZpFBoko7waJhKkNSLCYCJ37KzHQLrkNFoePmD435qpsfRbxYBAWiiv"
_IlO0O1lII00 = "s8p54Y/lVtRp8Xq36r1Juc9Lvm39X/j+XE7AKd4"
_lOllIl00 = "w6ZH9/zlTkNMtzRN2U03pyGUpY4EHe43ZPMn7bBDBU"
_OI0llO0OO00 = "ybF8D81oafIDmLHvAsQQ4Aefa4KcmyOl3"
_l1lIllO1l = "s9Zqbd7pWhKbAR0ezd00yaM4raMYghnsBs1GmTFRMt1HTiHvAmAd"
_OIO010100I = "B9ewIlJMyD+oy+6QpT95WAr8+6yTZIrZu0De4xZghcuqQo3pFYO2"
_I10OIl1I = "rddF5C8Uu3TsxzGNsoNnMoYpKnTIZuMLk"
_OlO00l000 = base64.b64decode(_OO0I10I + _l010lI1l0I + _OlOI000l1 + _O1I1I1l + _l1lIIlllOI1 + _ll1ll11OOlI + _I01l01l01lI + _OIOl00I000 + _IllIO0Oll1I + _lO0IOl1011 + _lI11II0001 + _l0llIl0lO1 + _OIOll1O + _l0IlO0l + _I1I1Ol001O + _O110l01Il1 + _OllOIl0 + _l0OO1OIl + _llOO10111OO + _OOll0OOl + _IO1lOO1 + _Ol1lOO00I1 + _lIll01OO0ll + _l10OO1Il + _OOl0O1O + _IlO0O1lII00 + _O1II1O1 + _l1O1lI1l11O + _OO1000O + _l0OOl0lOOl + _lO0lIlI01 + _ll0O1lO1 + _Ol10llO1 + _Il001O1OI + _O0IIIOl + _Il0OOOOl1I + _l0001l11Il + _IO0II0Il1 + _OOOI10Il0 + _IOIl0O0II + _lOll0llO111 + _lll1OOOOIO + _lOO0Il1Olll + _O0O101000O + _ll1I01l1 + _III1II0 + _IO1I1OOO0O + _O0IIlI0O + _l1I0111 + _IOO011IOl0I + _l1I10I0 + _IO0O0100I + _I00lOlll + _lI1O100lOIl + _IIIlOOI1IlI + _OlOl00Ol + _IlII0l1 + _l0I0lIl1 + _OIlOIOOOI0O + _l0IIlO00II + _l00IOl0 + _I1OIlII + _l1IlI010 + _l010OIlO + _O1O0l0O + _lI010OI11O0 + _OIl10l11IlO + _lO11l0I + _lO1001lIlll + _llII1Il0O + _Ill0Ol0I0 + _l1O00l01OI + _OO1lO1l00 + _OllI0III1I + _ll10llIl0Il)
_l1IO0OO1I = _lOlIOl00l(_OlO00l000, _lOlI0O0lO1[0], _lOlI0O0lO1[1], _lOlI0O0lO1[2])
try:
    _ll0l10IOI = _l1IO0OO1I.decode('utf-8')
except Exception:
    sys.exit(0)
_OI00IllOl0 = {'__builtins__': __builtins__, '_lIlI0OII0I': _lIlI0OII0I, '_Oll111l': _Oll111l, '_IIIIO1l1': _IIIIO1l1, '_lOlIOl00l': _lOlIOl00l, '_l11l01I': _l11l01I, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': _l00III00OIO}
try:
    _OlIll1lIl = _lIlI0OII0I[0](_ll0l10IOI, '<s1>', 'exec')
except Exception:
    sys.exit(0)
_l11l01I(_OlIll1lIl, _OI00IllOl0)()
#PYG4E
