#!/usr/bin/env python3
# Protected by PyGuard v4 (pyguard.akean.dev)
_IO10lIl0 = bytes([178, 16, 159, 190, 111, 31, 66, 87, 218, 133, 142, 121, 186, 224, 171, 183, 75, 74, 190, 52, 217, 239, 75, 59, 40, 76, 119, 230, 6, 196, 167, 202])
_l1lO00OIll = bytes([207, 185, 58, 55, 107, 74, 232, 248, 43, 1, 39, 105, 59, 238, 126, 53, 227, 109, 100, 254, 220, 148, 166, 155, 167, 240, 121, 63, 71, 101, 64, 248])
_l0010ll1I = bytes([93, 55, 53, 162, 70, 118, 198, 69, 40, 52, 100, 236, 150, 69, 43, 134, 219, 235, 230, 148, 85, 192, 22, 156, 197, 234, 120, 250, 51, 192, 9, 186])
_IOl1OO1O1I0 = bytes([127, 148, 166, 136, 137, 44, 19, 205, 163, 21, 28, 133, 65, 18, 7, 60, 6, 178, 117, 139, 59, 4, 192, 135, 203, 213, 20, 253, 254, 223, 33, 139])
_lII01IO = bytes([9, 116, 133, 63, 90, 23, 249, 203, 70, 86, 227, 254, 8, 4, 91, 19, 143, 84, 250, 150, 72, 130, 133, 45, 18, 230, 151, 173, 109, 56, 252, 61])
#PYG4S
import sys, hashlib, base64
_ll1IlIIlO = type(lambda: 0)
_lOOI10l1l = (getattr, open, exec, compile, type, __import__)
_OlI0I0lI = _lOOI10l1l[0](sys, '_getf' + 'rame')
_I00II1l = hashlib.sha256(bytes([173, 73, 89, 44, 33, 143, 96, 140, 144, 46, 249, 149, 81, 8, 52, 130, 111, 165, 140, 192, 6, 235, 248, 60, 34, 211, 26, 32, 214, 80, 153, 83])).digest()
_O00IlII1O = hashlib.sha256(_I00II1l + bytes([120, 8, 65, 1, 145, 106, 43, 14, 137, 228, 252, 126, 9, 210, 145, 210])).digest()
_IlIOO01 = bytes([84, 175, 163, 76, 192, 62, 15, 49, 87, 48, 253, 140, 252, 102, 228, 126, 207, 144, 163, 57, 17, 188, 232, 242, 29, 248, 164, 181, 4, 204, 240, 43])
_Ol1OOIll1 = hashlib.sha256(_IlIOO01).digest()
_IO0llOllOl = hashlib.sha256(_Ol1OOIll1 + _IlIOO01).digest()
_l0l01I01 = hashlib.sha256(_O00IlII1O + _I00II1l).digest()
_OIO00101 = hashlib.sha256(_IO0llOllOl + _Ol1OOIll1).digest()
_lO0O0O0 = _OIO00101
def _lO10II011O0(_I01lOlIlIl):
    _I01lOlIlIl = bytes(a ^ b for a, b in zip(_I01lOlIlIl, _lO0O0O0))
    _lI010II1lO0 = []
    _lOOOIlOO = _I01lOlIlIl
    for _ in range(9):
        _lOOOIlOO = hashlib.sha256(_lOOOIlOO + bytes([138, 184, 170, 235])).digest()
        _lI010II1lO0.append(_lOOOIlOO)
    _lO1II0l = [(b % 6) + 1 for b in hashlib.sha256(_I01lOlIlIl + bytes([138, 254, 66, 240])).digest()[:9]]
    _IOl0010O = hashlib.sha256(_I01lOlIlIl + bytes([184, 152, 186, 135])).digest()
    _ll1101IO = list(range(256))
    _O1l1OllII1 = 0
    for _lIIIlllIO in range(256):
        _O1l1OllII1 = (_O1l1OllII1 + _ll1101IO[_lIIIlllIO] + _IOl0010O[_lIIIlllIO % 32] + 165) % 256
        _ll1101IO[_lIIIlllIO], _ll1101IO[_O1l1OllII1] = _ll1101IO[_O1l1OllII1], _ll1101IO[_lIIIlllIO]
    _OI1lII10 = [0] * 256
    for _lIIIlllIO in range(256):
        _OI1lII10[_ll1101IO[_lIIIlllIO]] = _lIIIlllIO
    return _lI010II1lO0, _lO1II0l, _OI1lII10
def _IO0OIlOO1(_OIIl11O11II, _lIO111l0, _Ol100I1, _l00OOIO):
    _II1OlOO = bytearray(len(_OIIl11O11II))
    _Il0I01OI = 9
    _I1I1IO01 = 0
    _lI0OOOOIIO = 0
    _OO0OI0II = 0
    _llII0lOI0I = 0
    _lO01IlIIO = 184
    while True:
        if _lO01IlIIO == 150:
            break
        if _lO01IlIIO == 184:
            if _I1I1IO01 >= len(_OIIl11O11II):
                _lO01IlIIO = 150
                continue
            _llII0lOI0I = _OIIl11O11II[_I1I1IO01]
            _lI0OOOOIIO = _Il0I01OI - 1
            _lO01IlIIO = 162
            continue
        if _lO01IlIIO == 162:
            if _lI0OOOOIIO < 0:
                _lO01IlIIO = 124
                continue
            _l110lO100 = _Ol100I1[_lI0OOOOIIO]
            _llII0lOI0I = ((_llII0lOI0I >> _l110lO100) | (_llII0lOI0I << (8 - _l110lO100))) & 0xFF
            _llII0lOI0I = _l00OOIO[_llII0lOI0I]
            _llII0lOI0I ^= _lIO111l0[_lI0OOOOIIO][_I1I1IO01 % 32]
            _lI0OOOOIIO -= 1
            continue
        if _lO01IlIIO == 124:
            _llII0lOI0I ^= _OO0OI0II
            _II1OlOO[_I1I1IO01] = _llII0lOI0I
            _OO0OI0II = _OIIl11O11II[_I1I1IO01]
            _I1I1IO01 += 1
            _lO01IlIIO = 184
            continue
    return bytes(_II1OlOO)
def _l1OI1OIO1ll(_lll1OIOO):
    _O0IOlOOlOO = hashlib.sha256()
    _OlO1O11O0ll = [_lll1OIOO]
    while _OlO1O11O0ll:
        _Il1l0Illl0 = _OlO1O11O0ll.pop()
        _O0IOlOOlOO.update(_Il1l0Illl0.co_code)
        for _l1000l0001 in _Il1l0Illl0.co_consts:
            if type(_l1000l0001).__name__ == 'code':
                _OlO1O11O0ll.append(_l1000l0001)
    return _O0IOlOOlOO.digest()
def _IO0O1ll(_I0O0l0l0):
    try:
        _O0l11O1 = bytes(a ^ b for a, b in zip(
            hashlib.sha256(_l01l10I + _l1OI1OIO1ll(_OlI0I0lI(1).f_code)).digest(),
            hashlib.sha256(_l01l10I + _l01l10I).digest()))
        return hashlib.sha256(_I0O0l0l0 + _O0l11O1).digest()
    except Exception:
        return hashlib.sha256(_I0O0l0l0 + bytes(32 * [255])).digest()
try:
    _l0l1O0IOI = __file__
except NameError:
    _l0l1O0IOI = sys.argv[0] if sys.argv else ''
try:
    with _lOOI10l1l[1](_l0l1O0IOI, 'rb') as _lO11O1O0:
        _OII0IOl011l = _lO11O1O0.read()
except Exception:
    sys.exit(0)
_OII0IOl011l = _OII0IOl011l.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if _OII0IOl011l[:3] == b'\xef\xbb\xbf':
    _OII0IOl011l = _OII0IOl011l[3:]
_llOI00II = _OII0IOl011l.find(bytes([35, 80, 89, 71, 52, 83]))
_lI1l0O1lOI = _OII0IOl011l.find(bytes([35, 80, 89, 71, 52, 69]))
if _llOI00II < 0 or _lI1l0O1lOI < 0:
    sys.exit(0)
_I00O10O = (_llOI00II + _lI1l0O1lOI) // 2
try:
    _IO0OIlI = _lOOI10l1l[3](_OII0IOl011l, _l0l1O0IOI, 'exec')
    _OO0OlIOl = _l1OI1OIO1ll(_OlI0I0lI(0).f_code)
    _l01l10I = _l1OI1OIO1ll(_IO0OIlI)
except Exception:
    _OO0OlIOl = bytes(32)
    _l01l10I = bytes(32 * [255])
_OOI0I10I = hashlib.sha256()
_OOI0I10I.update(_OII0IOl011l[_llOI00II:_I00O10O])
_OOI0I10I.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(_OO0OlIOl + _l01l10I).digest(),
    hashlib.sha256(_l01l10I + _l01l10I).digest())))
_OOI0I10I.update(_OII0IOl011l[_I00O10O:_lI1l0O1lOI])
_Il0Ill01 = _OOI0I10I.digest()
if _lOOI10l1l[0](sys, 'gettrace')() is not None or _lOOI10l1l[0](sys, 'getprofile')() is not None:
    _Il0Ill01 = bytes((b ^ 110) for b in _Il0Ill01)
if compile is not _lOOI10l1l[3] or exec is not _lOOI10l1l[2] or getattr is not _lOOI10l1l[0]:
    _Il0Ill01 = bytes((b ^ 115) for b in _Il0Ill01)
_O1IlIlOO = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != _O1IlIlOO or exec.__class__.__name__ != _O1IlIlOO or
        getattr.__class__.__name__ != _O1IlIlOO or __import__.__class__.__name__ != _O1IlIlOO or
        open.__class__.__name__ != _O1IlIlOO or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        _Il0Ill01 = bytes((b ^ 243) for b in _Il0Ill01)
except Exception:
    _Il0Ill01 = bytes((b ^ 243) for b in _Il0Ill01)
_II1O00I = sum(b for b in _Il0Ill01) & 0xFF
_II1II0llO1 = _II1O00I
_Il0Ill01 = bytes((b ^ _II1O00I ^ _II1II0llO1) for b in _Il0Ill01)
_lIlIOIl0O1 = hashlib.sha256(_Il0Ill01).digest()
_IO00I1I10ll = hashlib.sha256(_Il0Ill01).digest()
_Il0Ill01 = bytes((a ^ b ^ c) for a, b, c in zip(_Il0Ill01, _lIlIOIl0O1, _IO00I1I10ll))
_OIO001IOl = bytes(a ^ b for a, b in zip(_IO10lIl0, _Il0Ill01))
_l1l100II = _lO10II011O0(_IO0O1ll(_OIO001IOl))
_IIl0IOO11O = "bLJ+0CbUjvmmGo2yS7zOamhTebiZh0w6a/sjK"
_O1O1OI000 = "eUB2+iXNTx7dW4YfE38xN/nPZmO0143mpCK4oyOOWKwGDtDAB"
_OIlIIl0llII = "vulgcE7QelagB/+vBA9tVBBJm9y+3VxPEuZNn"
_lO101I0O00 = "ETUAMHfzcOEcsri0yUBd039UW1QcEQxT45lE7j9GY1FdZHVuK2QCA2hI5DupQW"
_Il000IO0 = "TqSyOCTIQ/3lh8foU2ehycfAlutSBunU5cisP"
_I00OOI1Il0l = "YMDQORHxG/1skaYUOvgt9UawQk/jx2g2Boy761lJxEMj"
_Ol1Ol10l1 = "CgetTsLcAsCNz2HEzEUg7lI2ZA0T6Gc"
_l110O11 = "JP0zJdqCXKMMo+A51n3DCFSmmGt0evWj5zn0HZ"
_II0111OI = "1PaPWKBgVxIVQA0QSeFrrilZ4Aj1eGal+Txfx"
_l0OlOI0I10 = "cpBACdsoiPiyrstWEMNv+sO6"
_OO10l1O = "Ac6DqhmMz4mxtt1x7duMGfbCr/FeZ"
_l0001OII = "8cAxeqqUFWxbgqKyFgvKhhGKNX/3l"
_I1O11O0I = "oOir504DvAOVT+a2DCDez3DMI1IKQQqbmS8P"
_IllII1l100 = "+VCtSddqQlUJraeaFATzgRkaqC"
_ll1OOIl = "OIDyOv/Pqr0crlrKo4C8g/mk2BQxZoTeHPk"
_OI10O0O0 = "YRC2u7QIo0prQtmdR7rrg+9aR+NM9Xk7d3Zf"
_OlII1lOlO1l = "grbTEZbVAyEYl2LLAj6gxOlDO05W+Qb4hbccmv0t2T2WpHNcLPT"
_l111IIl = "KhF1/BT2ILpB3Kj9jrgbXUpS924rziabXPmdK8fLKu9eHtaZJ2VvwpJJk5"
_O00I1O0 = "phToTyC4OIx7gAp2Sh9i22/vAZGGlbeT43VPLDfWm7GOvza0"
_I0I01O11Ol = "6Umh9bIIx6+TjGlWH0ni6XCwTW3uzbl/SbPQVvuLZZd4Uq802wM0"
_IlO1l1O = "joa1amfDF41sYSz06YQaGkxNpsOLhN17qNaQLh6nqkBLlXSu4ByyoaQRcPYv"
_Olll00OlO = "DjzN4f7KdxzCHMF6ICYnLGsFI2"
_l1IIIl10IIO = "7y8LnXMdxPvJTUNK0WU+bMZFbP"
_I11Ol0OOI = "gz6xKOVWv/PKNPwlZCG8gjlXzfjhqf2c9BCh8JUGZw/i7mBipeM"
_lI1OIOO1I1 = "t6Ot0/O8FcgpigLNe1Bl8NBw2dnLfMgB2NwtWa8TdwwfEVqT09cG3q/UYchMp"
_OOl1O1Ol = "XUpD5C8J769FPwyUD623OB3F0C7uc2PcJM/D/iYcR+9mqJl1"
_llIIO00IlO = "Q7QGvmouLhtMPLzTKEr5FUAvHhOG/z"
_O01011OOO = "j6g/NVQ1R78JIuMnxFQyzlsnK4kdo/7sR1"
_O0IO0I11I = "ubwcLzlPAtj+sjB5Tz0806r8K+hjgFE2FazGZCIC0OgDEZINst"
_O0l0OOIIl1 = "xz4e1HHZilLv6/wphCLK1v7XgM3bjzzHCUD"
_lOOIO010 = "ZdNFFZ3mLLkCkgP7G5R/XZvUKFTfY"
_llOOlll = "L80dAagUlDKIrdiFLfr4WXcrLG8ajkLewCEUCB/LmT/0SD9Y"
_lOOO01IOI1I = "Dc92n/5JDcM0ERDTJXdSuOiUx25S6omDDlQeC7xWw7sFK9"
_IlIlOl1l = "gIazNKSErXqvomlsglj8W7iLNvECyl5j1Ps2wvM0Nj7gyY1V"
_l101O0ll0l0 = "32Mq7T3ob2uy6t397h/8Uit5PxlnQP+ZYsAXhOFH4BuKTywuZR"
_O0O0I11l0 = "78vxxRLu3x9zCUuOCttIirw0oX8Sc+"
_Ol1O1IOlOlO = "7/cjRZQLOufi2Iw8jkbRVJIm"
_I00O1lIlO1O = "c7wBA02lAZ2vU/QIRbiLTjvoeiFwirzzekZPIzCFT2iallyMuXNsE/ON74P"
_O0II1001O = "fxI7hwEUYA3PmIywG0yQV971T5Xyo3JaXJwi8"
_IOlI0OI = "GB9jb9K1MwP1m8q1z2G0rT+JjgVZWH0TJsPeQemxCYbjaUtQydj/"
_IO11IO01O0I = "6PTMELDM4DcBbeKM0tkvXL3QqM8D8VSb8ZkYQq0YCF+xBZipMgae2FCtjoE"
_OI1lIO1I0lO = "4sU20YMNHOdywljGDEOTv1VsR+t05I6EuFHrTzHdGXiK7PXsUnj3RbHX5K2"
_llIl0O0O0 = "eLz3POI1Z7p2C+mS5tZ3xZI0y9vf8jeGsGMz5pwu"
_IIOOl1llII0 = "xLCt7lhKwqUD4Yu3G4YmLYASAHkcRqW5E5MLFIALDipC"
_OlO0Ol1IO = "QyNOj536M01AwIIhA9VB98ms9fbvkR0Ch1dwUUB8"
_Il010l10l = "GndKYZdlvH1PzeSntUOGBR6PEwACtnItpftBny"
_IIIOIIlI = "gqdElNgYZCy0pqhJeoiB62XKvKHDVj685Q5t1wcEnBbRgZ+/oBdvWVS6TK"
_I1llOIO1I = "bgqjqhmmbWMZ5uVANCr7QFpCm/gzrvCzGZzqeZWmMB89V"
_l10IIl000 = "mPGhW31neVXudtbRzYm4ZyHLSBgKgitGWww7Mhe2Zbgh"
_OlI1O0l = "KxPSkCQXJG7UWku4f7fp+m3dM21KoHx5a1nq/fvDgoOLCF8k7XGhtHlyo4KQT2i"
_l1II001IO1 = "30qLQqK/N53YuMay0n1/EWNXw5rY"
_O100I10lOll = "nxDCvwlkSfgz3ElpBQ7NaQbr67SkcPlH"
_lIIllllII = "gFEiWHFeTA9HSHZMqLFliPvRSM7GeppUQnbHsRy"
_IOOO1lO0II = "gQwqNGYyu1/MDuNt6DwOWor7X1JkJy4Lv0ec6x+9fe0VXEcRExESJhSs"
_IOOO1000lO = "0vdnnhBQl9OspHHynedbl6zLWbnzqKtmxgswVNs"
_l1OOOO0 = "DfT8Neg4S+TPYn0TYYKQDzpP5oNEZbGQsuJ23jz"
_l1IlO0101I = "zBYqhypeTPPlkjIFhKL9MlgHNUaF5i6DXxxG"
_IlI0O10O = "Yp3EtDQj7Dg41QH0lVzzsbo4QNI58k"
_lI0010O = "W20numkujpCQq83UffG5/hKz2+HlA0y"
_Ol1lIl0l = "gTtWc7aH6I/r6Dtnn6RN8sCGs8ET"
_OI0001l = "upwl69S6v0dT8zRVmQk7/Lc3Rbnq+YXFoWpUR3+czexp/AG"
_OOl1O1IOI0 = "i8aLOGCKYRmWAL/u9TQpxpK+bnzY/qb0rZ0im4k"
_I00I0l1O = "HILSbL9ESJ0xEv8Br35h2pFa3bShiPvsXg2yyxWIVVOwJw/27Ex"
_llIl1lOl = "O1g+9cOnE2k6Ve71xOnJf9tU+YZjXNIlfJJ"
_I0IllO1I = "FmnpM8HnEf4Ulu4aUiU3CpI+X8A"
_IOO1lIlO0l0 = "YVXmaBnvZphoCGIrp6yeK2x72ZGmRA73sC7TW1C2lhBWpJ"
_OO0OlOlOIO0 = "mxun7jw0ipPLOWaQPpVH8bZd"
_O0000OIO = "sDmYEHLf8BZzmN4GY2sRJ0yty6MpwgomQalhYVyCXeXchxFNi"
_lOIOO0IO = "vrFxl9/VJEGyI8l1BsmAgcB2yRVmkLQjpQ9FzUPHERMqxe5qFb"
_llII1111110 = "uqk3dqvOBj5ney8DLuasgMufiSFF+N3nbhhBTD"
_OO0IO11I = "U1yH3d+jJlgGBC6vhWbGSFT3Fxz"
_lI111l1lO1 = "PFc7ftgq1hcqqSCkUOdxJvw7j7FTJsOj"
_OlOl100lO0 = "eg9tWqnq6ABgV+0DrNBZh0xkadmQcpiYsgiidBjSsBv"
_O00l1O0 = "6asPy42T+E97842Y8YiHypEHDuyH/MGjlVlWa7uAFqCbgBXI1vDoBTD"
_Ol11OI0I1I = "RZ4Cqrc3Jq2kYl71991Zdy8k7grZNw2LGfMPyBLCBrQ"
_OOOOlOIlI01 = "Dsz1YXLFWBj+Uwh2IkNh2irM1wRCiVxbWug"
_lIl0l11Ol1I = "W0RhqqFkaPiLzut2wh7p5WxnRzPu1f5FOwVwBfW"
_l00100I = "kRnvPCn94ityjXo8N/+wM/WgZk87rwkHmllHdf8ED"
_I1llO11O0l1 = "CBwZLpJQ9F89h4lZWnbohm+0g1pHCCj6nmBxzGwMJ2I1oRzvPF/wyikd"
_OlOlO00Ol0 = "tzks0weUFEJESBz5fg0p8NuDR+pb1LI7ijB7Xrw5Hqzfk5chJ7hYKNOMOeQqoL"
_IO1ll0O = "RAjNFMPBpapgSKG46jx9UQZo0PacdmVzPCoigxplOoCUsNjm7b3vhA6Fk67wqI2"
_Il1I010I = "5xRMt41z7HDvag7SUhfQC9X7mRuSWqlRkQv2sr1PNuDg8tVqPsxafyQMOVenAl"
_l0OOIII1101 = "uPpwPPglqxwHajIqjTAtnanFv+3xMx"
_Ol11OlIOI1 = "c8PEpSQRIU9oHfXtR5kqDC1xZGj"
_II0OIlO1 = "R8XDdybn6blNksYiMVdiVwa6fQEYzPiOCISgygT+zhic"
_OOO1l0l = "WanUbMYEE6ca3LBWGbBh2RCf"
_l11IlOI11I0 = "JEODW1Zp7+kh1LYQqMKHmyWflindWWr"
_IlOIIOll0O = "96vU7bAOrj3S0AvUuyI7I5CZslXIzhc8/i4"
_IOl0O1llI10 = "vD+LKoqg2SHVuPp1Kpwr4yPjFZHHiruu3zchvDkYElAEWvtuX89mqyYbp"
_I11IO110IO = "v5WL4I83wFGMr8KepsoYCf3rnjU6ICTvqdQVh/Fyu6rTzO4/NQGqi4dVQnV"
_O01OlOO1O10 = "JnyR627HUG3YQXTcqwzawdUEXiadmwOCBsUFrg7V2BYhGvAYCI+i8+"
_Ol00lOl = "A+ecln9e3zUMsEBXnIt/XMhtkSGn"
_OlI01l0lI0 = "8HV1MoXOha9qbPnusEjrdlCnSuNx5gxo+vPU7PO9ohA"
_O0O010O = "bLNueujY0LuxkwGxX3gqnVec8/0EaLfm9Iie3E2rtmZbKVK8jhTWd5"
_ll0l1O1ll = "uB2C81XJGUucFCNsxZWc37+3QIXklBlyGj"
_Ol1lIlOOOI1 = "Sg8cRC2xeoeCtx4NNoAayAk1GF+7sDtAyx5337kMVOo5EYzdwwq1"
_O1I11O11I = "9accZfbFbcdhRO0hBZOsxO8vJZ41RmF7Xhd"
_llI101lI = "0m6OkhbOwpeWu9QjVBvG14lOT7ZX/zK2N9b89G4N"
_O10000lIII = "JbVEFzM/AAcaatm+9ZGmQPZIisCTghJE5h/49acED1h"
_l1I0OIOO0OO = "HmSqWRbUYW7LiDa1a/7CS8X7FFlf9Xi2NNghXqwpZsnEN2b5wox5qbfRn2DKaU"
_IIO1l10I = "7H+twwJB3hDruwAhffcmkFH8bV7QMtTRH7yYxaY9pe2HfEroY0frt"
_llOOl10II = "AXzTz7oxlze8D6qvG1AixzuH62bJ9e"
_Il1Il0I = "Ossv8IeNnBHvIB5ALbe+h22yDhr4uqcHe+Sm"
_llO1IIOO1 = "1uECmWm092awA3b96huxX4Y2Xph9Lq"
_OO000IIOO = "VX9glV+uC++BVriajdwIqGu3YXNnHfbiFjzpxtf4OnBdctS1VrNVyIc0F8/KJP"
_l01IO1lO00l = "vYpZ2VWEMUsB5a5PQ9OPq/Z5iTZkht+NyB2NCIhaBGfVu1U"
_I110I0I = "Sphlxq51bhEj4upId/tVeB3cnvBHWFlKe/ycxpddBX30NCwmJYnqnqtB8CAz9"
_OI0IIOO1l = "nX369Zsgi42WeTdKXIKlCxKm+VawMxmVbaDwxTyNho5wuSKGbPmd5"
_l1lOll010II = "Z7tIuxBIBnv+M/MTtf4x5Ui/nTqDWhmqt5zqKoYDc/G3p5erYvHd60y4"
_IOIlIII1 = "Gf6wBuRPX8X3Cl/dzRe/RXzGPq3Mto"
_O1IllIIll11 = "+gNwJdnHa46PA9lvN1k98D2i1J9zPh/2tAzwHHCDEHCA7+l"
_lOlOIIO = "E+EjjQ6qNWKKzIcEQdCv2kVpfzubQPjU"
_OI0OOIl = "/SM1BIJBNrov0jRw4pnrRDpK2CBl6yEcIEt8nR"
_O000I010 = "nL7Snf17/yS98tgOFGrr4c10Qb"
_IOOl10l0l0I = "Q08Dsht2sqhlZUYKooxVEk2iB2lIsB"
_IlI101l = "erEOuVQmKLhDX0UT6yDrYoqRbtxgmA"
_II1l10O = "jTUe2yhVKPG79ypLyrBHOxGyV91962lrUt5323WsBlpnKCLwly1+t"
_OO0IOlO0O1l = base64.b64decode(_IlI0O10O + _lIIllllII + _IOO1lIlO0l0 + _I0IllO1I + _O0O010O + _IIl0IOO11O + _Ol1lIl0l + _IIOOl1llII0 + _OlOl100lO0 + _OOOOlOIlI01 + _lI1OIOO1I1 + _l0OOIII1101 + _l0OlOI0I10 + _IlO1l1O + _IOOO1000lO + _l110O11 + _O00I1O0 + _O1I11O11I + _l101O0ll0l0 + _O00l1O0 + _OI1lIO1I0lO + _OI0IIOO1l + _l1lOll010II + _OIlIIl0llII + _Ol1lIlOOOI1 + _IllII1l100 + _O1O1OI000 + _OlII1lOlO1l + _llIIO00IlO + _OO0IO11I + _I11IO110IO + _OlI01l0lI0 + _Ol1O1IOlOlO + _IlIlOl1l + _O01OlOO1O10 + _OO000IIOO + _Olll00OlO + _OI10O0O0 + _I1llO11O0l1 + _lOOO01IOI1I + _lOIOO0IO + _O100I10lOll + _llIl1lOl + _llOOlll + _O000I010 + _l1IIIl10IIO + _I110I0I + _OOO1l0l + _l0001OII + _I00OOI1Il0l + _lI111l1lO1 + _I0I01O11Ol + _OOl1O1Ol + _l00100I + _IOOO1lO0II + _OOl1O1IOI0)
_lOI11lI1Oll = _IO0OIlOO1(_OO0IOlO0O1l, _l1l100II[0], _l1l100II[1], _l1l100II[2])
try:
    _IO0IOOOOO01 = _lOI11lI1Oll.decode('utf-8')
except Exception:
    sys.exit(0)
_I01OlIlI = {'__builtins__': __builtins__, '_lOOI10l1l': _lOOI10l1l, '_OIO001IOl': _OIO001IOl, '_lO10II011O0': _lO10II011O0, '_IO0OIlOO1': _IO0OIlOO1, '_ll1IlIIlO': _ll1IlIIlO, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': _l0l1O0IOI}
try:
    _O01II1lII0 = _lOOI10l1l[3](_IO0IOOOOO01, '<s1>', 'exec')
except Exception:
    sys.exit(0)
_ll1IlIIlO(_O01II1lII0, _I01OlIlI)()
#PYG4E
