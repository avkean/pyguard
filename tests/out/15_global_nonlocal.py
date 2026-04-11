#!/usr/bin/env python3
# Protected by PyGuard v4 (pyguard.akean.dev)
_O00l1OI0 = bytes([202, 86, 141, 233, 237, 58, 242, 97, 36, 255, 84, 65, 168, 202, 247, 130, 245, 37, 148, 226, 90, 37, 72, 23, 165, 74, 238, 93, 78, 83, 120, 135])
_IIO0OI1O1 = bytes([13, 151, 201, 139, 116, 233, 85, 178, 33, 144, 222, 83, 39, 234, 21, 229, 254, 29, 184, 249, 64, 16, 50, 230, 82, 150, 66, 50, 241, 21, 122, 86])
_IO0IOl0 = bytes([154, 113, 230, 147, 81, 89, 203, 8, 57, 83, 113, 120, 154, 63, 95, 53, 214, 214, 2, 111, 209, 47, 243, 78, 233, 167, 68, 115, 19, 94, 17, 77])
_IOl00lO00 = bytes([55, 46, 37, 251, 199, 188, 84, 137, 182, 4, 147, 22, 73, 203, 21, 100, 33, 164, 115, 127, 116, 215, 183, 90, 137, 150, 48, 140, 87, 127, 67, 133])
_I0l011IlO = bytes([87, 122, 5, 166, 228, 98, 71, 3, 209, 36, 122, 85, 133, 183, 231, 72, 249, 221, 62, 165, 231, 34, 183, 75, 127, 54, 62, 151, 90, 98, 165, 188])
#PYG4S
import sys, hashlib, base64
_IOO1llO = type(lambda: 0)
_O0l1lOl00 = (open, getattr, compile, exec, __import__, type)
_OIll0I1 = _O0l1lOl00[1](sys, '_getf' + 'rame')
_O00II100 = bytes([14, 99, 230, 176, 96, 155, 41, 224, 125, 181, 191, 123, 201, 98, 231, 23, 51, 23, 183, 164, 13, 69, 210, 221, 230, 237, 185, 92, 229, 89, 247, 161])
_OOO11IlIl = hashlib.sha256(bytes([33, 38, 106, 93, 40, 57, 58, 248, 230, 74, 139, 200, 17, 2, 229, 28, 79, 50, 214, 211, 194, 78, 162, 120, 218, 224, 236, 173, 186, 35, 90, 209])).digest()
_l0l1I110l = hashlib.sha256(_OOO11IlIl + bytes([230, 230, 15, 252, 193, 171, 78, 173, 44, 138, 242, 157, 112, 4, 109, 89])).digest()
_II000lI = hashlib.sha256(_l0l1I110l + _OOO11IlIl).digest()
_OlO0O0l = hashlib.sha256(_O00II100).digest()
_IOlI1llO1O = hashlib.sha256(_OlO0O0l + _O00II100).digest()
_IO0O100Ol = hashlib.sha256(_IOlI1llO1O + _OlO0O0l).digest()
_OOIllIIO = _IO0O100Ol
def _OOOI00O0I(_IO11O0II1OI):
    _IO11O0II1OI = bytes(a ^ b for a, b in zip(_IO11O0II1OI, _OOIllIIO))
    _IO11O1O00O = []
    _OOllIOl = _IO11O0II1OI
    for _ in range(8):
        _OOllIOl = hashlib.sha256(_OOllIOl + bytes([185, 127, 166, 224])).digest()
        _IO11O1O00O.append(_OOllIOl)
    _O1O00IOl = [(b % 7) + 1 for b in hashlib.sha256(_IO11O0II1OI + bytes([20, 137, 117, 228])).digest()[:8]]
    _l01ll1IlI = hashlib.sha256(_IO11O0II1OI + bytes([19, 192, 47, 196])).digest()
    _Il10llO0 = list(range(256))
    _OI1l1I001 = 0
    for _l01I11l in range(256):
        _OI1l1I001 = (_OI1l1I001 + _Il10llO0[_l01I11l] + _l01ll1IlI[_l01I11l % 32] + 196) % 256
        _Il10llO0[_l01I11l], _Il10llO0[_OI1l1I001] = _Il10llO0[_OI1l1I001], _Il10llO0[_l01I11l]
    _l0lIOOO1O1l = [0] * 256
    for _l01I11l in range(256):
        _l0lIOOO1O1l[_Il10llO0[_l01I11l]] = _l01I11l
    return _IO11O1O00O, _O1O00IOl, _l0lIOOO1O1l
def _l0O01III(_I0OOlO0I, _O1OlOO000, _lI1lIIIl0I, _O0l10I1I):
    _lI0Ol00IO = bytearray(len(_I0OOlO0I))
    _OO1Ol1Ol1 = 8
    _Oll1II1I = 0
    _IOO11001IO = 0
    _lIIIOOOOI = 0
    _lI110IIIlO = 0
    _lII10l01OO = 243
    while True:
        if _lII10l01OO == 100:
            break
        if _lII10l01OO == 243:
            if _Oll1II1I >= len(_I0OOlO0I):
                _lII10l01OO = 100
                continue
            _lI110IIIlO = _I0OOlO0I[_Oll1II1I]
            _IOO11001IO = _OO1Ol1Ol1 - 1
            _lII10l01OO = 65
            continue
        if _lII10l01OO == 65:
            if _IOO11001IO < 0:
                _lII10l01OO = 58
                continue
            _I0l0O010OI = _lI1lIIIl0I[_IOO11001IO]
            _lI110IIIlO = ((_lI110IIIlO >> _I0l0O010OI) | (_lI110IIIlO << (8 - _I0l0O010OI))) & 0xFF
            _lI110IIIlO = _O0l10I1I[_lI110IIIlO]
            _lI110IIIlO ^= _O1OlOO000[_IOO11001IO][_Oll1II1I % 32]
            _IOO11001IO -= 1
            continue
        if _lII10l01OO == 58:
            _lI110IIIlO ^= _lIIIOOOOI
            _lI0Ol00IO[_Oll1II1I] = _lI110IIIlO
            _lIIIOOOOI = _I0OOlO0I[_Oll1II1I]
            _Oll1II1I += 1
            _lII10l01OO = 243
            continue
    return bytes(_lI0Ol00IO)
def _II1l1lIl00(_IIII101O):
    _OOO0Ol1 = hashlib.sha256()
    _lIll0lll = [_IIII101O]
    while _lIll0lll:
        _I1OO1Il = _lIll0lll.pop()
        _OOO0Ol1.update(_I1OO1Il.co_code)
        for _OI11ll0 in _I1OO1Il.co_consts:
            if type(_OI11ll0).__name__ == 'code':
                _lIll0lll.append(_OI11ll0)
    return _OOO0Ol1.digest()
def _ll111lO0O(_Ol10lOI0l1O):
    try:
        _Ol100l1I0I = bytes(a ^ b for a, b in zip(
            hashlib.sha256(_l0OI10lIlI + _II1l1lIl00(_OIll0I1(1).f_code)).digest(),
            hashlib.sha256(_l0OI10lIlI + _l0OI10lIlI).digest()))
        return hashlib.sha256(_Ol10lOI0l1O + _Ol100l1I0I).digest()
    except Exception:
        return hashlib.sha256(_Ol10lOI0l1O + bytes(32 * [255])).digest()
try:
    _OlO0II0O11O = __file__
except NameError:
    _OlO0II0O11O = sys.argv[0] if sys.argv else ''
try:
    with _O0l1lOl00[0](_OlO0II0O11O, 'rb') as _O1Ol01I0:
        _O0OIl1OOIOI = _O1Ol01I0.read()
except Exception:
    sys.exit(0)
_O0OIl1OOIOI = _O0OIl1OOIOI.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if _O0OIl1OOIOI[:3] == b'\xef\xbb\xbf':
    _O0OIl1OOIOI = _O0OIl1OOIOI[3:]
_l00I01l111 = _O0OIl1OOIOI.find(bytes([35, 80, 89, 71, 52, 83]))
_O1O011001l = _O0OIl1OOIOI.find(bytes([35, 80, 89, 71, 52, 69]))
if _l00I01l111 < 0 or _O1O011001l < 0:
    sys.exit(0)
_lO1IllOO1 = (_l00I01l111 + _O1O011001l) // 2
try:
    _OII10IOlII = _O0l1lOl00[2](_O0OIl1OOIOI, _OlO0II0O11O, 'exec')
    _O0l0111O = _II1l1lIl00(_OIll0I1(0).f_code)
    _l0OI10lIlI = _II1l1lIl00(_OII10IOlII)
except Exception:
    _O0l0111O = bytes(32)
    _l0OI10lIlI = bytes(32 * [255])
_OO1lll01ll = hashlib.sha256()
_OO1lll01ll.update(_O0OIl1OOIOI[_l00I01l111:_lO1IllOO1])
_OO1lll01ll.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(_O0l0111O + _l0OI10lIlI).digest(),
    hashlib.sha256(_l0OI10lIlI + _l0OI10lIlI).digest())))
_OO1lll01ll.update(_O0OIl1OOIOI[_lO1IllOO1:_O1O011001l])
_OOI1I1II0 = _OO1lll01ll.digest()
if _O0l1lOl00[1](sys, 'gettrace')() is not None or _O0l1lOl00[1](sys, 'getprofile')() is not None:
    _OOI1I1II0 = bytes((b ^ 19) for b in _OOI1I1II0)
if compile is not _O0l1lOl00[2] or exec is not _O0l1lOl00[3] or getattr is not _O0l1lOl00[1]:
    _OOI1I1II0 = bytes((b ^ 205) for b in _OOI1I1II0)
_I11OOll0 = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != _I11OOll0 or exec.__class__.__name__ != _I11OOll0 or
        getattr.__class__.__name__ != _I11OOll0 or __import__.__class__.__name__ != _I11OOll0 or
        open.__class__.__name__ != _I11OOll0 or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        _OOI1I1II0 = bytes((b ^ 128) for b in _OOI1I1II0)
except Exception:
    _OOI1I1II0 = bytes((b ^ 128) for b in _OOI1I1II0)
_Ill0O0IOll1 = sum(b for b in _OOI1I1II0) & 0xFF
_I101I1I = _Ill0O0IOll1
_OOI1I1II0 = bytes((b ^ _Ill0O0IOll1 ^ _I101I1I) for b in _OOI1I1II0)
_I01O0OO10 = hashlib.sha256(_OOI1I1II0).digest()
_l1O0O1l11OI = hashlib.sha256(_OOI1I1II0).digest()
_OOI1I1II0 = bytes((a ^ b ^ c) for a, b, c in zip(_OOI1I1II0, _I01O0OO10, _l1O0O1l11OI))
_II0OlOO11 = bytes(a ^ b for a, b in zip(_IOl00lO00, _OOI1I1II0))
_I0OllOOOl0 = _OOOI00O0I(_ll111lO0O(_II0OlOO11))
_ll01O01l = "LzhaQPM/ZteRdmS1pSR7KC9D+2/lP7Vwr2GzLoAPbBrMbVzSFuRX5Xe1j4t"
_lI0I0l0lO0O = "jecqhBDB2ud2f2J7QzDWnbWp5iQRqTPVB7bum/znDXPz1cGL3R/Y1BNZdO"
_III1lI1Ol1l = "01tGJi7XGL3IbAVbFEDqr2pXuMOheYYPi2DGfIddWUuVOJFhOg"
_O1Ill1IO10 = "IDmTX/GSewTBqndvQmqVADm/T"
_llO0I0IOl = "xWpkEfdG7iTHvl6ZvngzirWaBzFk09tGAmSVmMrrAJGo2SEpPup"
_l01O00I = "2BfrIB8O16ZBGhe2/a7Txwl8tZZs"
_IOIl00IO1I = "qe8d1KngF+4A4jw2xP7F9l3kOgRnYQS"
_Ol110Ol = "lq9c0CjjD1WBvTLg4vL6NHwHz8pM8cwtuNUYcBrbiRQ9LaUEevpdB6YOszhk"
_O1ll0II = "Bg2rBod5QpZFqLXRiLGwHd0sQQ2CNohHeNY0qXsiay5W3"
_OOlIO0lII = "wg1F2N9mpnu3B2Sl8ylBCPs7eF+R3rOpohKPLoPicGYieZ0vnm0QOpIYM"
_Il1II1lO011 = "V1Q0+2FVIrXyTkxTmCyiusQ2fnlQx"
_IIl01IO10 = "SaKZ4+oUbkYaq1sV18A7yJEdNOnnwSnSM6YWExeeO3lpSLoamM9"
_I10Il010l = "bs68XoSedzm/nIIgKTEZkrzX502"
_OlIl0I1 = "Ni3mP68ebsTeey3aFVibfJCVbvLNsGsoCEhzfngZntlD71Vm"
_llIl00lO0 = "zw6qfrI3RlAtXXgpki8+hhwKUDuO/KTrxV04WPu"
_OlI1l1llOO = "bPNPYzB3Yu8NPpQAGJjtpZLhhQz6svpcHp93pUAEzr"
_I0O0110 = "M3cK1kYste/M/8ugPsTib0BhliDLinY7D2wm8B7"
_ll0IIlIll0 = "reh/c0Xh3ja8c3zt/ic6uJqE3tfrGyEPNmHPpYemk4"
_l00lIOl = "iRwdlExhHfEfdQlCkqC9yPpxbFi9Ljh6Gta"
_O1l1lI0lO = "umCN6DZGsRNpLDv4FSCXXkJJWRB"
_Ol1II01IIl1 = "Zg7aOZWk5LR2utbIV1mD1y/jqCp5KzgAvuoL1wt4i+x"
_OIl0lll11I1 = "gERe8OqcK8fVSN3Qe8HRwKI5eVBqC3wV"
_ll0O0lll = "CaOyA08l3/WuRfOwTzW7K7TyXZqTS+80PxgiPhSYVbQGJKm6YJqy5Pes3"
_I1l111lOlO = "mW2qyhTOgkoOWMqn8lY+31c2naNmzWsvFwyU92PyN5wiWAJchcNnxVm2MT8J1+"
_lO1O1O00 = "8KwAzA+iiJRmhLmOIgMVgmOKjpDNK4C8Ry/TUwZpN7fIIWv3SBfE3ona"
_I0lIIO0 = "V45dtoreR1+dVklDmwDzUBrCMc1BWhB9L2sMfJsqoAyA7l83S0zoRKQqZAj"
_llIll10OI = "dFg2Eq6qaGcHzh04zwNZgkouc"
_IO1100IO0 = "shIB0IfHe19bW9aqQdPOW5C3qiLIAVZtPEt9uk"
_lllI1ll = "ewvQuJ2GXagVOPqozJuJ66AMtuFk"
_llllOIllI10 = "KxK8vaKp+sW6HISwoACL5EZk5lFR48HyDlM3s+0lqMHPWDTuTHS6Da0TLVAl"
_lO0I1lO1lI = "zkyOz/Mc4kyYERh9uz0aU3kKvSknRlDp6"
_I0I1OO01 = "+wt9DUQ/SINVrgS+ehjG3DRi8YGGys"
_I1OlO00ll0 = "REdfgyKkyrK3e5vg+h21EqCCtISZABSzI0ghmKUkcnol1CKm/xja"
_I0llIOI0 = "o8zQv9e0V8OBI96xwvyncgXs0AKM4Vt6MnWcECVC/KkXC+shuj0hKh5pTFgkomV"
_O0lIO1O = "iZVBKa2bmnGZFyPPMdL0m6T7RmUDD"
_IOI0IO0OIOI = "QJ/082pGZC0NtbqqtPeOoQrMIejxSl4xv3XF2EbIcGOr6aee"
_O1ll1O01I = "kvqMPFE88FpOayG49qM+pJM2nVTrMilWS/t9HH4ZOQ5m8otSUctDyehaFl"
_O1OIIIO10 = "ZILCa+52+qIaxphWloAmNRO2ZlFWg+iU"
_I01lO1l00ll = "9Pm/utqNH+lxzEUsNZbRhF7TD/F/k6WU65N4r3YWFslmcNd1"
_I11OOOI0 = "5fGFsn4nRMKuWfs4ql9vrOjUX2"
_I0l0IIO0I = "MQQyKBa5+w+OGKYD+f3KYBkLxg4owObMmEY194"
_I101IIOOIIO = "plFvxz43lv453arWM0XcrZDzubJyGs1"
_ll0IlO00l = "cV4a1OuLPY6Oy3jRfh7bZVL0t"
_IOlI0OIIO = "dcW12Y1ohLpwYQvFyTratsgV8GT"
_I0lOOlOl = "pUfATD+hx6dlIpZvZVQw5ZNrFlDj7WpmKkCaaPIPAlpWkGPfUoxyzCaLuXr"
_OI00IOl1OIl = "xL9PhctqhdhNno3dUxAjEDnVusK32MdO9dVOlrysDR+l+6dXikyaff3ZbUE1t"
_O11l00IO0I1 = "jk1++RmgiorXLRuVobF3q32mosjB7Rjh5ArPiYImf/"
_I1II1I11l00 = "x2YR0MGVRqW5JqDELjDRVXK5Zt3v6CAFSQUrppBJAfouPDLqhqIgNIF28uwPKz"
_I1O0101 = "FwwGi20gICO0YNwF5hJNDUDzCuMvzjcBCbokXYoHTUtOmbMYW8uYOEuZU3xNDXe"
_Il1II0lI = "3bJW4l8cZLd2wdifmAEHs/8QRe+5evX"
_I0I0l011 = "E/7zdeDaVlTHRdhRWgmI+3gk2UutSsqY2OQr+8QGHqPpbgTe6j6tX+nuTo3e"
_lII1II1I0 = "TRw+yyzGRxX/df8jWgHimxAY6XQ"
_Il101l11 = "hfu2xEPITdxXaUKHVliIwJoMfd5R7ps7dd/iV9VutIJUFV1pu"
_lIl111I1IOI = "Eymu95EQeF4KR0hqrN3mTm6gN"
_O101O0lO11 = "o0GDyYRwGNXaPRZ25s0QBCc4+vTz5ZisW6/rKFWI3kFLAytpXOsyL4Az8I1RL"
_llOIlIll1 = "OcRIRDkjAh7x5b7tx3nvcs3WL+RtrkoPLFkbYoFSff7D"
_I1IIlOO1IO0 = "8/lrNh1Pp3CHkUdFp4RdTnyT1f/g"
_I1l01OO1 = "Fnim4ArddJBeWMfb1TfsH49A/nFP18k4NaXy71sRzU5lp8yHiySqlh"
_lOO1ll10 = "bHuJ8OhWe7LhaaIrHu73f2wQ1otf0+TDM+r5"
_ll01lIOl = "nch1R8Y9U9AT57jEL6yptUD+XCmtLoSRVkYOD5O3J/yim10I0QgDurtM"
_I1O0O00100 = "QCR2Znvn71p30dzajLtA2x1LNZ78"
_l0Ill1l0OO1 = "lWHl3mIxVcmy1JFgFOn63VBr4rKIlH+uLI5"
_I0lOIl0O = "FADSYDQ6MViAxWSZFpwdfYfjnBfg0Zm3Xjw"
_OI0l0OII = "RswwDVd2LtNkwgwgO8CAyXoqbfaNRjxplIAMlMlhSwq8JydmOHZfPh2"
_Ill00I10 = "ZSeVqEt7hs0EW52S64FSwm9OHm9ORBvb1u9Zs7"
_lO0lOIOl0 = "4PjsL1jyurTSIUkPqVfi4rkIl3aATy6WDMkdWPA"
_OI1I1lOO00 = "OabKIVbd2HaPDaLoAxn2MKkOIvBRBw7cafIG2E7p+8"
_O0llll01llO = "Mw6k07cOXJOSUlW/oKHY8WToYkXdiezL3baUbH/uv1pXQ68gxr50YnuoYIw"
_II110l0Il1l = "7j48lxT2oscfTznNAAjbnxgdkpLG7HHifEXaybClb/zXg48iRPZl"
_IOO10OIIlO = "MQ9lNrygJ/a9K4QsbkbwCANJucQCUoU4BzB5gr4EZWwM3lekSwlEO0Iy"
_OIIOIO1 = "7Tt8ULAQkWHpzVf0/j91zvNOTXa5wNXdMo"
_I0OllO1 = "dEYynRYx6HnuL5byBHQD6SvOOP4ngl9WIHUN7qN/XB0Uu25xrlhGwPrweBUaH"
_OOO0010 = "22UTUAVoyHeA4cXMI9yAtX4GBnG5bK5Mek"
_O1Ol1IOl0 = "wZQQ/JjYYjFeK7NV+08/jb7B"
_I0I1l0Ill = "HwmWw/M6gvK3SRb9mobZZQ4c8OQVp0aWgVEV1CZ/r"
_IO1O001 = "rLRgRts7L+AeD9xAhTbTO13c5RMf+zreynno8+ksdaaCoIAMemIRuAbLiB"
_OI0lO11I1 = "WCjEvekBGVsMXyxxc7Fr6OSS8hASiRXtg4Gj1GswYdhJ31ZF"
_IO10II11 = "OiQ2tFNvM1jUksrTRTUuih+Wubac6nNkBQBf9Fe0a7+fo1"
_IOIIIl1 = "mdtWkjkIAb6OpnsO9YhzMo8SJmIy+H7UbNAMS2yZE"
_IOOO010lOI = "KIVkt9FzyrklqLNDqFONat8NEwObcLMAgBBGjsQXSbybgm7kFxI8scuJ0"
_OIOl1l1I0 = "w2KOfzL6AxpSDo9gBRvkpAnvWgyB6uFmSNBd1s5ge"
_I01O0II00O0 = "ARalpa7+QLg5DyYZiwoosMjyeQZTswWW"
_O1l0111 = "2wbMQZeLk/K/zd1ooEZGM4E9cCsJumwnwRkariIo+Etj1og4BsXdj+KVzfO/dZK"
_l1IOl01O = "SsFvCYFH29OpsbmAkLtrxvGEYKCQEv9PW5Ab36MjCy+FLUsbeOcNVAWbjRlKJL"
_O110lO1 = "ir0tJStNttomPfENrkowN6hYCPHbuRi"
_Oll111O = "HdKr+STHJvHsMt1DgS2TvbOHS"
_Ol00IllI0 = "2CyF8l87nSyOU6VDFuqKk8/5"
_OlIlI1l = "RnXVKRUfKKmAuYa86PcLDFhmTfUeqkuXonpgdbl7CtF7RZnenz2qCGnLts"
_Il100ll0OI1 = "d4F4vjUTr63+X/0GMQEr7fcR0mFE/bgd3P5tXoMWRxvLW0lQL2"
_OOlI1111lIO = "6BKnbVn4ESRYHojpYF0wmfcqnzojgqGGjpuWA766l"
_lOOl1OlIl11 = "IqC+ZZNJOqZarlEyK/TE6mZ9COoS"
_lOI0llO0O0 = "cgkLr+8NTmKZ/dXuZ7QP1fx+yBZDeMFM2i"
_lI01llO1 = "5AEnFA2iSfpaKX2m85H4aFnQP8HO/fC0KFhp1C44qrw3bCjcF+T0"
_l0I1IlI0Il = "zyY2Ww9rFT1qw7X+DH6ehYNl"
_l0I1l0OI = "6x1b0Aif3kSnoGKuU18shSX3zoCB0KWM3Q"
_lOIl1O1 = "w/I8V+fsrQKNInSIadEvgKBl2f"
_O10lI1lO1I = "nnsQKPoS1lIDoff1eRPO5KYr91+22cQGOiyOYCPM3lScIagON24BhQQuMeqL8dQ"
_I1I1IOO0I0l = "Hx10yVoO8Wml/b2sw6vVwWdLsY1LvVX1kI31O"
_O01110l = "XGUkLx5G8RDchACiAARWs070WWmPEeR+d6y"
_IIl1I0011OI = "Ya5Bne4PBMZcXG9h3wntLz12UkxwUHA0t473nSeBGpZlXrtS8dRN8VmGqDPMr"
_l10IlOOIIO1 = "3bi8fgJHJm6GdxdpLy/MikKx8RfqzZM1E5mUILkSF4Jfg"
_I1O0Ill0 = "g5odsrzFv9phXw0mnXqvwnjccxgYCw/SzN/53IQxS4IScYq7WTTgAoPld7xlts"
_IIIOlI1O0l = "f4WkazKnOjohl5pbFa9Yu2PEBb5jNacLx1t1z0GydfZus/XB2zA9nqrHB2"
_IlOII1I0 = "H/X9teLi5iKj3OVpO6CK0gLdpykWWG2+fa"
_O0IlI01 = "mVze2Ut+KE2dnm/omG9rtE+rnZARaxuYJm9M9O9vMP65dPSeO"
_IOI10O0 = "kJvFNFerRaTI+DzJr+ggyVvPRsWPFGNA/hTKMnbKR3Qj3FDniqxf"
_lI0IIOIlIOI = "bDV7AJt88tJHAaGRrIgUIcpd0h3VxLwAzwBbIQO+omm99wAxzQU"
_OOO1OlI0 = "oplXdT4aQhgvxTtaJu7bdKO8uwPTLNxk/iSt0UiH6urjVPq5xUtpd5A7"
_lO1OO1I = "0vP/tqphnuPUfdHuXZstSdt797IiYZ"
_O0IO0lIl = "u+W3DbfsFhH4wvk5D2fMuc6qkDfc0W9Qq7l4zY/FLhU608iVcUWyOCh"
_l1l0IOO = "gZamZLx4N120MGW/LmzDWw4qrce3MVXQZBdjw"
_l0OllI0O0 = "BHES7FS0JNdtVaSasEE2jrnfTF/OH5FCKRQV7N18BWCmP"
_I0I1OOlIIO = "IoO8hHOAcHyQ8SN1z7vseztKbZr+tdwsGvkI1UEOHX6Vy0oLKX7vU+hdARp"
_Il00ll0l0 = "/qXFcc8zCvDFr8qpwNCL+uyG7pDLxbtJqS+53k3w1OmE7bBpleZWQaHAL0"
_lIOI0l1OI1 = "Xn1rZTHaxB4fo9F6AQVmVTyqlfJitPcYyv7TLMnGY+MvlkF"
_III1I10lOI0 = "sPchqEE/JzcUe0poJZ1pSyGnc2k/TLurmp7u9T0Vpy"
_I0IIO00II = "3A/GPPlEhtdyRYwgeNsXxQe/X9abGHD2"
_IIll1ll0O = "f+UwECHembtbvpKdevciAO2AGxERc3"
_OOIIIlllO = "BXVtTUWZqegJBuDoQYBJqt7kc5vp6rJvpRXHq8vp12zWTSjsytUAhT7b"
_OI0OOl110I = "8yYUW20V173p8stzyuM9XFvQg9j2D7USjuOJzshFpmYc6lH"
_lIl1IIOl = "zP6f2x+V95/DjMVExouldKVd3/rZZTGWc36qK0JpW+"
_l11IOOIIO0 = "AEVEDcBDiUcGlRYU0zu5RhF4OdAVx/bIeyQEGmDjgIENJSuqtrPIzEtg0V"
_OO0OlI11I0 = "45pRhRZjK3mF/MxBCP954YCpW/GE/4CrQyHla6"
_O01I001O1I0 = "KVAn6qw4t+nxTlUw/APUNrM63nU90MCsc2hIPCDCL7vkqkr6K71gjVEjNNg8Ua0"
_I01llllO = "I62NG+4vLdDDWt24NaJITBbLWnru1E4fQ0NN"
_OI1l1O1lOl1 = "iKNemSsgH7UIXQJmAWIeRCicizv+PRBenHZAD24MYR+c6oxW7tM4nWp6m7l"
_OOI011O00I0 = "P2DEL5mf++uPT+TjvQwuvurw9U/PN7mG6lOVWMXztLNmntl5oYQn/nwfJzvi7K"
_I01IlIl0Il0 = "6gDnC//ONXB5PPwM7Ms2zfkQlq7c5Bqe4bvaarHWRvbQuY5wSUnmsLY"
_I1O11lO = "gArJV9q7NHhw+DTENonppEoeAgG1YJF7MH+7aI3IgIpE"
_O111I00II01 = "WHtzK6USfhm2gl6A9/PmRGQd"
_lIIlOIOl01 = "WyoHXA4a7SjSbQrNp8kRity9UfwHUZffBaB+Nfq6+ewnTbXOOm"
_ll1lO0ll0OO = "x3LPJEAvxo4LhfULtvRgRwmSUVI08A+LfNG+iuHKeFtSnkHhIYOSSAKKr0b0"
_O1OOO101O01 = "gFYFUYt4O+sFMAgLKXpLgmaZE"
_l00l0Il01OI = "gDSPmdXCN8HRjJHafy+KTONZy4P0sx7BHX8ws8TWc+I+Dp3RUgVQx"
_lOlIIOO0I = "b/qMP4ISSH9bJ+dD384sRapP4funFOvIY2RLA+cz319M"
_lO0IIII = "288HPwNc/fb8dicGucw="
_OO1lO1000 = "osIRaTlSFJgfHr0IEpUVMKQJ7BMF4EIcBu1cvTLezXWeBZJGcc"
_lIOO1l0IIOl = "i7orgGFapxZ/a+eT1Nr2oA+Ihg2ICVAFVovCC"
_O100111II = "eupzUtprvEyLZ/cQ9+mYntHexhT1fDm8HEQ19uIHZ/r4NYLYPJMShayX"
_II0lI01ll = "XHJqn2xKagUlv0MhDwo9aRWLlu0"
_OOI1Il10 = "YDPlAHVEshPt2xBJGuJ1GZtVCSv"
_IO01lOII1 = "B09pl2+AjeMgHB3LBnQV+xG4QuwV6IwNqwJavcBpmbouix8jzyytEt"
_lIO011I = "XkIzoX2Wvf+wjv94sVWHETF7KDI+c9i7OkirvdENacrMvU3MW4SZ"
_IOl011OOl1 = "K4hVNej22p/EatLQRAIYaQaM9kpgCQEq"
_O1O1lIlO = "5UKhMAZprAMK1v5Cg2OBlX3j4Kz05lm6l6QYTN7E8yIl"
_I1l0I11I100 = "sm66uIyWtg3XNkHMzPK6bCWYgQePQzV"
_l1lI1l1OlIO = "u9H0iwv5Av27fcGA2V6V0KONtes"
_IOll00I1IlI = "M3tYlgbAeaEdILd3HSpJft3CaLIHcmr4XBP0x89/XuAOjqAK/UZO587F1u4F3"
_I1lOIllO = "gy72ljKZ8lkuy2rtTqn6ovbXANWYTy6EruRCKqS37UAOcvjei9WipLtohUp8TRy"
_I1O0I1lOOO = "lMPhmKQFio3jzP20ClrFwT3Q8nFrp5ivhR+3cFcAe8d3JJNzfDwMB"
_I0I0lO1l0 = "GUMaUtH3RYfKYwYPun5jExu2WCwRti7hvOYXLu6s7"
_llIIIOl = "tQzeGAex+Q5l6vU3ytUByRZq6TrEO6UeICN+1huFTXxbMFwJ3aR3qfcp"
_IllI00I0111 = "buAnl3wrxOEjiBPVyRbE3QBvv3BTf6GDqU+c5EtHeQ"
_IO0l0OI00 = "0I9hs0ECdpPFpzYEtQ/04Fb9CoTr0eyXngBgv0Yb4k2BDizhbqSpQYrYJXppVe"
_ll1I11I1ll1 = "YVyFMH4hxHbEo+UW3GMxT+dUbCCDxHGquGiQVPVz4aDrwW181"
_l01I1II = "tOylpT8yhSHVuaGPtCUWXmq6XoWL0/IxT7Kh4Wf6"
_O1I01ll0l = "zLk4o4L6fLTsccWDG181EDaT2Gj9Mji2NlqQ"
_O0O10001OII = base64.b64decode(_I1O0Ill0 + _IO1100IO0 + _Ill00I10 + _Il1II0lI + _I0I1l0Ill + _O1OOO101O01 + _llIl00lO0 + _IO1O001 + _ll0O0lll + _I0OllO1 + _I0IIO00II + _OOO0010 + _OO1lO1000 + _IO01lOII1 + _III1I10lOI0 + _lOOl1OlIl11 + _I0I1OOlIIO + _O1l0111 + _llIll10OI + _OOIIIlllO + _O1ll1O01I + _lII1II1I0 + _I0I0lO1l0 + _I1OlO00ll0 + _lOO1ll10 + _l01I1II + _O1Ol1IOl0 + _Il100ll0OI1 + _IOIl00IO1I + _lO0I1lO1lI + _IllI00I0111 + _II110l0Il1l + _IIl1I0011OI + _II0lI01ll + _OlIlI1l + _l1IOl01O + _ll01O01l + _OlI1l1llOO + _lIOI0l1OI1 + _IOll00I1IlI + _O10lI1lO1I + _I0l0IIO0I + _ll1lO0ll0OO + _I1O0101 + _O1O1lIlO + _I0I1OO01 + _llIIIOl + _III1lI1Ol1l + _OIl0lll11I1 + _I1O0I1lOOO + _OO0OlI11I0 + _l00lIOl + _I0lOIl0O + _I10Il010l + _lI0I0l0lO0O + _I1O0O00100 + _I101IIOOIIO + _Il00ll0l0 + _I0llIOI0 + _lIOO1l0IIOl + _l0I1l0OI + _I01lO1l00ll + _l00l0Il01OI + _Il1II1lO011 + _llO0I0IOl + _OIIOIO1 + _O111I00II01 + _O0lIO1O + _lllI1ll + _Oll111O + _O0IlI01 + _I1l01OO1 + _I1l111lOlO + _IO10II11 + _OI0OOl110I + _O11l00IO0I1 + _O0IO0lIl + _IOO10OIIlO + _O1OIIIO10 + _OI1l1O1lOl1 + _lO0IIII)
_Ol01lI0II1 = _l0O01III(_O0O10001OII, _I0OllOOOl0[0], _I0OllOOOl0[1], _I0OllOOOl0[2])
try:
    _lOlOI00 = _Ol01lI0II1.decode('utf-8')
except Exception:
    sys.exit(0)
_O1lOI00 = {'__builtins__': __builtins__, '_O0l1lOl00': _O0l1lOl00, '_II0OlOO11': _II0OlOO11, '_OOOI00O0I': _OOOI00O0I, '_l0O01III': _l0O01III, '_IOO1llO': _IOO1llO, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': _OlO0II0O11O}
try:
    _OOl1ll11II1 = _O0l1lOl00[2](_lOlOI00, '<s1>', 'exec')
except Exception:
    sys.exit(0)
_IOO1llO(_OOl1ll11II1, _O1lOI00)()
#PYG4E
