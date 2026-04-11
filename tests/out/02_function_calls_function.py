#!/usr/bin/env python3
# Protected by PyGuard v4 (pyguard.akean.dev)
_lO0O1I1 = bytes([132, 239, 98, 12, 62, 168, 159, 228, 6, 167, 153, 16, 115, 105, 247, 133, 250, 248, 200, 106, 91, 200, 162, 8, 224, 89, 100, 129, 68, 167, 129, 46])
_lIOOO0Ol001 = bytes([189, 208, 31, 254, 41, 219, 242, 85, 220, 79, 183, 133, 194, 221, 6, 63, 138, 62, 68, 174, 154, 157, 62, 157, 33, 49, 32, 25, 253, 31, 239, 49])
_OlO1OIIl0I0 = bytes([10, 117, 148, 8, 48, 92, 138, 149, 33, 34, 36, 94, 142, 254, 30, 16, 122, 143, 9, 157, 112, 227, 121, 152, 174, 192, 84, 26, 169, 52, 136, 195])
_lOOO0001 = bytes([133, 148, 218, 143, 194, 20, 193, 34, 3, 85, 69, 186, 38, 24, 152, 132, 92, 195, 130, 0, 221, 9, 182, 194, 238, 101, 154, 227, 137, 177, 91, 196])
#PYG4S
import sys, hashlib, base64
_OlIlIl11O0I = type(lambda: 0)
_IlO11OO11O = (open, compile, exec, getattr, __import__, type)
_OOl111OIIOO = _IlO11OO11O[3](sys, '_getf' + 'rame')
_IO0O0IlIlO1 = bytes([193, 39, 183, 36, 154, 79, 72, 46, 141, 90, 201, 56, 116, 228, 92, 79, 175, 50, 46, 135, 174, 17, 7, 41, 70, 97, 139, 216, 145, 62, 156, 0])
_l0OI0OO1IO = hashlib.sha256(bytes([180, 205, 222, 183, 77, 86, 105, 190, 206, 103, 233, 108, 23, 142, 194, 32, 117, 105, 172, 51, 80, 150, 124, 116, 105, 195, 229, 50, 131, 149, 93, 199])).digest()
_OOO1I1O = hashlib.sha256(_IO0O0IlIlO1).digest()
_IllO1l1 = hashlib.sha256(_l0OI0OO1IO + bytes([156, 185, 9, 160, 26, 167, 2, 223, 72, 175, 123, 96, 237, 91, 234, 101])).digest()
_I0OIl110O = hashlib.sha256(_OOO1I1O + _IO0O0IlIlO1).digest()
_IOlOOll0I0 = hashlib.sha256(_I0OIl110O + _OOO1I1O).digest()
_OIlO1OI00 = hashlib.sha256(_IllO1l1 + _l0OI0OO1IO).digest()
_l0O00IlO0 = _IOlOOll0I0
def _IIl1OOO(_IO01IlO1):
    _IO01IlO1 = bytes(a ^ b for a, b in zip(_IO01IlO1, _l0O00IlO0))
    _ll0IO0O = []
    _I0l0l1l11 = _IO01IlO1
    for _ in range(6):
        _I0l0l1l11 = hashlib.sha256(_I0l0l1l11 + bytes([180, 110, 108, 43])).digest()
        _ll0IO0O.append(_I0l0l1l11)
    _IO00O1I1I0l = [(b % 6) + 1 for b in hashlib.sha256(_IO01IlO1 + bytes([47, 212, 231, 25])).digest()[:6]]
    _lOl10lO0 = hashlib.sha256(_IO01IlO1 + bytes([169, 24, 131, 75])).digest()
    _IOllO1011O0 = list(range(256))
    _lI1I110 = 0
    for _Il0OO1l0I in range(256):
        _lI1I110 = (_lI1I110 + _IOllO1011O0[_Il0OO1l0I] + _lOl10lO0[_Il0OO1l0I % 32] + 196) % 256
        _IOllO1011O0[_Il0OO1l0I], _IOllO1011O0[_lI1I110] = _IOllO1011O0[_lI1I110], _IOllO1011O0[_Il0OO1l0I]
    _l00lI1lIO = [0] * 256
    for _Il0OO1l0I in range(256):
        _l00lI1lIO[_IOllO1011O0[_Il0OO1l0I]] = _Il0OO1l0I
    return _ll0IO0O, _IO00O1I1I0l, _l00lI1lIO
def _l10I0II10O(_O1O01lll, _IOIlII011lI, _I1l10IlO, _Ill101l0l):
    _Ol0I1lOlI00 = bytearray(len(_O1O01lll))
    _I010l1l = 6
    _II1O00O1OO0 = 0
    _I001lII = 0
    _lO0I1l1O0 = 0
    _lIll0l00I0l = 0
    _OII0O1lIII = 62
    while True:
        if _OII0O1lIII == 176:
            break
        if _OII0O1lIII == 62:
            if _II1O00O1OO0 >= len(_O1O01lll):
                _OII0O1lIII = 176
                continue
            _lIll0l00I0l = _O1O01lll[_II1O00O1OO0]
            _I001lII = _I010l1l - 1
            _OII0O1lIII = 138
            continue
        if _OII0O1lIII == 138:
            if _I001lII < 0:
                _OII0O1lIII = 124
                continue
            _O01I10ll00 = _I1l10IlO[_I001lII]
            _lIll0l00I0l = ((_lIll0l00I0l >> _O01I10ll00) | (_lIll0l00I0l << (8 - _O01I10ll00))) & 0xFF
            _lIll0l00I0l = _Ill101l0l[_lIll0l00I0l]
            _lIll0l00I0l ^= _IOIlII011lI[_I001lII][_II1O00O1OO0 % 32]
            _I001lII -= 1
            continue
        if _OII0O1lIII == 124:
            _lIll0l00I0l ^= _lO0I1l1O0
            _Ol0I1lOlI00[_II1O00O1OO0] = _lIll0l00I0l
            _lO0I1l1O0 = _O1O01lll[_II1O00O1OO0]
            _II1O00O1OO0 += 1
            _OII0O1lIII = 62
            continue
    return bytes(_Ol0I1lOlI00)
def _IlO10IIIl(_IOIII100l):
    _O0000IOOl = hashlib.sha256()
    _lI001OlI001 = [_IOIII100l]
    while _lI001OlI001:
        _IO111Il1OI = _lI001OlI001.pop()
        _O0000IOOl.update(_IO111Il1OI.co_code)
        for _l11lO0O0 in _IO111Il1OI.co_consts:
            if type(_l11lO0O0).__name__ == 'code':
                _lI001OlI001.append(_l11lO0O0)
    return _O0000IOOl.digest()
def _lIOOIl0O(_l1O1O1lO):
    try:
        _IIIIO1O = bytes(a ^ b for a, b in zip(
            hashlib.sha256(_lllIll01lOI + _IlO10IIIl(_OOl111OIIOO(1).f_code)).digest(),
            hashlib.sha256(_lllIll01lOI + _lllIll01lOI).digest()))
        return hashlib.sha256(_l1O1O1lO + _IIIIO1O).digest()
    except Exception:
        return hashlib.sha256(_l1O1O1lO + bytes(32 * [255])).digest()
try:
    _OOO0Il001l = __file__
except NameError:
    _OOO0Il001l = sys.argv[0] if sys.argv else ''
try:
    with _IlO11OO11O[0](_OOO0Il001l, 'rb') as _O10I00llO:
        _I1OOIIlO1 = _O10I00llO.read()
except Exception:
    sys.exit(0)
_I1OOIIlO1 = _I1OOIIlO1.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if _I1OOIIlO1[:3] == b'\xef\xbb\xbf':
    _I1OOIIlO1 = _I1OOIIlO1[3:]
_I00101O0I0 = _I1OOIIlO1.find(bytes([35, 80, 89, 71, 52, 83]))
_I0O00O11 = _I1OOIIlO1.find(bytes([35, 80, 89, 71, 52, 69]))
if _I00101O0I0 < 0 or _I0O00O11 < 0:
    sys.exit(0)
_OIlI0IOI1O = (_I00101O0I0 + _I0O00O11) // 2
try:
    _llOIOOIl = _IlO11OO11O[1](_I1OOIIlO1, _OOO0Il001l, 'exec')
    _IIl1IIIOlI = _IlO10IIIl(_OOl111OIIOO(0).f_code)
    _lllIll01lOI = _IlO10IIIl(_llOIOOIl)
except Exception:
    _IIl1IIIOlI = bytes(32)
    _lllIll01lOI = bytes(32 * [255])
_lI00O10IOI = hashlib.sha256()
_lI00O10IOI.update(_I1OOIIlO1[_I00101O0I0:_OIlI0IOI1O])
_lI00O10IOI.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(_IIl1IIIOlI + _lllIll01lOI).digest(),
    hashlib.sha256(_lllIll01lOI + _lllIll01lOI).digest())))
_lI00O10IOI.update(_I1OOIIlO1[_OIlI0IOI1O:_I0O00O11])
_I11l00101 = _lI00O10IOI.digest()
if _IlO11OO11O[3](sys, 'gettrace')() is not None or _IlO11OO11O[3](sys, 'getprofile')() is not None:
    _I11l00101 = bytes((b ^ 10) for b in _I11l00101)
if compile is not _IlO11OO11O[1] or exec is not _IlO11OO11O[2] or getattr is not _IlO11OO11O[3]:
    _I11l00101 = bytes((b ^ 148) for b in _I11l00101)
_IIIO100O = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != _IIIO100O or exec.__class__.__name__ != _IIIO100O or
        getattr.__class__.__name__ != _IIIO100O or __import__.__class__.__name__ != _IIIO100O or
        open.__class__.__name__ != _IIIO100O or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        _I11l00101 = bytes((b ^ 168) for b in _I11l00101)
except Exception:
    _I11l00101 = bytes((b ^ 168) for b in _I11l00101)
_l1I0l001I = sum(b for b in _I11l00101) & 0xFF
_l1I111I1 = _l1I0l001I
_I11l00101 = bytes((b ^ _l1I0l001I ^ _l1I111I1) for b in _I11l00101)
_I0OIOOll = hashlib.sha256(_I11l00101).digest()
_l0OlIOO1 = hashlib.sha256(_I11l00101).digest()
_I11l00101 = bytes((a ^ b ^ c) for a, b, c in zip(_I11l00101, _I0OIOOll, _l0OlIOO1))
_IIIIII0 = bytes(a ^ b for a, b in zip(_lO0O1I1, _I11l00101))
_O0OOI0Ol = _IIl1OOO(_lIOOIl0O(_IIIIII0))
_O1IllOI000O = "axb082Eunj/IM4nofYh6IMrT"
_O0IllIOlIII = "toAJbygmMwW7/7tscgG6wAtGpe1"
_l0OOI11OOlI = "InyzPg8KZONnTkgjE94yxaxS"
_IIl1O110 = "PMWWAHWYfkWvzJu83WThXkgDv73lQRyvPzKwIu3/V16Fz64ZfjI"
_O11lO11 = "yiTFqIFkdPq9BcDRhXJdSWhrHtcKkQsGJW2XFWk7INtqCRYbEypgc"
_Olll0IO1 = "/tYq+uCZSuoGOn8llV6WlWQ1QE+EF"
_O0011000lO = "uKjrTo78GLBD71YORPvVk761qGsM"
_llIll1IOl1l = "54Tz6Pts00g9dTyDAoRqdk2907B"
_OI11I1I1lOl = "aWcQLQUVbwyiXLvycxvVE7zzsSzfCotEuY5y84S19zD5xOU7"
_llO1OOIlO1 = "sGfuPPrL56WcPJRxJXBK8daixXkxCqLqU/T3e2GO7uV2Kl7DfraBx0nmuUglW"
_IOl1I11Ol = "oLd94t21rFfUPP1qR2Xf8ewNpVvHXUlD82MuRukOM17tiI46gtNaL"
_l01I100 = "CtAuK/14KjC+P24RmmtTyMtGXLE05fen09rKzZXxg0U2J90dZ34jsqLmZ7ZPX3"
_OIOIIIl = "RW4NeC572uYaCXUmirp0+ph8xYshBly1xAQ5WClj98VfMj7sAVjhGqJH3Uv7"
_O01llI0IO = "0apkhAN8hYWeuxNz80a5wkTEFV8nSQIO4sL9s0pHE9xssnmcYitp34WxvBCf"
_l1O100Il = "plVnoQotntfs1DbsuccUu8etTszXpTw9ng"
_O0OlO00Ill = "mgDcxsD73xzNKJtfjT7nvvHqIqeetvYv7TZwj3ndbopczOkdiIJaGC"
_Ol1Il01O = "/zSkTL0JjpjQ/xV0XTJLWyjgMNMqV+QEWH5G26p2nNYYLy996b85wfIoKNPGxk"
_O1OO1O000 = "iv0CUSXKmfCKEA3DRaQpHW9hW4hMhL8e1OMp"
_II0lII01 = "eexY8qvVXIeY64tpPv1v3BBtdqyzWD5n"
_OOlI101OIlO = "BndNB1Xmdh9S/TzhoTQYF60Fc/EHhqCDLc2fD"
_IlO1011l = "XBtkaocxtbdaiaugM4GxljiEpdbS2n2nf5W"
_I1I0001l1 = "m+adDsGq6eIK0A08aDMmsk9k6Yzk5g1GiWpK"
_l1101O0O = "jCBUFCi5a3oo+UdupSgtoD3h/bEcxGo"
_lOOOO1l = "tPcOvcay37cnP7zY="
_l1O1O0O = "jvC8oTzeKXNy5Hfpq0F1d6TSH"
_II0IlI0lIlI = "IU7kyGGyVaNWepVad45GkvA59FvUPRv7PDYIGO0vWqP"
_lIOIllOO = "TbRwTXU5q9tciTxOMLxkGKdqX+2zhn5aBW+ZHE13GC/cTKl7DLj"
_II1Ill0lll = "eN1SLC09nspMvId3OXN8G1V9IxLK7gdnlVR1cRJm"
_lllOO10 = "rhwVrDOker6BcMLlaCIgU7/ZqGxSTCZSF4gEiou1pFV1ij4wVGKxVq0Hz48aau"
_IO0O01lI01 = "raEC13kIpIw+/N43Im8Bh0TpFptGwSxd+n6nEzcC9Tna8Jml"
_lI10l1Il0O = "bIOQqR9mX9cTozHdveY8jUDZqDQr3ImHEDxY05l+q4jXT7vXb7yzlhXFqI"
_l1lO11lll1 = "rHzFqKhQQpZJQ1o3miutMZPhJTkLRhDJn+5wbuUzfS3Lh+b"
_lOI0l0I0 = "AdW3Ws4ugPuoG0yWSu/cWOuz7TWIqFfgdw6vUvxrNCRU"
_O1I000ll0I = "cY9423CgXoKEd/nknbGodGPAjlIO0DkOG7"
_Ol0O10l1Ol = "JZzJROF4dR6wOt2yLlQqwUoo7V3mKugnn5H/InAUGrcehmOOJ6/x"
_lllOl001ll0 = "HNyXAuMJMEhpfWRZTa33i9xDahi4Wc9i8692bli6"
_OlI0l1lIO = "Qf5Izn/ueB8nvgIUhniaOizM+URG7CMs6LZew37RT5EG/DuK+WL05"
_OI1IlI1l = "BetSZRXdDlN27SBHxIlNGLtKEn+JRylToQ137gdZTyzGfqWJVzPi92UG7M"
_IOl10IIOO = "GTZ10QRdlQXohio6ArNuay1I0c0tJNjophNidukx7pMkz2Sz4tVCwySJNqEbaJA"
_lI10l01 = "3ZAhKH+iHcXlCfFQBBX9kZUPelWe2lggRSCHCeGdxph6ouxVCUb8kM/OTZKv/MK"
_IIll1llIlI1 = "fgrLlNhMiAOL1ND8EMgyk24w"
_O1lOlll = "MEITCUUM2we9y4cFwgyHjWKWPIFcFF2Vnj5OXnL8t"
_llII0lOIO01 = "ZuBB9HVo61y1zjYsWb/1LU2UB7jP9IqMj76ARt6gFxvoE"
_lOI0O1l10I = "7YweXlGiGIPQZZYaGmUp7c/gTkJkT0AbO4pUxJvSiN6u3Hzc3V/c8BHzr5AJ"
_O1l00O1l1OI = "CEexqqXia96yubEuW8btcikAh5Pt"
_lI00lOOIllO = "XC5bNnpQEtjhqv3Twws8uQo7hVRi7vZDjr3lL+cs/tpCukHLO"
_O1O011l01 = "m0JdwhiBACvr2E2KU7scfvBx2xNI7HjOwIhxt"
_llOlOO1lI = "h8Epuxm+49IjDbD0+EWC8ouQ8qLDbnwCEtehpJu0cMTCnLHgCuTzP1FtZ"
_I1l011O010 = "IZp7BB070KMd3OIwBNUBpOySsGHmSy6qCgoJ1kg3zugV+CCq01n8622k"
_IOIOIIl0 = "eW1vcZApgUZpDaSNl7h/pa3P0LB1Dz0/wE3tZy+mWX+R0X0M"
_IOOl0lO = "U4OEVE7nyUAut+olszNDrWvf3XMxR6"
_O1OOlIl = "pfr69c7Qmv/NhBfnyD6uyy9WiOO4aGJc"
_I11OlIIlI = "QaOJACw5HygFiLYsMNrvGoNfwLn3TXiYZC"
_lI00OO1lI0 = "/XVgbdLdoxPDP184KgMe3X3jCejw4r/xH18B"
_O0Oll10 = "jZX+RlO4LRVjYqE+kAcXa/M9N7w8LGk6wSjGS6FJM"
_I11O1011 = "rEijRP97WaRL+p3tj2j8bXQRjQOaIY32r3ObvqM"
_lOI1I000O = "O8kT7HoM9M/ZaERs9EgBNBWxFOUVT9xGMau9IWmI12phax1PVXjSMYdmn"
_I1lO111ll = "3BhQAooQJdQUEmeWAeSo+YpH07fx8DpeEpH/5niHG/t/Fs4"
_lIlOOOl = "FHC10UrPYnH4VdG3msSRjZuvMjeenEgicjwmQStW1j4nIl"
_IO01l1I0O0l = "l6GJp24vTK0ATnf/pLpaJhUaxYW4u/oEmbY2Ac"
_I0O0IOl1I = "0IvfWbMSUcDIvc7e1m1ENfi8hcz3kI2J4Ebs2bCiNKlM2ydIGSTXBRSN3L1l1"
_I01IOl011O = "J17u4Jw0TmqzFsmeIFbXdk3EXDKuKKZoyFiNrfFk"
_OI0l1OO01 = "29m/zRm4+tb4fEd2vSdTvYDuY1zKAmMKxmEvwG1o2qrsfD09X"
_lOl0I0Ol = "d+ulYh0v3zRmtFCZbMSNs0AsebjxZc"
_I0IOO1l = "GqFDmdfPJp2UIZ2RxDEZ8z635Y5aOL92oWUUA5mV+ClkRDk+j+nVHUmu7EVGu"
_II10IlII = "m4Je2Au35SlniufyY/XbEk+DGkrwMmP8h1flzK/k"
_lIOlOOI00I1 = "+aEBWKfKi9OXT5Xl47FngBjAeNgwwLt863tWa"
_I0lI10OI = "1dA/mCRRJjPTMqQOaGwp7aobF1ZqxdZDhE4axlW05Br"
_IOO1OI1OOll = "NofQC39Xf9OcDYOoFsTc9uW/AsKTIwfputRIwi9BnZA+xBVCALIc3p+1ZyS"
_IO01lI1OlI1 = "xtntdcMmGGA8/jYSL5cnZYnOrac+VQouc7tS56BV/n"
_O01I10l = "xdWaoqIx/E0j9lWJoYhG2Qo51HALIOtZ41AwCiH"
_l0llllOll = "cgxuhwmCx7GvSj6svxDUAxtMsU5mAfP7+Z+"
_I0O10IOIIII = "BiIBGqJ99fi3wwOoGJENjVVa"
_IlOIlIl0 = "Nb4V5eFeoO7oLP36oEUETxDf"
_OlIIO11 = "CBC8Pq1JWQh76NShZsiLEFyfknb8PCoL1TMij9+uxIVs"
_II0O0Il = "vpZT9pXpe8wKbgsWsRLrJelBGzcyet3n"
_O0IOI0lOl = "TVaKcmEYMfaD0oOm9BdcYqIY8xcfGFVj9WbQVws33ZoK9IhvY0"
_I01llOl = "y20Jc9YVRmy7VLsYh1/Y8qZ4EQ1Lfle+EZkZCiRvMtj"
_ll1IlIl1I = "zfPV5glzq9dawKA79nMFk6s+HTK3Kv1j"
_IIO1OI1l01l = "0xO0IwvqRauxYDdfDxZVNoGX"
_Ill1I0O = "dXZBZFCO8Mz+IHQeuzFqV4RXSGeKv0UgR2KCFED7plTppj"
_ll0I00lOO = "6oEc8xJyJizzS4Ik9+UQ7nubHzWlLPv6nDhVz7Ev6X58JJuXy"
_l1O1II1O = "4LxhRR/ggYdCWbZfJT1SSB6SR1oDecch7x6"
_OO1lI0l1 = "K5vLabRQ3SAHJoW5OjUbqI5XGBQuOfwY1tDF23efdpx4o8VXr"
_IO10001O = "LpsqP2rqJmDG6ueDHw6ruh68+sq0WqSxOY7XeMaOV4MZRC"
_IIIlO1Il01 = "5NM3MFVMDDT3WZ1Ryd7tyhZaiFrOhtBb8C"
_I00IlI0 = "xsFKRGOFFl4M2WXqFw1XS0EvfBOtmVxGKs906TuOUuBIMhpmwkWUt"
_IlOl11Il0OI = "LC5EtQIuZz64/wkdH964I9fKmDADepBx7fPEJNAmBIDUJOqHb+FOwkw/Llf"
_I1OIO0l = "qyvmRcuJHEfij/JrXWCRuXpBMaH1QA2/23LTSg4yUzBwUi"
_IllOOOlO1lI = "3lq/CfqfScjOsLoquX2PWKIK6xZmIKwDc0wNTA+TaVSeG"
_l11IOOIlI = "Zs19eS+cOudQCm1LKMKnZYcFV+6zQo+HPHJLLZO7bmzi9LZX5+uylj"
_I00OO1Il = "j+vAajtP+m783a/cPd3Xa/I/ONctNe93hEm"
_I1II0I0l11 = "zUKuhHCDooCBmfP/mSAMD3sbNJf7GmjqdovvJWgZHbs+RmTVGcB"
_I1I00lOIIl = "QTvTXewKowIELnjRSC1mgPmy4TLWaU/C5l5CEMX+VctzOdLsbuzh3q"
_lOIlOI10l01 = "ILaPqo69yooLvz2MvrkNDS66ObCixM7ydyx89DwJqIZueNvLHmpYP"
_l1lOlIIO = "TIPaS2jt3peRifG7tq0N9eiP9ASFG3ouLxXxCjLp1Al363Az29Bnk537"
_I00OOOIOOOI = "Maleva1BKOTY06botkUa1cLO6JmrCyIQz2xVr/3Om9PNijbQAacFYw"
_IOO11OlIOO0 = "vjQYHCJywfqeoG0riTLHfmn0iLD0EOKBOzz"
_l000lOl1 = "0rM9P1iHBzkxzzy964/aROLLwBkc4unmB"
_OII1llO = "ekNig1oVDwmJL/ndpIDlda2v2BTnVR296akEp6GR"
_Il1lOIIIIO = "d2APGHRHE08DTHum4aF2YSSDzS"
_OO101l0 = "Y4f9SZS9XmY9SIXT5w3Q+557gWv3hucZwQG0Bk6LmixrY"
_O1100101I0I = "HPSj+FvC4ENcfbPLw11fn3DDxvsL5S0+Gia4tR8UUOqex8Sa1P1"
_l00O0O11l0 = "ECJq8N3iRi1uN4+jlpvTAjcnagkohlbksQn30C+ylVvN7UrgzftD0B6kGahZ"
_OlI111IO = "2p4VLe+ipGYrlo1i400kkb1cLQOq7l1rRPXGUnfAhgcOWddD7sI8xB9"
_II0OllI10l1 = "8C5Tc3xzvMW1s71+NleuL0MWXQzt1SVAfkfSJ+MPUfziUpzHG"
_lIlOOlI = "4p+XNgGYzObR/3V1haEBSzT/"
_l1000OOI0I = base64.b64decode(_O1lOlll + _l0llllOll + _lOIlOI10l01 + _OlI111IO + _lI00lOOIllO + _O1IllOI000O + _I1l011O010 + _IOOl0lO + _l000lOl1 + _O1100101I0I + _l1O1II1O + _OlI0l1lIO + _Ill1I0O + _lOI0l0I0 + _OII1llO + _Olll0IO1 + _IlOl11Il0OI + _llIll1IOl1l + _l1O100Il + _l01I100 + _lIlOOlI + _lI10l1Il0O + _O0011000lO + _O01llI0IO + _I0IOO1l + _IIll1llIlI1 + _I11OlIIlI + _l1lOlIIO + _O0IllIOlIII + _OI1IlI1l + _lIOlOOI00I1 + _O1OOlIl + _ll1IlIl1I + _I0O0IOl1I + _l11IOOIlI + _II10IlII + _Ol1Il01O + _O1l00O1l1OI + _I0O10IOIIII + _OI0l1OO01 + _II1Ill0lll + _lllOl001ll0 + _IllOOOlO1lI + _OOlI101OIlO + _OO101l0 + _ll0I00lOO + _IO0O01lI01 + _l00O0O11l0 + _I1I00lOIIl + _O1I000ll0I + _OIOIIIl + _OO1lI0l1 + _Ol0O10l1Ol + _O0OlO00Ill + _IOO11OlIOO0 + _lOOOO1l)
_OO00l1OI = _l10I0II10O(_l1000OOI0I, _O0OOI0Ol[0], _O0OOI0Ol[1], _O0OOI0Ol[2])
try:
    _IIOl0110 = _OO00l1OI.decode('utf-8')
except Exception:
    sys.exit(0)
_OOO1101OOO = {'__builtins__': __builtins__, '_IlO11OO11O': _IlO11OO11O, '_IIIIII0': _IIIIII0, '_IIl1OOO': _IIl1OOO, '_l10I0II10O': _l10I0II10O, '_OlIlIl11O0I': _OlIlIl11O0I, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': _OOO0Il001l}
try:
    _O00OO10O0Il = _IlO11OO11O[1](_IIOl0110, '<s1>', 'exec')
except Exception:
    sys.exit(0)
_OlIlIl11O0I(_O00OO10O0Il, _OOO1101OOO)()
#PYG4E
