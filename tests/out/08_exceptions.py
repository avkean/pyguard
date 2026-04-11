#!/usr/bin/env python3
# Protected by PyGuard v4 (pyguard.akean.dev)
_l1O1IlO1IO = bytes([107, 211, 85, 83, 239, 85, 187, 136, 102, 34, 13, 119, 219, 165, 151, 31, 134, 252, 189, 23, 44, 211, 160, 12, 38, 20, 137, 13, 139, 137, 217, 75])
_lOl01O0Il = bytes([58, 136, 15, 86, 5, 99, 176, 79, 70, 150, 25, 161, 168, 238, 91, 175, 86, 77, 161, 252, 188, 194, 188, 156, 110, 176, 200, 247, 253, 214, 128, 138])
_OlI001O1l1 = bytes([216, 243, 59, 240, 92, 254, 204, 116, 187, 90, 188, 55, 178, 37, 97, 84, 73, 218, 35, 223, 20, 235, 104, 167, 144, 242, 243, 20, 16, 211, 130, 88])
_Ill00l1I = bytes([81, 243, 103, 250, 41, 172, 122, 133, 224, 199, 121, 149, 112, 206, 234, 141, 223, 13, 129, 88, 59, 137, 179, 245, 12, 116, 8, 169, 54, 61, 103, 219])
#PYG4S
import sys, hashlib, base64
_lO1OII0lI01 = type(lambda: 0)
_OlI10lIl = (type, getattr, open, compile, __import__, exec)
_I0lOl1I0lIl = _OlI10lIl[1](sys, '_getf' + 'rame')
_O00I0011 = bytes([107, 29, 146, 124, 227, 19, 208, 49, 248, 101, 213, 22, 30, 112, 41, 92, 147, 249, 175, 175, 240, 90, 225, 236, 47, 67, 210, 211, 207, 214, 47, 78])
_OIII10Il = hashlib.sha256(bytes([222, 34, 15, 60, 79, 205, 249, 238, 15, 46, 215, 24, 38, 153, 157, 251, 52, 212, 54, 97, 74, 33, 35, 92, 9, 237, 18, 253, 117, 27, 137, 109])).digest()
_ll00lO1lOI = hashlib.sha256(_OIII10Il + bytes([89, 75, 18, 249, 47, 48, 74, 49, 84, 177, 18, 249, 186, 69, 182, 247])).digest()
_OOIIOOII = hashlib.sha256(_O00I0011).digest()
_I1l011I1ll = hashlib.sha256(_OOIIOOII + _O00I0011).digest()
_lOl1O01 = hashlib.sha256(_I1l011I1ll + _OOIIOOII).digest()
_OI1I1001 = hashlib.sha256(_ll00lO1lOI + _OIII10Il).digest()
_Il00llO = _lOl1O01
def _l0Ol0lllI(_II0Ill01):
    _II0Ill01 = bytes(a ^ b for a, b in zip(_II0Ill01, _Il00llO))
    _I00I0lO0l = []
    _lO1O01O0O1 = _II0Ill01
    for _ in range(8):
        _lO1O01O0O1 = hashlib.sha256(_lO1O01O0O1 + bytes([105, 51, 217, 153])).digest()
        _I00I0lO0l.append(_lO1O01O0O1)
    _IlOOIOI1Il = [(b % 5) + 1 for b in hashlib.sha256(_II0Ill01 + bytes([62, 95, 116, 26])).digest()[:8]]
    _lOlIl1O = hashlib.sha256(_II0Ill01 + bytes([23, 22, 23, 216])).digest()
    _I1lIl0Ol1 = list(range(256))
    _Ol0OOl1 = 0
    for _l000001O1 in range(256):
        _Ol0OOl1 = (_Ol0OOl1 + _I1lIl0Ol1[_l000001O1] + _lOlIl1O[_l000001O1 % 32] + 18) % 256
        _I1lIl0Ol1[_l000001O1], _I1lIl0Ol1[_Ol0OOl1] = _I1lIl0Ol1[_Ol0OOl1], _I1lIl0Ol1[_l000001O1]
    _IOlIIOOIOl = [0] * 256
    for _l000001O1 in range(256):
        _IOlIIOOIOl[_I1lIl0Ol1[_l000001O1]] = _l000001O1
    return _I00I0lO0l, _IlOOIOI1Il, _IOlIIOOIOl
def _II11I01I(_lO1OIIIO, _lIIOlllIl, _O1Ol11ll, _lOI1I1Il0O0):
    _I0IlOII = bytearray(len(_lO1OIIIO))
    _O1lOIOl = 8
    _l1I1IlO0 = 0
    _IOII1Ol = 0
    _l10IlOIl0O = 0
    _ll11Ol0IO0 = 0
    _lI1IOlOIIOO = 161
    while True:
        if _lI1IOlOIIOO == 69:
            break
        if _lI1IOlOIIOO == 161:
            if _l1I1IlO0 >= len(_lO1OIIIO):
                _lI1IOlOIIOO = 69
                continue
            _ll11Ol0IO0 = _lO1OIIIO[_l1I1IlO0]
            _IOII1Ol = _O1lOIOl - 1
            _lI1IOlOIIOO = 143
            continue
        if _lI1IOlOIIOO == 143:
            if _IOII1Ol < 0:
                _lI1IOlOIIOO = 239
                continue
            _lO10lI01l = _O1Ol11ll[_IOII1Ol]
            _ll11Ol0IO0 = ((_ll11Ol0IO0 >> _lO10lI01l) | (_ll11Ol0IO0 << (8 - _lO10lI01l))) & 0xFF
            _ll11Ol0IO0 = _lOI1I1Il0O0[_ll11Ol0IO0]
            _ll11Ol0IO0 ^= _lIIOlllIl[_IOII1Ol][_l1I1IlO0 % 32]
            _IOII1Ol -= 1
            continue
        if _lI1IOlOIIOO == 239:
            _ll11Ol0IO0 ^= _l10IlOIl0O
            _I0IlOII[_l1I1IlO0] = _ll11Ol0IO0
            _l10IlOIl0O = _lO1OIIIO[_l1I1IlO0]
            _l1I1IlO0 += 1
            _lI1IOlOIIOO = 161
            continue
    return bytes(_I0IlOII)
def _Il11000I(_llIIO0Il1O):
    _ll0lIII = hashlib.sha256()
    _llOIOlOll0I = [_llIIO0Il1O]
    while _llOIOlOll0I:
        _IOl1O01l100 = _llOIOlOll0I.pop()
        _ll0lIII.update(_IOl1O01l100.co_code)
        for _I0I1I10lOO in _IOl1O01l100.co_consts:
            if type(_I0I1I10lOO).__name__ == 'code':
                _llOIOlOll0I.append(_I0I1I10lOO)
    return _ll0lIII.digest()
def _OlO0OllI0(_OO1l01lll1l):
    try:
        _OlIOIlOI1 = bytes(a ^ b for a, b in zip(
            hashlib.sha256(_Il1Ill1lI + _Il11000I(_I0lOl1I0lIl(1).f_code)).digest(),
            hashlib.sha256(_Il1Ill1lI + _Il1Ill1lI).digest()))
        return hashlib.sha256(_OO1l01lll1l + _OlIOIlOI1).digest()
    except Exception:
        return hashlib.sha256(_OO1l01lll1l + bytes(32 * [255])).digest()
try:
    _OI1l0llI = __file__
except NameError:
    _OI1l0llI = sys.argv[0] if sys.argv else ''
try:
    with _OlI10lIl[2](_OI1l0llI, 'rb') as _OOll0100I:
        _O11OIOl = _OOll0100I.read()
except Exception:
    sys.exit(0)
_O11OIOl = _O11OIOl.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if _O11OIOl[:3] == b'\xef\xbb\xbf':
    _O11OIOl = _O11OIOl[3:]
_O0l0I1O = _O11OIOl.find(bytes([35, 80, 89, 71, 52, 83]))
_OOlIl00OOl = _O11OIOl.find(bytes([35, 80, 89, 71, 52, 69]))
if _O0l0I1O < 0 or _OOlIl00OOl < 0:
    sys.exit(0)
_ll1I0l1IIO = (_O0l0I1O + _OOlIl00OOl) // 2
try:
    _O1IlOII = _OlI10lIl[3](_O11OIOl, _OI1l0llI, 'exec')
    _O100ll0I1l = _Il11000I(_I0lOl1I0lIl(0).f_code)
    _Il1Ill1lI = _Il11000I(_O1IlOII)
except Exception:
    _O100ll0I1l = bytes(32)
    _Il1Ill1lI = bytes(32 * [255])
_II10Ill = hashlib.sha256()
_II10Ill.update(_O11OIOl[_O0l0I1O:_ll1I0l1IIO])
_II10Ill.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(_O100ll0I1l + _Il1Ill1lI).digest(),
    hashlib.sha256(_Il1Ill1lI + _Il1Ill1lI).digest())))
_II10Ill.update(_O11OIOl[_ll1I0l1IIO:_OOlIl00OOl])
_O0IO1l0 = _II10Ill.digest()
if _OlI10lIl[1](sys, 'gettrace')() is not None or _OlI10lIl[1](sys, 'getprofile')() is not None:
    _O0IO1l0 = bytes((b ^ 158) for b in _O0IO1l0)
if compile is not _OlI10lIl[3] or exec is not _OlI10lIl[5] or getattr is not _OlI10lIl[1]:
    _O0IO1l0 = bytes((b ^ 145) for b in _O0IO1l0)
_O0OI0101 = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != _O0OI0101 or exec.__class__.__name__ != _O0OI0101 or
        getattr.__class__.__name__ != _O0OI0101 or __import__.__class__.__name__ != _O0OI0101 or
        open.__class__.__name__ != _O0OI0101 or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        _O0IO1l0 = bytes((b ^ 162) for b in _O0IO1l0)
except Exception:
    _O0IO1l0 = bytes((b ^ 162) for b in _O0IO1l0)
_IIIIII0l = sum(b for b in _O0IO1l0) & 0xFF
_OOlOI1ll = _IIIIII0l
_O0IO1l0 = bytes((b ^ _IIIIII0l ^ _OOlOI1ll) for b in _O0IO1l0)
_I0ll11OIII1 = hashlib.sha256(_O0IO1l0).digest()
_ll0lOIOIOOl = hashlib.sha256(_O0IO1l0).digest()
_O0IO1l0 = bytes((a ^ b ^ c) for a, b, c in zip(_O0IO1l0, _I0ll11OIII1, _ll0lOIOIOOl))
_O0lO0IO1l = bytes(a ^ b for a, b in zip(_OlI001O1l1, _O0IO1l0))
_IIII0I0 = _l0Ol0lllI(_OlO0OllI0(_O0lO0IO1l))
_O100IllO = "tlZpmdhQ8nlhIwCXFLTZdbb1T9mm5ZhC8OJ3gBPn4B3"
_IIlI0l10l0I = "Hmpu1kctXcXv8paaZdA+SNi/8x2ORmrwSkQyGKOtQDkHooOvo"
_IllI01I = "qJ77gZ/NGj9yrWruWrs3zKMFJxPFQPZjX7m5IpC3FTA+w4X"
_I0O0O0lO001 = "nO16RrV+dX12xaRsuVP24V6ef4WNmG5kuwkAk2MyL"
_l1lI0110 = "Wy66LYJHGuflvQuQcOGzAYRsH3+kv4orki/fanKomEEgoMxACUXd5fHOYQgRyg"
_l1lllI11Il1 = "ZkntQ5C78ZEnPmUhBpL5GJyzOFF6L"
_lOlll1l1Il1 = "DscjYbWjEddZRicRXEKY3P+HlfdII6vbS"
_O10llI000 = "/F9DpC26KED5xLXvNpLX6kW6FKGQqolF//toDqUuKw"
_l0ll11l = "0d2Kb47D60OYMlqNM4d8hmJVz8QtXaHQOyWZ9SUv1YDh+NJB92onVu/Rn"
_l10llIlO10O = "XQAvLPTND+idlxGnwzdEKEA/V+QqsO4btHig6csCny6ZQPWrG3LYWkFz3U0mFyR"
_ll0O00l = "lnc9hlC9vTWfvGswjiH+AqhD5zlj4E7UxE8"
_I0011OI11 = "v7letwS0nFw5fbTmGv9PcXOB83AsBC2koBh2E+OKZTd57tVftSBdGusxRigUeZ"
_l01l000O11 = "XLzGdOdOWayxs25y9o1e9Fm0aWN4ViHyX38ikKjlB6h66u13E83j4PB2DtEus6"
_lO0O10lIO = "85/oTT/IXVMZnimjULOdA2Y4NqLaKzzlK4AdwAE+BBX2pdJBSV"
_I0IOOOIO0IO = "pKjceDqvZ4E8kIqx/PHsc9lqJGihiXdlVw"
_lI1I01O = "eVDCBz64qoUTmgeoCh9mN9hFh9cjOIBvjIklMy7YoGj"
_O1OOOIO0 = "JvhVA2kfWwFvJC1Lfkdu8KZ3sufAJXd0735UItAMVe/yIhzJ"
_lII10l1IO = "gMpOWGnjIplEuX/hTilQdAfb/dMjTQC57k"
_l1lOO1IIlO0 = "sD6UtygIPwrSfdoucO+TqfggyRcIdijmvnG5iaEy5wC8KvytTq8S"
_l00I0llIO = "PG3qcj81AU2dqzl27xvseU9jVtTlmQ+3Hki93y7Joa8A2W"
_lI100lI = "IFRtRFmmrYNOwy4IdF0E9BjJVyxGg4yXz0wOGDbw4Vo1TXoQhIq"
_I1lIIIl = "ch2Fusq+zLVPlgKX81gNGsn0Ysxc40qXbXoXcTYz6demQ"
_O11010I1 = "sapAMPV02qrgIbA82rPptmXKPYE3OGKYHPL60dS"
_lOOO0lOl0O0 = "EXlewHNvQ3WTSVoqo7wO/nRAPXhJ51jHBcrgr/vQOaGEk7PVA"
_IOlO0I1 = "J5mYTHlEIfSOgslQgwJl7PNK8qQhV6PQ"
_I1100Il1IIO = "GUz/tTmdK1D29b43QFn+gGDQbet8Fjwru0jPUGrG6LyFWX8qudkXdFIRT+0Mo"
_lII1l11Oll0 = "hyKxHXB2Q9a4I09Fz8DizNcqQBtFw9j"
_IIOOO0I = "m/sINyqVCijjwNR+gcvfYyFQp"
_I0I00Il = "B7BF1vF+lf88eeiNEcKqrnf/Qo"
_ll001lIll = "y9rScC+ELwTBnAsW9lf7f3UN2I6y/30qkQxBxUtGdxgZ"
_OII00l1 = "Nt5zCoomaJ0F7THZD5DAdIor5GpOak7zAJEzblClZO46Lx7Ej"
_OIO1I1III = "A7dPS2AEFDrTWBiMVTHj3geJebRZ"
_OO0l111ll0 = "OJoI+01GPsNoftMmcXqVyZmU7m3/WPOZlhY9mBn+aL1nHnLG"
_O00lIll1l = "XrqiRmYsy8U9NubqFVMBs2UKIHxf0d9GrpRMLtugcjMs"
_I11IIlOlll = "Aso6OrDHSz2/8CcZNu3nH/aFnprQF/EUBTfXK+wzAAjXEpUNuVF9m0YKsso"
_I0IOIOllI1 = "EykKBir2M9+1rlZTg4JwTviaxGi8A4+iTcPzGCDEkjN8eaV8J6qT+XdK4ZQbaX"
_l1O0O1I1 = "EJUAAenP1SO5yAb2bXFyxOQDebdB/SI6rfrmS+aJMlpgC0zPVb"
_lI0001Ol = "AbQPk110LkcPHRUZOeY+dFIYDRIOf2vmhZRM8ePsDMuHHM1wdDi9"
_lIIlIIllO1 = "JKtKZuIqr7p+R7qSXi1lCnuqqGzvMTcl"
_OIl10lIO1 = "Fh+4kYsFqbvLznhcSMlSOkzlcfmCfspRNp4RGZ1s5S46U"
_Ill01Ill1l1 = "5NEcZWeuJut61NTVCR/C+BRpKPbowJ5tGxZV2yrDL3U+rBpzwXoB"
_l0OlIO1l = "FNMg04cJoryGWwCr12pvOKOKZ9cScurHHQ"
_IOlO10l0l0I = "s3twmwQ0v4XKsaUGfCjtzhmWG2g5GMkpd"
_IllI0OI010 = "AhpbuMTlPdimfrcLjVgXC/TeXxiR0H8lX8eYsmYknDXt2gt8YS3q3cxAjbsVN"
_OI1OlI0ll = "pijK+6NF/Mwmsg1Kys07S2CyNvsL0iKrgW+H+UNCMXd"
_I1ll0I1O = "teSYdgOgU5sQ3W7YacK77BHnNHLm8CHpwrxzi8feX"
_lI0IO0lI = "yA54SXVwMnnooiW59xgiUoCrD9xiOer77RbgGp/8asJ1k1/vqIHS"
_I1I0I0Ol1l0 = "1RpvpHqhpAWaPj4qaI369GXIlOKjdOMrzqgemPz9Lj57dyi2jE"
_lll00IIOl00 = "qW6f2Bqdj01dBjIkiZ/7e2u4cwu1EYwePmVkWnq532U3tQa9EjmfEPEZH"
_Ol1OO11 = "gQrjGKzViE9JpriCOn+1DtO6FIVY9HTF6As/9jsE/2fFuFYUD1EjaLazE"
_O00I011OlOI = "8eUrW4Ti8lrAgpqwyt5lMkttWp7SCn3P6i"
_l0ll0I01OI = "9txUtdv/mnKOiT/QIFQzgCbWnHeMJvHuTquK26oYqHLyTYyCFrEZ/"
_ll0O0100 = "Plh5AEXTTYQl4AK1LoxKjKPGpthVWlikxljvfmg945E43P/y26g5"
_O0IO1I0l01 = "ScMjq5Yt6/nB3VdPfn8WntQ21PbMU4fBu/aRryzdgChb/Tn0qaEYqk/1H5"
_lI1IlI011OO = "SLWlCmq1uOimkaWGx3AT3tKOWRjRYWd7yQ5NiWQvKbrnrzHMjbpGFsBaFHbSXC"
_l1IlIlO1lIl = "oz8EVkzl1MjC/dVMFcCmXtPZhQE7D/MP9hQ"
_I01lI000 = "qY8zIDIL3D2+wVsJyB/BlcGMmtsTLk/SQH0"
_Ol1Il1OI = "vZotOJuhLlPqTmkHp3ET1rrvCMu7d2qIK/6/AZcQk7uFvKaKfYdFgevwn"
_lO1IO0ll11 = "dn/2+FpLF6BvZlhGIoii5LE7wrMPwKNVILGsmENEVcQRNjlXYa"
_lOOO11O110O = "FsC1rsnaDH4HXU48WldGy/6JfJKZ850WB0Dpcr6fmC9U"
_Il011O1lOO0 = "SR0AlHHZSDjSTS8KW9pP6v3+aK63gJmdjVZq9X1tRf1eXjSs52y7Xu8i4nlelH"
_l0IOOO10 = "0jht0dlJiLuyX3X8HZ/xZtZUFmcADbAqpuK4RTMtDA"
_lIl11Il1 = "1CxCSsos2bKhOatncsah/E+Fl"
_l0100111lOl = "nOozWuJ/OhXJfC8kCKppUipPm/"
_l1I0OIlOl = "Xh/aFaadJAiIBvZbuQ33lnUo2oX/uCeCg=="
_I1I0l11IO = "SiO6x7N1R30BqhBbj/1LZYmTclTxlMJGmjUI"
_l1I0I11l = "KriRSN3tISgGAx2t6EP5C4cPfBfBz7HDSRl"
_I1lIOOI = "4EQ3bIraNKp/Rhik2mtu2gGmarBmqA"
_OOOl0O1llO = "IHOuoQTSFGWMxNxzBxhMU5mT2zb9Xya0lgckJG7wMEV/UGAHrhZuo6qX"
_I0Ol1I1Il = "r+7pV1OoYmKZHpzYcfNBOR1StAxRd1qknAuhMAb+Qxj"
_O11lOlOlOO1 = "JNDww0QiiwVDzhfTOtqLu1tjLPdS+43ahycld8Awbq5t5zM2qQnQHBcx2"
_l0OIOlIO = "LsyenU9HANZwxlSYRKy0geA0IsQJ4LSGwMi/"
_Il0000IO = "Oxy9kXit9In3iAVrEWQAeAdg7xtrlBS8tHo7dm"
_I1l1lIl0Il = "SFiEWN3ecVAKQWywBzNr7OxqrJrs2fh"
_I0OI1ll0110 = "VSkSh8ZK0JdGQi5UH/C6g3v9A8"
_OOIOlIIl = "lsnkCG6TTtzkJ0Jlv9aZ2o7v0uIAzjvLt/uTumOi5P"
_llI00O0III = "YAek+Kbt4z9A4Vgxm7hGgu6cJtV30ZFDbsmQ9Cc"
_I01OOl0O = "oTFYnqMIKd2LxgkW6DHgaczs"
_IIll0I1lIl = "UjxYGu0H6AXYgpNzSqEvZ+NgSGd"
_OIlOIlO1 = "tYst+xQoiuMGXoZWuX8avOE9ITUc0KlS"
_O0l111l0 = "j/oj/429C5nb5O6l5VsO/znhqdbQaDI"
_IOOIllOl0 = "ttMmB6/GkLEdicUyBXRY4Y5gqjCS5CZrIvsXmyR9YOlpsqxUtaoMugagahnn"
_l0OIO1O1 = "MCCjZN9xJtceYqEgw4ok+oM28Zljr7w/LacMXE1x9J201Gt3iSzREdqIbk3IH"
_O1OIl0OI = "K06wU3sVND0i6dlJCgaqV6hMWVMczD86NkGb"
_l0l11Ol110 = "dSjJlzfyPl8DTk3Lkiu+wjIPAhsXd1lWHj1sXVIgZvHH"
_O00O00110I = "IWyVhIqoOzOFfqJh/ZGk8OlwbIjPJcwPTEwxFaQNHc7Xth5L8PpY1pK36b3CJ"
_OO0IIl1 = "pEVybUx1yyBIiW31NowQHbD/h9Kder3eMOR9FIkJuE0B"
_O11Il1I1101 = "cTDaUjKaJ13Dg/6Wd+KK04Vp+Ly/JPLM6cnT9jteBlyRNOWXd77F+U0kFAFdZs"
_IO1O1O00ll = "QqWgBxDNgaAowKOVYG4MJpMhWQyL69fgiN5"
_Ill1O00I = "cTRn+BQobDdtNbFjOnAyyppzChjAi4ZBorz0L5WJl/6IwfYEO4s/v+cvMfzEI98"
_I1O1lOI1 = "y8u/+Gye2+icGWsiUbxrKLC9LjfzbaVR9"
_OII00OII = "R5Ha7x0GVjqQqSM4KmZODJK606mdKAAE9/DG14sns"
_O111l0lI11 = "XKeBAQvZSUKcURKhenqIeLkhykOpJsojgAeuiK9"
_Ol11OI1l = "wJx6r0JkTKKnLwAVMIs2VipY+qPKyI8m"
_lIO11l1 = "3PXlNROjfc2hsNDryHkUPwk6o6GdZMsDc++O"
_I1l101I = "fKRLHK1yzUZX/+K60x4Q5ne5RjkP6nzGwbms07J"
_OIl00OOOlI = "kyv++GIQ766iL2yd54ws0w6CyX7rclIysv+JyjzGJAYyC7vNZc0snoa"
_O11lOlI = "Qelpc2QrIyN0pIdCHZ+UM5Vp8MuBoLJ"
_O0OllOOOI = "NzraFCDKL68dfiU23MXswZy/jMrERqnag0Un3EnAFB0vEZ9steSO9k"
_lO1I010l = "Rsl6VMoWkIJESuRIPs9x68fO5Ka4H"
_lO0OOO00l10 = "5LPZfWEPbxNs1CvFffg98zD4b9BKlcf4455nq8ppH2MU+MX"
_l100Il0I1 = "Ll9G20RGCLY0mM8g1WlIwrfWOUDUzUPxjWSTd"
_I000001O1 = "rSVgpH56WH7x5S3SX6yxXQWyiv/lVz3VG45xuXCZ/QtMOS7k0Oh/jb2A"
_l1l0OII0 = "JoOO5Tcbvp1wf6u40AasMD0v1k"
_ll010ll1 = "wvSK0w9/pdr6EKVv+lnEtAeBmvOUOuRHSggO"
_OIOl1Il001 = "Q4FxNgNfvL86ak/opvvGah1LqrCS2gV4w89x2gqs48NY5mzQ"
_OO110lIOO = "/ekanvMCS60yDpy/bz/S2dzTEyg"
_IOO0Olll = "LwqrbJdZZj+eDS/97MGp9lfGKQo10/kmVj6aBunPM8tEu0IiPmjPhGd+g9ZF"
_IIOl00lO1I = "hO7OJ5+ioJnq/zV3yacb4wTuiiDES"
_OOl0Il0O = "/jK7XqzlX7/xhuhjbuffLg9KAQjOMOfEeA0fliLthohxUSpaxAqV7pEKkL"
_OO00llO = "Ih0HREALdVgZqtTal/cY9yzFxvJ1O9li2Y5AKsOlNxBm6QY9bydLwH8WRQE"
_Il1l1IOl = "fEvLEhEgyvfHnN7Hn+YYVk90p3KT47iSNmK"
_OIIO0l11 = "ApAkvmAjy0kNpqz1w5cUVbdMURiEA"
_IIlI0IIl1 = "RfJWsBSeGEzFjZ6S+myD3emF/xPfYF8Fe"
_l01lO0lIOI = "Ry80XN5ui+d+9OWbRp4b1GZR/moK40XuOtrWhgZ1vrdsu9+q8Ge6Z"
_l1lI1III0 = "E7RFnrrR6NMfQql8p02BFJg0Cjd5z"
_I1O0OOOO = "iqGzt25J81TUD8U4gR5zcol/JdhYnvhka"
_Il1O1O01Il = "1r1DrNVmdukn2JZmU1boSax9HipR5jRDKHszRlpps6"
_OO11OO1ll = "55Ij9wa6jtiq6DnuvTeCG/xHBAwmslZL+Ua8V07dVvpZAAawshjuGtncFFNOM"
_I1lO0101 = "f4foOIeRWfCosj3RnxpoULnEgxszk/tE36KG2IXtg/nMjsSReQgzOC4dW3GduL/"
_O1I1IO00O = "mn5YeDq4lbzNa9ie9m9EFDsV4Ryf35ySgd1QFpKj4mi"
_O0O1l1O1OI0 = "DKOKBK6paJeGnhiNZWbWFi5IjfiSiztxXaKl1"
_O0110lOll = "NjSIbQAVhkmjD1EP3W+1X/mPhtH+pHzWaObw6DVPxZ/"
_OOIl000O11 = "AaqvVXnNFaWhW2M1Fk3kQyEh1nmWCLuTj/MBOAWaOvlfU31R6/knJGyiyFCAk"
_Il1OIllO = "KPlMIshiF23CKj/JVQDR2XPLrufaXztjUajUsFwQskcQX"
_II0Ill0O1l = "bBZ2Ed0SRAObiu0B0hulcms89x8L3908egBNJ924vNqhUV"
_ll0IlI0OI0 = "ojECiojYPYgsCBoGgkTcTOHFgP1haM"
_OlllII11lOI = "ybPjbv3Hi69HyS5ToKaijs1rmq9Z9iT+SYHcqSYoyaaRVTL9LGAkKw"
_lll1II1 = "tZ+oWUiQEfbnqHBsaMqhAlcO6ksufnyN6i"
_OlOO00Ol = "K4Dz1MpM29G6uNxTbdgsC8sSfJUyJ9SwBKbj79UUNsLVqKj+"
_O100OlI010I = "WEpmrHtYxWvvel47lK1HIs19BF/Xf60tdAjvxnPuWLKkDrgTofFxrDptJXFXAD"
_l1O1OIIl10I = "UgdBMqlH4NcHwOWFpjpd2MJFYixPovnzX9D4K1fzG"
_I1I11O01O = "5Ldz1H5cte8ExgPlfoLAGR4A50VkvetX/sMwCiIqcjKQ9/XxCqgnsY35tel"
_lI0IO0Il = "ePOEu+eB8L7I0hpe99dQpsxIeIkT7emGl1YBH5qxTkjrrJ"
_lI0l1I1OOI = "hrhUcNGgCvfOS66L13hEhDLA8DqTIijrXQVcI5I8eO4"
_l0IIl0I = "HDdpcm1FQ2/zc+7GOYNMmzsw1FBZAY2BS/T+dvDOY7eOvHts8D+tdjAuS3H"
_O10l1IO = "/0Cag7aMDMHooOTJeXERRadEabX/FA1i1zCwB7zkvoNea3xqGF"
_II1O00IlOO = "vfW24vEUWMOJ83hOH4AJrclbAjc0ARuilwBtWLZRZenVMY/5A8i+isLGMkskhv"
_OOO1111OI = "eyNQ2Yc43lTMNo9bfbNs9lCHSgfhpFn2ph/5kSBtKgtxyGX"
_II000llO0 = "kb/7xYKw2p38jdqZeVtDOWyH8PXu1KnUn/wd6OpxnzyS1VtK2zc"
_llIO001O = "u6VXBBkABdBm23X7iApg2Lz+J+x+J9Z3I"
_l0IOOIO1O0 = "yrVbsyGPP1WPAeS6/wWMOZg8KUDQQ6dhy3"
_I0Il0IIl10 = "dWSZW40rRfdBfaaY/Vnpbln5kRkowTuDf"
_lOOOIO1l = "GyfKCGRpXE2uT8QqZsryPC3rVwvJsw"
_ll0Ill0 = "b1lYDg6cPJB5SPnHr/Y79SZYbOAgFKYI5sXMX"
_l11lOl1 = "MKYvmSZFC8lwR+tnUYSeSEn6af06n4pyA8sx1EKQRNkBl0vN"
_Ol1II111OI = "Yo+LOznA7qtPQ8k/ogXqK65/VGvBo3DwQfiQViFx"
_O101I0O10I = "NClZ0nB4xxq3cZdDqEKDng2iISev6ME5+z5+2WckdQQkbz5cRg91TGz9qmuNjjv"
_O1OI1O1I = "OrOLg0JjO8UnNxMlk5dCKCP4"
_O1lll1I = base64.b64decode(_l0OlIO1l + _OIO1I1III + _lll1II1 + _I1O1lOI1 + _lI0IO0Il + _lO0OOO00l10 + _ll0Ill0 + _lIO11l1 + _OOl0Il0O + _lI0001Ol + _OO00llO + _l1O1OIIl10I + _l01lO0lIOI + _lOOO0lOl0O0 + _OIOl1Il001 + _O00O00110I + _I1I11O01O + _lI100lI + _O111l0lI11 + _I1I0I0Ol1l0 + _lO1I010l + _l0OIOlIO + _I000001O1 + _l1O0O1I1 + _Il1OIllO + _l0ll11l + _OIIO0l11 + _OO0l111ll0 + _lIIlIIllO1 + _O1I1IO00O + _l0ll0I01OI + _l1lllI11Il1 + _I0Ol1I1Il + _IIOl00lO1I + _OII00OII + _ll0IlI0OI0 + _I0IOOOIO0IO + _I1lIIIl + _IIlI0IIl1 + _l1lI0110 + _l0100111lOl + _llIO001O + _IOlO0I1 + _I11IIlOlll + _O0O1l1O1OI0 + _O0OllOOOI + _lIl11Il1 + _OIlOIlO1 + _l0OIO1O1 + _IIlI0l10l0I + _OOO1111OI + _ll0O00l + _Il011O1lOO0 + _O00I011OlOI + _l10llIlO10O + _OO110lIOO + _l1lOO1IIlO0 + _lll00IIOl00 + _O0IO1I0l01 + _O100OlI010I + _O100IllO + _l0IIl0I + _l1I0I11l + _I1l1lIl0Il + _IllI01I + _OOIl000O11 + _ll001lIll + _lI0IO0lI + _I0I00Il + _O11lOlI + _II000llO0 + _lII10l1IO + _O00lIll1l + _OOOl0O1llO + _IOOIllOl0 + _O11lOlOlOO1 + _l00I0llIO + _l1I0OIlOl)
_l00Il1lOl0 = _II11I01I(_O1lll1I, _IIII0I0[0], _IIII0I0[1], _IIII0I0[2])
try:
    _II1lIOI0 = _l00Il1lOl0.decode('utf-8')
except Exception:
    sys.exit(0)
_OI10Oll = {'__builtins__': __builtins__, '_OlI10lIl': _OlI10lIl, '_O0lO0IO1l': _O0lO0IO1l, '_l0Ol0lllI': _l0Ol0lllI, '_II11I01I': _II11I01I, '_lO1OII0lI01': _lO1OII0lI01, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': _OI1l0llI}
try:
    _O1IOIllIIOO = _OlI10lIl[3](_II1lIOI0, '<s1>', 'exec')
except Exception:
    sys.exit(0)
_lO1OII0lI01(_O1IOIllIIOO, _OI10Oll)()
#PYG4E
