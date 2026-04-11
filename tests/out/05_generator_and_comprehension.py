#!/usr/bin/env python3
# Protected by PyGuard v4 (pyguard.akean.dev)
_OOO0lO0 = bytes([214, 43, 162, 25, 49, 28, 105, 43, 57, 114, 108, 23, 40, 242, 124, 186, 123, 21, 60, 145, 196, 10, 196, 56, 44, 201, 244, 52, 133, 220, 190, 239])
_I0I1Ol0l = bytes([62, 37, 225, 174, 233, 224, 202, 168, 88, 204, 57, 104, 47, 252, 15, 96, 145, 2, 85, 58, 222, 140, 200, 13, 245, 32, 58, 5, 142, 207, 163, 51])
_Il11I0OlOl0 = bytes([159, 112, 178, 121, 218, 137, 208, 121, 193, 132, 240, 193, 21, 33, 92, 235, 125, 242, 10, 174, 221, 215, 76, 3, 242, 23, 118, 242, 152, 218, 156, 214])
_lOl1I0OI1 = bytes([71, 220, 142, 76, 123, 246, 94, 5, 116, 80, 215, 128, 8, 36, 41, 114, 194, 206, 252, 160, 165, 102, 49, 108, 207, 191, 153, 2, 110, 40, 31, 150])
_I1OO0Ol = bytes([239, 163, 116, 248, 106, 123, 164, 241, 40, 106, 47, 74, 233, 16, 99, 98, 80, 56, 124, 17, 206, 243, 220, 168, 153, 152, 66, 205, 72, 42, 249, 53])
_lO0OO110lO = bytes([98, 18, 187, 210, 170, 59, 8, 11, 152, 123, 29, 107, 158, 103, 18, 223, 54, 251, 4, 6, 145, 39, 98, 233, 54, 234, 241, 108, 181, 207, 102, 146])
#PYG4S
import sys, hashlib, base64
_OO0lOII1 = type(lambda: 0)
_I10100O = (exec, compile, type, getattr, __import__, open)
_lOOIO0OO0 = _I10100O[3](sys, '_getf' + 'rame')
_O01lI0II0I0 = bytes([150, 134, 203, 64, 245, 235, 131, 95, 224, 94, 45, 153, 179, 152, 155, 85, 163, 32, 118, 77, 227, 28, 39, 142, 165, 110, 82, 78, 108, 48, 89, 48])
_OIl1Oll = hashlib.sha256(_O01lI0II0I0).digest()
_IllOlO10ll0 = hashlib.sha256(bytes([176, 147, 63, 68, 150, 40, 213, 71, 72, 165, 122, 165, 3, 161, 51, 68, 196, 73, 20, 72, 110, 172, 170, 145, 165, 194, 75, 13, 174, 166, 197, 238])).digest()
_lIOlll00I1l = hashlib.sha256(_OIl1Oll + _O01lI0II0I0).digest()
_I001lll011 = hashlib.sha256(_IllOlO10ll0 + bytes([243, 232, 100, 170, 6, 42, 124, 142, 58, 205, 129, 32, 119, 41, 197, 197])).digest()
_III1OOlO = hashlib.sha256(_lIOlll00I1l + _OIl1Oll).digest()
_Ol0llI110 = hashlib.sha256(_I001lll011 + _IllOlO10ll0).digest()
_O011Oll0 = _III1OOlO
def _Ol1ll011(_l0Il1O1I1I):
    _l0Il1O1I1I = bytes(a ^ b for a, b in zip(_l0Il1O1I1I, _O011Oll0))
    _O01I1I01100 = []
    _O11lOIOIlOO = _l0Il1O1I1I
    for _ in range(8):
        _O11lOIOIlOO = hashlib.sha256(_O11lOIOIlOO + bytes([200, 171, 62, 127])).digest()
        _O01I1I01100.append(_O11lOIOIlOO)
    _OO0lO1lI1 = [(b % 5) + 1 for b in hashlib.sha256(_l0Il1O1I1I + bytes([123, 241, 177, 34])).digest()[:8]]
    _OO1I1111 = hashlib.sha256(_l0Il1O1I1I + bytes([170, 120, 29, 92])).digest()
    _l0IlO1I = list(range(256))
    _O1l1I0l = 0
    for _IO1IO0Ol in range(256):
        _O1l1I0l = (_O1l1I0l + _l0IlO1I[_IO1IO0Ol] + _OO1I1111[_IO1IO0Ol % 32] + 74) % 256
        _l0IlO1I[_IO1IO0Ol], _l0IlO1I[_O1l1I0l] = _l0IlO1I[_O1l1I0l], _l0IlO1I[_IO1IO0Ol]
    _I000O1I0I = [0] * 256
    for _IO1IO0Ol in range(256):
        _I000O1I0I[_l0IlO1I[_IO1IO0Ol]] = _IO1IO0Ol
    return _O01I1I01100, _OO0lO1lI1, _I000O1I0I
def _O0I10I0(_OI001I1Ol, _IOlO00IO0, _l010OOO0, _I10lll00I):
    _OIlOOl0I = bytearray(len(_OI001I1Ol))
    _l0lI0I1lIIl = 8
    _IO011OIO = 0
    _I0IIOllIl = 0
    _OllIl0I = 0
    _III0I11 = 0
    _Il00IO0l1 = 233
    while True:
        if _Il00IO0l1 == 86:
            break
        if _Il00IO0l1 == 233:
            if _IO011OIO >= len(_OI001I1Ol):
                _Il00IO0l1 = 86
                continue
            _III0I11 = _OI001I1Ol[_IO011OIO]
            _I0IIOllIl = _l0lI0I1lIIl - 1
            _Il00IO0l1 = 228
            continue
        if _Il00IO0l1 == 228:
            if _I0IIOllIl < 0:
                _Il00IO0l1 = 78
                continue
            _l110OIOI10 = _l010OOO0[_I0IIOllIl]
            _III0I11 = ((_III0I11 >> _l110OIOI10) | (_III0I11 << (8 - _l110OIOI10))) & 0xFF
            _III0I11 = _I10lll00I[_III0I11]
            _III0I11 ^= _IOlO00IO0[_I0IIOllIl][_IO011OIO % 32]
            _I0IIOllIl -= 1
            continue
        if _Il00IO0l1 == 78:
            _III0I11 ^= _OllIl0I
            _OIlOOl0I[_IO011OIO] = _III0I11
            _OllIl0I = _OI001I1Ol[_IO011OIO]
            _IO011OIO += 1
            _Il00IO0l1 = 233
            continue
    return bytes(_OIlOOl0I)
def _O0lIIO0I00(_O01IOOllI):
    _l10OOI1IlOI = hashlib.sha256()
    _I0lI00lO = [_O01IOOllI]
    while _I0lI00lO:
        _O01lI01l0 = _I0lI00lO.pop()
        _l10OOI1IlOI.update(_O01lI01l0.co_code)
        for _I10IOOIl01O in _O01lI01l0.co_consts:
            if type(_I10IOOIl01O).__name__ == 'code':
                _I0lI00lO.append(_I10IOOIl01O)
    return _l10OOI1IlOI.digest()
def _O01II00(_l1lOl11):
    try:
        _l0l11II01 = bytes(a ^ b for a, b in zip(
            hashlib.sha256(_OO0lll0lI + _O0lIIO0I00(_lOOIO0OO0(1).f_code)).digest(),
            hashlib.sha256(_OO0lll0lI + _OO0lll0lI).digest()))
        return hashlib.sha256(_l1lOl11 + _l0l11II01).digest()
    except Exception:
        return hashlib.sha256(_l1lOl11 + bytes(32 * [255])).digest()
try:
    _lII101Ol0 = __file__
except NameError:
    _lII101Ol0 = sys.argv[0] if sys.argv else ''
try:
    with _I10100O[5](_lII101Ol0, 'rb') as _I0OOII0O:
        _O1lOO1lO = _I0OOII0O.read()
except Exception:
    sys.exit(0)
_O1lOO1lO = _O1lOO1lO.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
if _O1lOO1lO[:3] == b'\xef\xbb\xbf':
    _O1lOO1lO = _O1lOO1lO[3:]
_OlI101010 = _O1lOO1lO.find(bytes([35, 80, 89, 71, 52, 83]))
_I010I100I1l = _O1lOO1lO.find(bytes([35, 80, 89, 71, 52, 69]))
if _OlI101010 < 0 or _I010I100I1l < 0:
    sys.exit(0)
_l1IIlOlO1 = (_OlI101010 + _I010I100I1l) // 2
try:
    _lOl1llIl = _I10100O[1](_O1lOO1lO, _lII101Ol0, 'exec')
    _O011IlOO01 = _O0lIIO0I00(_lOOIO0OO0(0).f_code)
    _OO0lll0lI = _O0lIIO0I00(_lOl1llIl)
except Exception:
    _O011IlOO01 = bytes(32)
    _OO0lll0lI = bytes(32 * [255])
_OIOIOl0100 = hashlib.sha256()
_OIOIOl0100.update(_O1lOO1lO[_OlI101010:_l1IIlOlO1])
_OIOIOl0100.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(_O011IlOO01 + _OO0lll0lI).digest(),
    hashlib.sha256(_OO0lll0lI + _OO0lll0lI).digest())))
_OIOIOl0100.update(_O1lOO1lO[_l1IIlOlO1:_I010I100I1l])
_IIlll100 = _OIOIOl0100.digest()
if _I10100O[3](sys, 'gettrace')() is not None or _I10100O[3](sys, 'getprofile')() is not None:
    _IIlll100 = bytes((b ^ 163) for b in _IIlll100)
if compile is not _I10100O[1] or exec is not _I10100O[0] or getattr is not _I10100O[3]:
    _IIlll100 = bytes((b ^ 90) for b in _IIlll100)
_ll1lOIl = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != _ll1lOIl or exec.__class__.__name__ != _ll1lOIl or
        getattr.__class__.__name__ != _ll1lOIl or __import__.__class__.__name__ != _ll1lOIl or
        open.__class__.__name__ != _ll1lOIl or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        _IIlll100 = bytes((b ^ 106) for b in _IIlll100)
except Exception:
    _IIlll100 = bytes((b ^ 106) for b in _IIlll100)
_l0OI11100lO = sum(b for b in _IIlll100) & 0xFF
_IlOO1Ol1 = _l0OI11100lO
_IIlll100 = bytes((b ^ _l0OI11100lO ^ _IlOO1Ol1) for b in _IIlll100)
_OO0llI0O = hashlib.sha256(_IIlll100).digest()
_IO01I000Il = hashlib.sha256(_IIlll100).digest()
_IIlll100 = bytes((a ^ b ^ c) for a, b, c in zip(_IIlll100, _OO0llI0O, _IO01I000Il))
_O01011O1 = bytes(a ^ b for a, b in zip(_lO0OO110lO, _IIlll100))
_lOI00I1II = _Ol1ll011(_O01II00(_O01011O1))
_OlOll1OOl = "0FsS3Cyg7140dcKdyKoVoiLA"
_l1ll0lOllO = "HFotXAx1Kd51fb1320LIIJyzHNeCy3ukkeK"
_lOl0O1I = "zR7wdBQ1TDffJxsrhWfNe/SowkMQnaHxrgERF9c6so96H02qAAsa"
_l10l010O110 = "rN4J6keEBWq2BA9LfTCGPGJNk4dYEtC5azLVL+ZCSRgjYDwxyYyq5xMibGbUecH"
_llOO0OlI = "9znPB4B5R8U3TD7zRMOR+igR2pof+ITUT+n"
_llI0011 = "elYmZGP/SHoHOcd8KT/1MoPJTgZuZXGU83Ls2MEbOx47sEpfUl3aaSL3Zi4ECQV"
_IIIO1lI = "tq3dmkYjdwlEpz6L35DaB5XsKgZgZKzq92skCzklFSvduRy5jneaF1Hy1o1o1u"
_O1OI00O1OO0 = "vLaAglaSUP+Pa51DPhTqbvfwGK4DotH4EZTSoj4ks1yiTydSWxlULeLSk1H2oG"
_l101I0Ol00 = "SMqhjl7xEKwmtRaScHOy0ZGpo0+ZBL6XJVg3/vykJmDV113hdygPpMHGek8"
_l011O00Il0 = "Ydfa4+XtuEoxitfzqz0H49fUpEDEYS9P/7cH9L8PQPq"
_OIO11lIO = "B5f3FGsm3UM+nsVrkNeLGLZ4MR5xAM6gKv0Ag"
_Ollll011lI = "q9s+I751w7aYqcJmveqkpY3ZOvZA/s3PmFtX0wjefc+8YG5gsLJ5MOJIOyvmi"
_IOI01Il11I = "3GQT3hH/5hQyd4dd/W3IGFOISwMUREqIa4kQU0Ok8EBR7XWIgYenCWtf1"
_IlII11Il0O = "X0B+QSyz4tP62wAnxaijTXtRFKIWgPEkhX6v+ZcHEa2/c1bTfm+n2tX3RJYs+"
_II0OI0Il0 = "MhNhn2v3sbEi/wjj44oj2Q+I4lD8coVC+YjvAcB8XepO"
_I0I110Il = "VoMIGY5yxPdb7rBZj4Jbl7pxeZLatUfV"
_O1O00IIO1O = "L4cDYW7k/22RkBUi6XEGWQuQ689aOjw26wuS/Gd3wF2klvsvmOZhIZiThxZTJ"
_lO0O1II1O = "IRku1MBXeuyDruldZlBomUlSCg2RpuUpA1i0Y7/qqT07D3nA2C1IBFAXLPljkn"
_lIllO010I = "d6E3Es6lCwPToD2Djr9eZ5uHxyaU6tgQN8kslZBsiOeizAGelMy2Qi5k3AtI"
_lIIOIO1l1 = "rs3Z1p79kCxDmj7AYBntliPJTVUkjMzrZMBuzv3oZtcUvgtcdZ"
_l11I10l1II = "5BbLA9a5PJ4b4Pm7XhSv4TauSfawPrTV"
_OIIl1OlIIl0 = "D3tJPyX/E788XsolnMp+DAUNJ"
_l1011OI1 = "Jq3nbovlyAazI3ps0ARN1pwzHm4Ii/O1oLRX/i3BS"
_ll100O0III = "s6NrES3GDJcDlHH+oa/tUtdE1yvkmp9uKRu"
_I0I11OOO1 = "Yf/aul2zRBWHh0xtxykY6rnY2YjmS6DrGtK6Xk5Tu"
_OI01I0O0 = "7npW8eHRlwSjvbzl4Brc1VAfp7rOicPll"
_II1IIl0I0 = "fW2C4g903SAndrDRRDQkvJ93TUvBg+v7EcewHY1i+Q0k"
_II1IO0I = "rpe95jpyDvH3t+pP2c8tNwCp8GBY2YBtonn3OEfGnjyJBdCmx+rVzO"
_Ill01OI0 = "NF/1JuPsVHmnIjQQLIeLK38xM8kZyI"
_lIl11OlII = "vpga97FNAxu99cwS/JCfr0+DAls1pHxKGSrh"
_O10O0O10I = "vah3U0VByNhdAnax/l3MImEug0dTo5pEQDH7810UZ/LvRYEkP1l//"
_I1IIllI = "FAqM+7JYCc8FnBRs2muGq0NSa25mZZQvP9gMVHiraFo2VE4P4"
_lO1100Oll = "/8tAMMv5VEypqiNPkYtEFVbZ/8eVQY/CmxpCqXPWr"
_I1II1OIl = "x0yf3lWzBvIqynMWnqTEjFlL39emNySnFJlcnc8Y266JIqbG4YKbyv"
_lO011IO = "9Ch0objsp1rY6A3TUXvF/Gv/KAwlRR"
_l1lOO10 = "kTEMAwv6rjpEgtJXdcVn7ycM+oLtBUJgGt7l29sSrqL9K"
_I0101l11l01 = "CAL/p0iJkJKOk9d4zcLaAtmN1MEEiyD"
_III0lO011 = "O0bSPrhVmjGRKUJwk6cnYyzVEF06xC"
_l0lIOOI = "IqHMX3VNW+xd6RtyTtJ62hMFyuXc"
_l00III0O0O = "m8YNyu8LHrLP6oV1o5EkhgtZceei+B08loQHYPpyRjt"
_lO0l101 = "8k0i3YVfdvK5mVEardUK9dijijGYCQR30w8RdLZh"
_II00O000OI = "1LdDh96laGTcFKgFZHgMNhaZ/YEX"
_llI1I0lIl0 = "LTfMSC9Yl8TxPRROlUYlnLhoHE5bjLOHbX4"
_l01l0OOlI0 = "hsJgLZN3qKQf6siavbe+bwOFiTMfTzTbVuWRx5Ucj"
_OlI1OOOI11 = "I7IocZmgPVuM12xdTCFlFzKBxvLpVGY"
_I001I00 = "9Qmv0PRA8GMJWiql6X+Ys6sJZgBiZ4hB7qZKkWVcCe+qx4N/gGOKMsiY"
_llI0Oll1O = "mXWYGmBT7aTKupr0W1EwfwnGShdZbUE4yWpA1JCp4"
_OOOl0110I = "xdVfsHDGJglKd3nTyaUHlkYcPg59u8VlGOO5"
_I1II1lIIO0 = "8g8nROcJQ3Wt1W6N8tI5Ht6bn23othzwInM"
_lIl0l1OI = "BhvyR1ZVXnkV2LDheovDm3rzkoraoasNrkcwTYRZWAM"
_I0IIOll0I01 = "QZBi6xrM2KAkcWZH4T++35Y7CtNmnNwUcCRXRgj0F41O"
_O01OOOlI10 = "F0WLCVFFbocxujejtE1vetxWCY5TLmJADwWKpu7MkyJdxL/Ds"
_OO1IOOIO1O = "+KIbNUIyBA92GmA3vHiILA+YBus2CqecfE7hMHdxV7S"
_l1ll1Olll00 = "qR5gxa2++9tp0fdBAnzYDREMOW2Dw6TC"
_l1lOI0I = "xJxBvloh3lpKIP0SZrPRROa0RhlmUqe2Bobn/xAetlmfRgaD7MwD0Db4gxYM"
_Il1lO1lll = "hznqPL5Gc/sMBsjRICcMUYnmmTfpDYwmNkO"
_l0I0I1O = "uYGv+37Ev3eCJ/Q5ZLv5cgmLj7bFGWhEGEyrtYyNSbQxH23DxH/bHZAtmW"
_O0011I0lO0 = "2r/vio/dcUCC43Smrt0yFzII6XnnrB+ZKobTP3aktwgGkCtPIXukprrtbJEl"
_lIOI0I1 = "EU+jBJcAkjrKBJUQQgYP2iOo5fhbbQXjYpDFY5aFFHo"
_Ol001O01 = "Z38c+pFagHGaNF4fqkW9cBjwU"
_OlOOl1OOOl = "D859bSEcPZ6HAO8i2Mw3RB8lH"
_Ol01OIlIOlI = "M0aMTPwZj7OFKpY4/CYznqeoC5YZKj6Udx9arGUBluUsHw2bL/AQ4"
_IIl1O1I = "cfzG2yeXpTai2RDr/Hi1ZsreBpi6u5LKtmztrGmEMXGbVWqLfBQ0yLEv6I"
_OllOOII1I0I = "5SDLTaqBocunId6yzMwrxaa1NS3N6F1EHvpqfwbHeih47kurUvIo"
_lO1l11OI0 = "nEBuvxVJLK6Y/U/Vlpn70BfKUcff6K90imxfv+I5nvax"
_OlO001Il = "ai6u3NlRnPk51HZ4GQzsCMvzQiTGzNamvYIlcH9axdvIcf9UFkJ"
_I1O0lllllO1 = "PSSbb2LyHW21aaSfqLfW2hi1R30JIycW9hAKCOYJ0dhUDn2lsyLbyUUNnk1cv"
_llI0l11O = "jD+LneuO/fyi1bqOCMzfU/3rlP"
_O1llIl11Il = "fVeNW1heF2IDsMkEpPNaE/+1vEGLkLN4D6G0Y9LucsXHROM6Kb"
_OII0ll10O0 = "iqwSd/ZVusple9F4rsEnbIYETvlhh+okDO3I/LTvmDKVSca"
_lII0l01O = "dUtFXTDfxj/f+dF2j3RJlumas7F82QzvTUoS/9xAsWFBgdYPAncXn/"
_l00O10lOI = "LgJtDfbg6cj953xcbJHxlitPkbHLywU"
_Ol1OIOl10O = "MPVoTm9d86LCDG9G+CMDGseDp+3w3ER5CgPJVX"
_IOO00OOOl = "2ZCmK9GhFexr3WkspH3OpGIgWya+5NIHSMYSmHZ/B8Lj"
_lIlIll0Il0 = "DnfblflzMeYggFsgKDjJBVJBpo8Bp/QzfPHa4hS2+QVl3vq1"
_O0IIO0Ill0l = "ao/0wb2zcV/kSE5HS1agyF9XcnC"
_I1OOOl1IOOI = "QMTIl82ypZ4rubDoemPuGWvR60of2rsSdx3GD4zdmtbDdfcC"
_lOOll0OI0l = "1DT6af8ByhacMfDLS55ME/S3UvyvErPaklxjCKlvPfGhfhP"
_O10IIlO110O = "vs+BFjR4RpwQwcB1X6oGtId1PtP1L516CJ34IpI1Z"
_lllO011O1O1 = "DpHD9WPixGNUKLbMznsRWnPZb1HS4WMRa045ACKAg"
_I1IO101 = "rZLgKdpLaPNZBBwJVD7mY3jQnnIeJWABTOB4"
_l1O01ll1010 = "nlDXKVuhT6Q+c7To8tduO8nkIpg8PidH+NV4+E0B8O"
_IOI1l1OOII = "3wkhrU2FTStfiX7nAezLvIPJN5huUw4F2u4Rk4KRZOrcGJVIKk0by"
_I0l10lO = "v40fAYY71LQbqAObAuKFee4l1wgXQepNY7iRft5kWR3OVlpO6V"
_O1lI1l1I = "tx6PL5j3han+btohMWV8YUWgsXuV1i1UES6YB8vo3FqJF2Ebls0/"
_lOIl11O1 = "4WOqOAx6lgg0TIeS2OliInkXjT5CFVU2"
_I1O1l1O01l = "tHSOkbZRQQyGlbZ8Ju8Qc5xZ+xB3K4uIz2I90bEGL7g7zC"
_lOI0011 = "sIfMBo53kFzGmQBtNGg3NUY6yPc0G"
_OO1lIl0I = "TWuIGc8NMuQew/gjeb/h2trK1EH1TCtbooIaGCklZSip+YKyPo+hHbD"
_lOOl0lO1 = "hn/bf3d8DQx03bkhDI4o11AL"
_lI01OII = "3jw731ldOWDx3GHSKORBoqwPzFsrgR/+HHt6VT7rBhJftrBY7MaL2m"
_I0O11l01lO = "2/6O+URz8SlMTw4CJt0eH1DoSm9JM8Ke3s86znoXjEcG+m4rCwmihSoPlSeB"
_IOOI01l0l = "TRlgmehxdWqUCclg1xdckuLidfFVZgTfsuhfWlw"
_llOllI1l = "Klq0zupCouKPLVPTIFr2j9fEeY5"
_Ol001l01I = "qbALyiSd9G06CGKlEtAShZ4WT7OH"
_lII00Il0l1 = "OD6bPg0y/3seZF1MywDulSGobw2N3eFCa5DZkj970q2T+xdiY7EtkpJB5PDqsX"
_l0I000I = "fXr2nbxZEfKmJQTJZPh5o8GMo4CDxXz910L6UXn+5NnEOQB4JO7cf1TUf8b"
_IlOlO1OOOl = "1DgpIvQxfFzQmdHUXeEap3nn4OMxzavF/fVN"
_I00IO1I10OO = "XeZSaDrUdEGT1chRyFhdy8RcphdnjJNW"
_lOlIIlI1O1l = "vok+fGbVqrI83H3/l0pRJtNn/bB2nWwwVbVlqHARt6AAjev0Rvbhq6ro2QXy"
_Ol00IlOOIIl = "A4X4wby9cGBBwuZVesFRFObCVHLiJCmCoT0MbRyfzcAn3X3w94xUP4y"
_Ol010IO1I = "sqwvvv6CUGRlzeS4qu4kPY3pCHltrZrLYk79ECgkOU9M5C77EKGpbGoK3o"
_Ol0OOlO = "kQY7mC+cTK7Ung3eqpdPkcYXtfKV+qC9sVaYTsfjferViHF+O0S5"
_l110IOlIlI = "ZaHyQ+Ccbe/jyN1zjtIpEGQ7Mx8qIwhb70YF"
_lOlO1I00lO = "qR+x0sB/VZR8ym3Mpp7fsE+0WDPun1GGKfoEz2NW"
_lI01IO1l11 = "KXjEV/fWkKY3EGQ0wGraFvi26pr3WazupDuaFN00hK"
_O1l1O0ll10l = "SptO/8zsUaxeQOYtTdl1IuT3V8dM+/TwKkYimtLnpEOQ"
_OIlO0llI1O = "ZXaQvxb1Ga4qHSLLsbReQ+NW9gyK5S6UAJ5Qm"
_IlO1I1O = "JaUNW946mSjbOYLB1kdhx8NmPq8xohDhOHKMP6Qb0jMWMaRdhJlJ"
_lO1O1O01 = "+SkJqE1e61mkWdnUOzSQNkfH6pJDfyF5cd"
_OOI10Ol0ll1 = "KAGlqJQWXlhSUmDJ8JWLAR1GfJBFDcLaW"
_I10I0ll1 = "C2c48czcWedzQzikX6u7yFj9xOPL"
_lIl1IOlIOl1 = "nIUnCfNmb0NR0LK4w8iiORI4"
_Il0lIOOI = "wo5qqn0FwRvwa0yrd9extVDQpCgY"
_O0OI1l10 = "sexuMkA9pSzJfiTvb9g7M3JZ8Cvm"
_OII0IIlO1O1 = "K+J5Yor0DXU8MbQ3Qe8EVc8chNOjtrLM9dLt87ZKGLzsoDG0yQ6ZzZTOA"
_lOllOI101I = "1hG5M5U+L3DoFdPqb1QZB+7UiN35z5S"
_IIl1l000Ol = "jFBbgLjbqLV9eh3rp87RbJPkiDi0/sJ5DU"
_O11OlIOl = "DJifLshBfISUC5bOfCjc21y7lFn38b70voPwfsEVxxjsh+68brCPKLWcAt"
_I11II1I01I = "QMyBtN53B3Qc2jShzoGcd6rkD3k8JH1bfqfL3vd"
_IIl1OO10 = "U/hHqsIUtyuW8sG4zpcPR0uWt"
_l100OlIIO = "OHTAhTsG1DO7z7hNYNZOQUezaTAgXpBwEquuCjEJaMEKNo8yM3H5ttFpjSx"
_OOIIO00Ol = "c0DSrRVmmdQp9Pg4zF2pSpjplD0You8HIxQiw9XQh/Shz7ox60wGOddSq5kG"
_ll011IO0 = "RHm72FnE9G1mavryN0f5UfczH6hsRb4wJFcUGE08axV30BXospfw"
_l0Ol1IO10l = "cRVE2j4nZgphCzGOBulxLdDTEZuc9j++pm3oyB/G5x1N"
_IlO1l0I00 = "WVL07uL2Ac46TLzZzy1XIGq3vpXbwg"
_Ol1lOI000I0 = "d8LxbasSw59GWwH2wfwLoWkm+A9KD1ERDsIG3KNqcNTtFqJtlrFsp3OyRfYX"
_l1lIIlIIO0 = "4hwP3RlY/ktZqpsmpiQ1vJ7glsvFebYPpsjz9DRJ"
_lOI00l1 = "YeL+6wou2W51FBooLx5FSX9kJKOk9QV8qFG1"
_IIl11IOIl = "BkG0RxZtRzJz9MzJbpanA+L1CfpFs5opbLPiCrn5ajZ7crvUZzozSFmR"
_lI00I10lOO = "nzrP865ULzeNdLloNZOPreKwgMQrgt7KcaFQ1vS7l4FpFE8nk8Q"
_OlO01I0Il = "UjGgOZ4KSB8k/KgP1atz6QxBBFDjFVFb4tDTHVyCTx2xnBEArNz"
_lllOIOI = "xI7u5nEeTyAvV2NEXcw1yHuCy5rylUuKwCdDKqLa"
_O10IIO100I = "cRy7P9hOMh31Ecl4qO18b84C3CMpwjazMblEyNwb2pkCvqC"
_l1001IO1 = "+oE9yK11AX1Po1j9JIiCxzVk"
_I1IIIOI010l = "3dlxzGqdLeUVGAvw33maLbVg+rqnCKDmkUmqC"
_IlO01I0O = "Dt9uZyDXPZIrADbGjtv3eBVdokm4TCBZz5BTkYAjYWM8+lW"
_I11ll0I = "R/6UvnbD5CYG8lyuRAfp0oteJ5NoHNYfdiGWIAYWBa8Drh2hkEw"
_l01Il11IlI = "hlokGO/TlWbRkvPbXvptU8w9ITdPqa"
_OO001O0 = "pC+AEibQFfMM+X6OldyktoOv0Zuz5jFZNcG7cUlKi2iNz/UFW8E"
_Il10Ol1l10 = "TobMqw4PskQ6R/4IDXkTIzdv18QRSAqxKX2IwiP3lJAyCqrgnlMrg"
_lOI1l0II00 = "xKw7KRoc89TrlMlzmfITYsFHDhWcCkt+ltCgxxnfwQhz7IO"
_l10l01O1l1 = base64.b64decode(_Ol1OIOl10O + _IIl1l000Ol + _ll011IO0 + _l10l010O110 + _lI01OII + _l1lOI0I + _lIl0l1OI + _lllO011O1O1 + _I1II1OIl + _lIl11OlII + _I0I110Il + _O0IIO0Ill0l + _OllOOII1I0I + _O11OlIOl + _l00O10lOI + _I0IIOll0I01 + _l0Ol1IO10l + _Il1lO1lll + _Ol010IO1I + _l101I0Ol00 + _l110IOlIlI + _l1ll0lOllO + _lOl0O1I + _Ol001O01 + _l00III0O0O + _l01Il11IlI + _IlO01I0O + _lOIl11O1 + _Ol001l01I + _I0101l11l01 + _OII0ll10O0 + _II00O000OI + _l0I000I + _lO1O1O01 + _lI01IO1l11 + _lOI00l1 + _l11I10l1II + _OO001O0 + _O0011I0lO0 + _l0lIOOI + _lOI1l0II00 + _llI1I0lIl0 + _IlO1l0I00 + _lO0O1II1O + _IlII11Il0O + _lllOIOI + _OIO11lIO + _IIl1O1I + _l0I0I1O + _OlO001Il + _OO1IOOIO1O + _I1IIIOI010l + _I1O1l1O01l + _IOI1l1OOII + _OOIIO00Ol + _l1O01ll1010 + _OII0IIlO1O1 + _OIIl1OlIIl0 + _I10I0ll1 + _O10IIO100I + _O0OI1l10 + _OO1lIl0I + _l01l0OOlI0 + _III0lO011 + _OOOl0110I + _OOI10Ol0ll1 + _Ol01OIlIOlI + _lOlIIlI1O1l + _O1l1O0ll10l + _II0OI0Il0 + _I0O11l01lO + _lIl1IOlIOl1)
_IIOlIO0lIO1 = _O0I10I0(_l10l01O1l1, _lOI00I1II[0], _lOI00I1II[1], _lOI00I1II[2])
try:
    _IOI0I10I = _IIOlIO0lIO1.decode('utf-8')
except Exception:
    sys.exit(0)
_I111lIll1I = {'__builtins__': __builtins__, '_I10100O': _I10100O, '_O01011O1': _O01011O1, '_Ol1ll011': _Ol1ll011, '_O0I10I0': _O0I10I0, '_OO0lOII1': _OO0lOII1, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': _lII101Ol0}
try:
    _lO00OIl0II = _I10100O[1](_IOI0I10I, '<s1>', 'exec')
except Exception:
    sys.exit(0)
_OO0lOII1(_lO00OIl0II, _I111lIll1I)()
#PYG4E
