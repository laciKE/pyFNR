import pyFNR
import pyFNR.Util

ipv6 = pyFNR.Util.IPv6()
fnr = pyFNR.FNR2(key='password', tweak='tweak-is-string', domain=ipv6.get_words_count()-1)

plain = '2001:DB8:2de::e13'
cipher = ipv6.unrank(fnr.encrypt(ipv6.rank(plain)))
plain2 = ipv6.unrank(fnr.decrypt(ipv6.rank(cipher)))

print(plain + ' -> ' + cipher + ' -> ' +plain2)

fnr.close()
