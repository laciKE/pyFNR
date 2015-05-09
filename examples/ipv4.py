import pyFNR
import pyFNR.Util

ipv4 = pyFNR.Util.IPv4()
fnr = pyFNR.FNR2(key='password', tweak='tweak-is-string', domain=ipv4.get_words_count()-1)

plain = '10.0.0.42'
cipher = ipv4.unrank(fnr.encrypt(ipv4.rank(plain)))
plain2 = ipv4.unrank(fnr.decrypt(ipv4.rank(cipher)))

print(plain + ' -> ' + cipher + ' -> ' +plain2)

fnr.close()
