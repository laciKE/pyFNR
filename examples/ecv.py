import pyFNR
import pyFNR.Util

ecv = pyFNR.Util.ECV()
fnr = pyFNR.FNR2(key='password', tweak='tweak-is-string', domain=ecv.get_words_count()-1)

plain = 'KE007JB'
cipher = ecv.unrank(fnr.encrypt(ecv.rank(plain)))
plain2 = ecv.unrank(fnr.decrypt(ecv.rank(cipher)))

print(plain + ' -> ' + cipher + ' -> ' +plain2)

fnr.close()
