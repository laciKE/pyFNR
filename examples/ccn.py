import pyFNR
import pyFNR.Util

ccn = pyFNR.Util.LuhnR(0, 16)
fnr = pyFNR.FNR2(key='password', tweak='tweak-is-string', domain=ccn.get_words_count()-1)

plains = ['4024007162012628', '5260106710301747', '6011001620745085'] 
ciphers = [ccn.unrank(fnr.encrypt(ccn.rank(plain))) for plain in plains]
plains2 = [ccn.unrank(fnr.decrypt(ccn.rank(cipher))) for cipher in ciphers]

for i in range(len(plains)):
	print(plains[i] + ' -> ' + ciphers[i] + ' -> ' + plains2[i])

fnr.close()
