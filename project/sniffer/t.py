import re
import sniffer
pattern = re.compile(r"""(?P<found>(USER|USERNAME|PASS|
PASSWORD|LOGIN|BENUTZER|PASSWORT|AUTH|email|password|clientuser|clientpass
ACCESS|ACCESS_?KEY|SESSION|
SESSION_?KEY|TOKEN)[=:\s].+)\b""", re.MULTILINE|re.IGNORECASE)

l='many more password and there is nothing here ufala  anther should be found this and is kkk and my data is 567890-'
m=re.findall(pattern, l)
if m:
	print 'fu'

for  i in m:
	print i
