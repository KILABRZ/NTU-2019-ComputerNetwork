try:
	from Cryptodome.Cipher import AES
except:
	from Crypto.Cipher import AES

try:	
	from Cryptodome.Hash import SHA256
except:
	from Crypto.Hash import SHA256

try:
	from Cryptodome.Util.number import getRandomInteger
except:
	from Crypto.Util.number import getRandomInteger

try:
	from Cryptodome.Random.random import choice
except:
	from Crypto.Random.random import choice

def generalHash(data):
	hasher = SHA256.new(data=data)
	return hasher.hexdigest()
def extendToThirtyTwo(key):
	hasher = SHA256.new(data=key)
	newkey = bytes.fromhex(hasher.hexdigest())
	return newkey

def aesEncrypt(bytesData, byteskey):
	byteskey = extendToThirtyTwo(byteskey)
	cipher = AES.new(byteskey, AES.MODE_GCM)
	nonce = cipher.nonce
	cipherText, tag = cipher.encrypt_and_digest(bytesData)
	returnPackage = 'O'.join((nonce.hex() ,cipherText.hex() ,tag.hex()))
	return returnPackage

def aesDecrypt(package, byteskey):
	package = package.strip('\n')
	byteskey = extendToThirtyTwo(byteskey)
	nonce, cipherText, tag = [bytes.fromhex(c) for c in package.split('O')]
	cipher = AES.new(byteskey, AES.MODE_GCM, nonce=nonce)

	plaintext = cipher.decrypt(cipherText)
	try:
		cipher.verify(tag)
		return plaintext
	except:
		raise Exception

def passwordHash(password):
	perfectSalt = 'this_is_the_perfect_salt'
	for i in range(256):
		hasher = SHA256.new(data=bytes(password+perfectSalt, 'ascii'))
		password = hasher.hexdigest()
	return password

G = 857
P = 150222214997246546179223346515393604829660673333778241175247157230399815528346898012232490305603940260886487855096511778838294033507528436570535715736787953951198303292055031796228220702143587885939346513233456912724392528866102636816173439515416880071092115414544988059271480859363123948425769942240289125921

MAXBITLENGTH = 1023
MAXBYTELENGTH = 128
MAXHEXLENGTH = 254

def genPrivateKey(ID, password):
	salt = 'this_is_the_perfect_salt'
	dataIndexer = '1021021120'
	thedata = ''
	selector = (ID, password, salt)
	for c in dataIndexer:
		thedata += selector[int(c)]
	privateKey = SHA256.new(data=bytes(thedata, 'ascii')).hexdigest()
	for i in range(10):
		privateKey += SHA256.new(data=bytes(privateKey, 'ascii')).hexdigest()
	privateKey = privateKey[0:MAXHEXLENGTH]
	return privateKey

def genPublicKey(privateKey):
	int_privateKey = int(privateKey, 16)

	publicKey = pow(G, int_privateKey, P)
	return publicKey.to_bytes(MAXBYTELENGTH, byteorder='big').hex()

def dhGenSecret(publicKey):
	int_publicKey = int(publicKey, 16)
	r = getRandomInteger(MAXBITLENGTH)
	secret = pow(int_publicKey, r, P)
	sender = pow(G, r, P)
	secret = secret.to_bytes(MAXBYTELENGTH, byteorder='big').hex()
	sender = sender.to_bytes(MAXBYTELENGTH, byteorder='big').hex()
	return (secret, sender)

def dhGetSecret(sender, privateKey):
	sender = int(sender, 16)
	int_privateKey = int(privateKey, 16)
	secret = pow(sender, int_privateKey, P)
	secret = secret.to_bytes(MAXBYTELENGTH, byteorder='big').hex()
	return secret


def randomString(n):
	thestring = ''
	charset = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPOQRSTUVWXYZ'
	for i in range(n):
		thestring += choice(charset)
	return thestring