import socket
from cryptoFunction import *

fileBlockSize = 100000
commandGeneral = {
	'login'		: 'Login',
	'Login'		: 'Login',
	
	'register'	: 'Register',
	'Register'	: 'Register',
	'reg'		: 'Register',

	'remove'	: 'Remove',
	'rm'		: 'Remove',
	'kill'		: 'Remove',
	'suicide'	: 'Remove',
	'clear'		: 'Remove',

	'Exit'		: 'Exit',
	'exit'		: 'Exit',
	'leave'		: 'Exit',
	'Leave'		: 'Exit',

	'list'		: 'List',
	'List'		: 'List',
	'ls'		: 'List',
	'Ls'		: 'List',

	'mask'		: 'Mask',
	'Mask'		: 'Mask',

	'unmask'	: 'Unmask',
	'Unmask'	: 'Unmask',

	'send'		: 'SendMessage',
	'Send'		: 'SendMessage',
	'sendto'	: 'SendMessage',
	'Sendto'	: 'SendMessage',
	'talk'		: 'SendMessage',
	'say'		: 'SendMessage',

	'file'		: 'SendFile',
	'File'		: 'SendFile',
	'sendFile'	: 'SendFile',
	'sendfile'	: 'SendFile',

	'Message'	: 'MessageBox',
	'message'	: 'MessageBox',
	'msg'		: 'MessageBox',
	'Msg'		: 'MessageBox',
	'msgbox'	: 'MessageBox',
	'Msgbox'	: 'MessageBox',
	'm'			: 'MessageBox',
	'M'			: 'MessageBox',

	'Fetch'		: 'FetchMessage',
	'Check'		: 'FetchMessage',
	'fetch'		: 'FetchMessage',
	'check'		: 'FetchMessage',
	'f'			: 'FetchMessage',
	'F'			: 'FetchMessage',

	'accept'	: 'Accept',
	'Accept'	: 'Accept',
	'Y'			: 'Accept',
	'y'			: 'Accept',
	'A'			: 'Accept',
	'a'			: 'Accept',

	'deny'		: 'Deny',
	'Deny'		: 'Deny',
	'd'			: 'Deny',
	'D'			: 'Deny',
	'n'			: 'Deny',
	'N'			: 'Deny',

	'Q'			: 'Quit',
	'q'			: 'Quit',
	'Quit'		: 'Quit',
	'quit'		: 'Quit',

	'history'	: 'History',
	'History'	: 'History',

	'log'		: 'Log',
	'Log'		: 'Log',
	

	'logout'	: 'Logout',
	'Logout'	: 'Logout'
}


def IDcheck(ID):
	if len(ID) > 16 or len(ID) < 4:
		return False
	charset = '0123456798abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'
	for c in ID:
		if c not in charset:
			return False
	return True


def HASHcheck(Hash):
	charset = '0123456789abcdef'
	if len(Hash) != 64:
		return False
	for c in Hash:
		if c not in charset and c != '':
			return False
	return True

def PKEYcheck(pkey):
	return True

def recvCommand(socket, length):
	return str(socket.recv(length), 'ascii')
def recvResponse(socket, length):
	return str(socket.recv(length), 'ascii')

def sendCommand(socket, cmd):
	cmds = cmd.split(' ')
	try:
		header = commandGeneral[cmds[0]]
	except:
		return False

	contents = cmds[1:]

	if header == 'Register':
		try:
			ID, password = contents
		except:
			return False

		hashedPassword = passwordHash(password)
		privateKey = genPrivateKey(ID, password)
		publicKey = genPublicKey(privateKey)

		contents = (ID, hashedPassword, publicKey)
	elif header == 'Login':
		try:
			ID, password = contents
		except:
			return False
		hashedPassword = passwordHash(password)
		contents = (ID, hashedPassword)
	elif header == 'Remove':
		try:
			ID, password = contents
		except:
			return False
		hashedPassword = passwordHash(password)
		privateKey = genPrivateKey(ID, password)
		contents = (ID, hashedPassword, privateKey)
	elif header == 'SendMessage':

		try:
			receiver, message = contents
		except:
			return False

		socket.send(bytes('GetPublicKey:{}\x00'.format(receiver), 'ascii'))
		raw_data = recvResponse(socket, 1024)

		try:
			nheader, pkey = raw_data.split(':')
			if nheader != 'Data':
				raise Exception
			pkey = pkey.strip('\x00')
		except:
			return False

		socket.send(b'WhoAmI\x00')
		raw_data = recvResponse(socket, 1024)
		try:
			nheader, myID = raw_data.split(':')
			if nheader != 'Data':
				raise Exception
			myID = myID.strip('\x00')
		except:
			return False

		socket.send(b'GetServerTime\x00')
		raw_data = recvResponse(socket, 1024)
		try:
			nheader, serverTime = raw_data.split(':')
			if nheader != 'Data':
				raise Exception
			serverTime = serverTime.strip('\x00')
		except:
			return False

		(secret, sender) = dhGenSecret(pkey)
		cipherPack = aesEncrypt(bytes('{}\x00{}\x00{}\x00{}'.format(message, myID, serverTime, 'Signature'), 'ascii'), bytes.fromhex(secret))
		contents = (receiver, cipherPack, sender)
	elif header == 'SendFile':
		try:
			receiver, filepath = contents
		except:
			return False
		try:
			thefile = open(filepath, 'rb')
			filename = filepath.split('/')[-1]
		except:
			return False

		socket.send(b'GetServerTime\x00')
		raw_data = recvResponse(socket, 1024)
		try:
			nheader, serverTime = raw_data.split(':')
			serverTime = serverTime.strip('\x00')
			if nheader != 'Data':
				raise Exception
		except:
			return False

		filename = '{}_{}'.format(randomString(20), filename)

		socket.send(bytes('SendFileStart:{}\x00'.format(receiver), 'ascii'))
		raw_data = recvResponse(socket, 1024)
		try:
			fheader, fcontent = raw_data.split(':')
		except:
			return False
		if fheader == 'NAK':
			return False

		socket.send(bytes('GetPublicKey:{}\x00'.format(receiver), 'ascii'))
		raw_data = recvResponse(socket, 1024)
		try:
			nheader, pkey = raw_data.split(':')
			pkey = pkey.strip('\x00')
		except:
			return False

		socket.send(b'WhoAmI\x00')
		raw_data = recvResponse(socket, 1024)
		try:
			nheader, myID = raw_data.split(':')
			myID = myID.strip('\x00')
		except:
			return False

		(secret, sender) = dhGenSecret(pkey)
		print('Start sending the file.')
		while True:
			
			block = thefile.read(fileBlockSize)
			print('Sending...', end='\r')
			if block == b'': break
			cryptedBlock = aesEncrypt(block, bytes.fromhex(secret))
			socket.send(bytes('FileContent:'+cryptedBlock+'\x00', 'ascii'))
		
		cipherPack = aesEncrypt(bytes('{}\x00{}\x00{}\x00{}'.format(filename, myID, serverTime, 'Signature'), 'ascii'), bytes.fromhex(secret))
		contents = (receiver, cipherPack, sender)


	content = ' '.join(contents)
	socket.send(bytes(header+':'+content+'\x00',  'ascii'))
	return True
def sendResponse(socket, header, content):
	socket.send(bytes(header+':'+content+'\x00', 'ascii'))
	return True

