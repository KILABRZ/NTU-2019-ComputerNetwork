import sys
import socket
import time
from messageHandling import sendCommand, recvResponse, commandGeneral
from cryptoFunction import aesEncrypt, aesDecrypt, genPrivateKey, dhGetSecret

class KATclient:
	def __init__(self, serverHost, serverPort):
		self.host = serverHost
		self.port = serverPort
		self.timeout = 10

		self.state = 'initial'

		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.settimeout(self.timeout)

		self.shellStyle = '$> '
		
		self.goodPassword = ''
		self.myName = ''
		self.privateKey = ''

		self.fileLoader = ''
		self.tmpfilename = ''
		self.prevSecret = ''
		self.downloadPath = './download/'
		self.logPath = './log/'
		self.writeFlag = False

	def hello(self):

		try:
			self.socket.connect((self.host, self.port))
		except:
			self.state = 'hello_error'
			return False

		helloMesage = str(self.socket.recv(1024), 'ascii')
		print(helloMesage)
		newPort = int(helloMesage.split(':')[1])

		self.socket.close()
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		for i in range(6):
			try:
				self.socket.connect((self.host, newPort))
				self.state = 'true_connect'
				break
			except:
				self.state = 'true_connect_fail'
			time.sleep(0.3)
		if self.state == 'true_connect_fail':
			self.state = 'hello_error'
			return False
		else:
			self.port = newPort
			print('Connection is built.')
			return True

	def send_getResponse(self, command):
		if self.state != 'true_connect':
			return False

		rv = sendCommand(self.socket, command)
		if not rv: return 'Error dues to client.\n'

		n = 1
		preResponse = ''
		reflectString = ''

		while n > 0:
			rawResponse = ''
			if '\x00' not in preResponse:
				try:
					rawResponse = recvResponse(self.socket, 1024)
				except:
					print('Server is close.')
					return False
				if rawResponse == '':
					print('Server is close.')
					return False
			preResponse += rawResponse
			response = ''
			if '\x00' not in preResponse: continue

			response = preResponse.split('\x00')[0]
			preResponse = '\x00'.join(preResponse.split('\x00')[1:])
			n -= 1
			response_head = response.split(':')[0]
			response_content = ':'.join(response.split(':')[1:])

# under this line, response is correct, '\x00' stripped off

			if response_head == 'Message':
				reflectString += response_content + '\n'

			elif response_head == 'MultiResponse':
				c = int(response_content)
				n += c
			elif response_head == 'LoginSuccess':
				self.myName = command.split(' ')[1]
				self.goodPassword = command.split(' ')[2]
				self.privateKey = genPrivateKey(self.myName, self.goodPassword)

			elif response_head == "ChangeShellStyle":
				self.shellStyle = response_content
			elif response_head == 'ExitMessage':
				reflectString += response_content + '\n'
				raise SystemExit
			elif response_head == 'CryptedMessage':
				cipherPack, keycipher = response_content.split('/')
				try:
					secret = dhGetSecret(keycipher, self.privateKey)
					self.prevSecret = bytes.fromhex(secret)
				except:
					reflectString += 'Message keycipher wrong.\n'
					break

				try:
					raw_decrypt_message = aesDecrypt(cipherPack, self.prevSecret)
				except:
					reflectString += 'Message decrypting wrong.\n'
					break

				try:
					message, sender, time, signature = str(raw_decrypt_message, 'ascii').split('\x00')
				except:
					reflectString += 'Message format wrong. ({})\n'.format(raw_decrypt_message)
					break

				reflectString += '{} at {}: {}\n'.format(sender, time, message)
			elif response_head == 'CryptedFileHint':
				hashedFilename, cipherPack, keycipher = response_content.split('/')
				
				try:
					secret = dhGetSecret(keycipher, self.privateKey)
					self.prevSecret = bytes.fromhex(secret)
				except:
					reflectString += 'Message keycipher wrong.\n'
					break

				try:
					raw_decrypt_message = aesDecrypt(cipherPack, self.prevSecret)
				except:
					reflectString += 'Message decrypting wrong.\n'
					break

				try:
					filename, sender, time, signature = str(raw_decrypt_message, 'ascii').split('\x00')
					self.tmpfilename = filename
				except:
					reflectString += 'Message format wrong. ({})\n'.format(raw_decrypt_message)
					break

				randomPrefix = filename.split('_')[0]
				trueFilename = '_'.join(filename.split('_')[1:])
				reflectString += '{} sends file {}\n'.format(sender, trueFilename)

			elif response_head == 'HistoryLine':
				messageHeader, messageContent = response_content.split(':')
				if messageHeader in ('Message', 'File'):
					if messageHeader == 'Message':
						cipher, keycipher, acceptTime = messageContent.split('/')
					if messageHeader == 'File':
						tmpfilename, cipher, keycipher, acceptTime = messageContent.split('/')

					acceptTime = acceptTime.strip('\n')
					secret = dhGetSecret(keycipher, self.privateKey)
					try:
						raw_decrypt_message = aesDecrypt(cipher, bytes.fromhex(secret))
					except:
						reflectString += 'Decrypt error.\n'
						continue
					
					message, sender, time, signature = str(raw_decrypt_message, 'ascii').split('\x00')
					if messageHeader == 'File': message = '_'.join(message.split('_')[1:])
					formattingString = '{}: {} -> {} at {}\n'.format(acceptTime, sender, message, time)
				
				else:
					time, sender = messageContent.split(' ')
					sender = sender.strip('\n')
					message = 'some file.' if messageHeader == 'SendFile' else 'some message.'
					formattingString = '{}: {} <- {}\n'.format(time, sender, message)
	
				reflectString += formattingString
			elif response_head == 'LogLine':
				historylog = open(self.logPath+self.myName+'_history.txt', 'a')

				messageHeader, messageContent = response_content.split(':')
				if messageHeader in ('Message', 'File'):
					if messageHeader == 'Message':
						cipher, keycipher, acceptTime = messageContent.split('/')
					if messageHeader == 'File':
						tmpfilename, cipher, keycipher, acceptTime = messageContent.split('/')
					acceptTime = acceptTime.strip('\n')
					secret = dhGetSecret(keycipher, self.privateKey)
					try:
						raw_decrypt_message = aesDecrypt(cipher, bytes.fromhex(secret))
					except:
						reflectString += 'Decrypt error.\n'
						continue
					
					message, sender, time, signature = str(raw_decrypt_message, 'ascii').split('\x00')
					if messageHeader == 'File': message = '_'.join(message.split('_')[1:])
					formattingString = '{}: {} -> {} at {}\n'.format(acceptTime, sender, message, time)
				
				else:
					time, sender = messageContent.split(' ')
					sender = sender.strip('\n')
					message = 'some file.' if messageHeader == 'SendFile' else 'some message.'
					formattingString = '{}: {} <- {}\n'.format(time, sender, message)
				
				historylog.write(formattingString)
				historylog.close()

			elif response_head == 'DownloadStart':
				safety_filename = ''
				safety_check = '/\\'

				for c in self.tmpfilename:
					if c in safety_check:
						safety_filename += 'x'
					else: safety_filename += c

				if safety_filename == '.' or safety_filename == '..':
					safety_filename = 'tmp'

				self.fileLoader = open(self.downloadPath + safety_filename, 'wb')
				self.writeFlag = True
				print('Download start.')

			elif response_head == 'FileBlock':
				if not self.writeFlag:
					reflectString += 'Somehow explodes.\n'
					break
				block = response_content
				try:
					raw_decrypt_message = aesDecrypt(block, self.prevSecret)
				except:
					reflectString += 'Decrypt file error.\n';
					break
				self.fileLoader.write(raw_decrypt_message)
				print('Downloading...', end='\r')
				
			elif response_head == 'DownloadEnd':
				self.fileLoader.close()
				self.writeFlag = False
				self.tmpfilename = ''
				print('File downloading completes.')
			else:
				reflectString += 'Unknown Response Header ' + response + '\n'


		return reflectString
	def interactWith(self):
		while True:
			cmd = input('\n'+self.shellStyle)
			if cmd == '': continue

			cmds = []
			wordCount = len(cmd.split(' '))

			if wordCount <= 2:
				cmds.append(cmd)
			else:
				try:
					cmdHeader = cmd.split(' ')[0]
					test = commandGeneral[cmdHeader]
				except:
					print('Wrong command format.')
					continue
				if commandGeneral[cmdHeader] == 'SendFile':
					receiver = cmd.split(' ')[1]
					cmdContents = cmd.split(' ')[2:]
					for cmdContent in cmdContents:
						line = '{} {} {}'.format(cmdHeader, receiver, cmdContent)
						cmds.append(line)
				else:
					cmds.append(cmd)
			
			for cmd in cmds:
				rfc = self.send_getResponse(cmd)
				print(rfc, end='')	


client = KATclient('127.0.0.1', 8451)
rv = client.hello()
if not rv:
	print('Connection fail.')
	exit()
client.interactWith()