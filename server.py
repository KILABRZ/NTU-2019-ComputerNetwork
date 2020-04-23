import sys
import threading
import socket
import queue
import os
import time
import math

from cryptoFunction import passwordHash, genPublicKey, randomString
from messageHandling import sendResponse, recvCommand, IDcheck, HASHcheck, PKEYcheck

STATE_MASKED = 0
STATE_MSGBOX = 1

class KATserver:
	def __init__(self, host, port, maxLink):

		self.connectorNum = maxLink
		self.host = host
		self.port = port
		self.timeout = 10

		self.state = 'initial'
		self.idlePortQueue = queue.Queue()
		self.onlineUsers = set()
		self.allUsers = set()
		self.onlineUsersState = dict()

		for offset in range(self.connectorNum):
			self.idlePortQueue.put(offset + 1)

		for user in os.listdir('./users'):
			self.allUsers.add(user)

		self.helloSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.helloSocket.bind((self.host, self.port))
		self.helloSocket.listen(self.connectorNum)
		self.helloSocket.settimeout(None)
		self.clientCounter = [None] * self.connectorNum

	def createUser(self, ID, hashedPassword, publicKey):
		userPath = './users/{}'.format(ID)
		os.mkdir(userPath)
		os.mkdir(userPath+'/fileBox')

		config = 'ID = [{}];\npassword = [{}];\npublickey = [{}];\n'.format(ID, hashedPassword, publicKey)

		open(userPath+'/messageBox.txt', 'w')
		open(userPath+'/history.txt', 'w')
		open(userPath+'/config.txt', 'w').write(config)

		self.allUsers.add(ID)

	def fetchUserConfig(self, ID, target):
		if ID not in self.allUsers:
			return False
		config = open('./users/{}/config.txt'.format(ID)).read()
		if target == 'password':
			try:
				rv = config.split('\n')[1].split('[')[1].split(']')[0]
			except:
				return False
			return rv
		elif target == 'publickey':
			try:
				rv = config.split('\n')[2].split('[')[1].split(']')[0]
			except:
				return False
			return rv
		else:
			return False

# this loooong function can be place into other file.
	def interactWith(self, newPort):
		interactSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		interactSocket.bind((self.host, newPort))
		interactSocket.listen(1)
		interactSocket.settimeout(self.timeout)

		try:
			(clientSocket, IP) = interactSocket.accept()
		except:
			print('Port {}> Second connect timeout.'.format(newPort))
			interactSocket.close()
			self.idlePortQueue.put(newPort - self.port)
			return False

		print('Port {}> Second connect to {} success.'.format(newPort, IP))

		userMessagesBoxContent = list()
		readingPrograss = 0
		fetchedMessage = ''
		messageheader = ''
		messagecontent = ''

		fileSendingLoader = ''
		tmpfilename = ''
		writeFileFlag = False
		fileReceiver = ''

		shellMode = 'welcome'
		loginUser = None
		preCommand = ''

		while True:

# Command Reassemble
# To prevent single seperated command exists

#			print('Port {}> wait command.'.format(newPort))
			rawCommand = ''
			if '\x00' not in preCommand:
				try:
					rawCommand = recvCommand(clientSocket, 1024)
				except:
					print('Port {}> client leave.'.format(newPort))
					self.idlePortQueue.put(newPort - self.port)
					if loginUser != None:
						self.onlineUsers.remove(loginUser)
						if shellMode == 'messageBox' and readingPrograss != 0:
							messageBox = open('./users/{}/messageBox.txt'.format(loginUser), 'w')
							for line in userMessagesBoxContent[readingPrograss:]:
								messageBox.write(line + '\n')
							messageBox.close()

					break
				if rawCommand == '':
					print('Port {}> client leave.'.format(newPort))
					self.idlePortQueue.put(newPort - self.port)
					if loginUser != None:
						self.onlineUsers.remove(loginUser)
						if shellMode == 'messageBox' and readingPrograss != 0:
							messageBox = open('./users/{}/messageBox.txt'.format(loginUser), 'w')
							for line in userMessagesBoxContent[readingPrograss:]:
								messageBox.write(line + '\n')
							messageBox.close()
					break
			
			preCommand += rawCommand
			command = ''

			if '\x00' not in preCommand: continue

			command = preCommand.split('\x00')[0]
			preCommand = '\x00'.join(preCommand.split('\x00')[1:])

			
# under this line, command is correct, '\x00' stripped off
			
			header = command.split(':')[0]
			content = ':'.join(command.split(':')[1:])
			print('Get header = ', header)
			if header == 'Register' and shellMode == 'welcome':
				try:
					ID, hashedPassword, publicKey = content.split(' ')
				except:
					sendResponse(clientSocket, 'Message', 'Command format error.')
					continue

				if not IDcheck(ID):
					sendResponse(clientSocket, 'Message', 'ID error.')
					continue

				if ID in self.allUsers:
					sendResponse(clientSocket, 'Message', 'This ID has existed.')
					continue

				if not HASHcheck(hashedPassword):
					sendResponse(clientSocket, 'Message', 'Password hash is corrupted')
					continue

				if not PKEYcheck(publicKey):
					sendResponse(clientSocket, 'Message', 'PKEY is corrupted')
					continue

				self.createUser(ID, passwordHash(hashedPassword), publicKey)
				sendResponse(clientSocket, 'Message', 'Register completes.')

			elif header == 'Login' and shellMode == 'welcome':
				try:
					ID, hashedPassword = content.split(' ')
				except:
					sendResponse(clientSocket, 'Message', 'Command format error.')
					continue

				if not IDcheck(ID):
					sendResponse(clientSocket, 'Message', 'ID error.')
					continue

				if ID not in self.allUsers:
					sendResponse(clientSocket, 'Message', 'ID is not exist.')
					continue

				if ID in self.onlineUsers:
					sendResponse(clientSocket, 'Message', 'User is active.')
					continue

				passwordData = self.fetchUserConfig(ID, 'password')

				if passwordData == False:
					sendResponse(clientSocket, 'Message', 'Server is exploded.')
					continue

				if passwordData != passwordHash(hashedPassword):
					sendResponse(clientSocket, 'Message', 'Wrong password.')
					continue

				shellMode = 'lobby'
				loginUser = ID
				self.onlineUsers.add(loginUser)
				self.onlineUsersState[loginUser] = [False, False]
				sendResponse(clientSocket, 'MultiResponse', '3')
				sendResponse(clientSocket, 'LoginSuccess', 'WoW')
				sendResponse(clientSocket, 'ChangeShellStyle', '{}> '.format(ID))
				sendResponse(clientSocket, 'Message', 'Login success, welcome {}!'.format(ID))

			elif header == 'Exit' and shellMode == 'welcome':
				sendResponse(clientSocket, 'ExitMessage', 'Bye')
				continue

			elif header == 'Remove' and shellMode == 'welcome':
				ID, hashedPassword, privateKey = content.split(' ')

				if ID not in self.allUsers:
					sendResponse(clientSocket, 'Message', 'ID is not exist.')
					continue

				if ID in self.onlineUsers:
					sendResponse(clientSocket, 'Message', 'User is active.')
					continue

				passwordData = self.fetchUserConfig(ID, 'password')

				if passwordData == False:
					sendResponse(clientSocket, 'Message', 'Server is exploded.')
					continue

				if passwordData != passwordHash(hashedPassword):
					sendResponse(clientSocket, 'Message', 'Wrong password.')
					continue

				publicKey = self.fetchUserConfig(ID, 'publickey')

				if publicKey == False:
					sendResponse(clientSocket, 'Message', 'Server is exploded.')
					continue

				if publicKey != genPublicKey(privateKey):
					sendResponse(clientSocket, 'Message', 'Private key is corrupted.')
					continue

				os.remove('./users/{}/config.txt'.format(ID))
				os.remove('./users/{}/history.txt'.format(ID))
				os.remove('./users/{}/messageBox.txt'.format(ID))
				
				for tmpfile in os.listdir('./users/{}/fileBox'.format(ID)):
					os.remove('./users/{}/fileBox/{}'.format(ID, tmpfile))
				os.rmdir('./users/{}/fileBox'.format(ID))
				os.rmdir('./users/{}'.format(ID))
				


				self.allUsers.remove(ID)

				sendResponse(clientSocket, 'Message', 'Goodbye {}.'.format(ID))
			elif header == 'Logout' and shellMode == 'lobby':
				
				self.onlineUsers.remove(loginUser)
				del self.onlineUsersState[loginUser]
				loginUser = None
				shellMode = 'welcome'
				
				sendResponse(clientSocket, 'MultiResponse', '2')
				sendResponse(clientSocket, 'ChangeShellStyle', '$> ')
				sendResponse(clientSocket, 'Message', 'Logout success.')

			elif header == 'GetPublicKey' and shellMode == 'lobby':
				user = content
				pkey = self.fetchUserConfig(user, 'publickey')
				if pkey == False:
					sendResponse(clientSocket, 'Message', 'Wrong.')
				else:
					sendResponse(clientSocket, 'Data', pkey)
			
			elif header == 'WhoAmI' and shellMode == 'lobby':
				sendResponse(clientSocket, 'Data', loginUser)

			elif header == 'GetServerTime' and shellMode == 'lobby':
				sendResponse(clientSocket, 'Data', str(math.floor(time.time())))

			elif header == 'SendMessage' and shellMode == 'lobby':
				try:
					receiver, cipher, keycipher = content.split(' ')
				except:
					sendResponse(clientSocket, 'Message', 'Server gets wrong format.')
					continue

				if receiver not in self.allUsers:
					sendResponse(clientSocket, 'Message', 'Receiver not exists.')
					continue

				if receiver in self.onlineUsers:
					if self.onlineUsersState[receiver][STATE_MSGBOX]:
						sendResponse(clientSocket, 'Message', 'Receiver is busy.')
						continue
					self.onlineUsersState[receiver][STATE_MSGBOX] = True

				formattingMessage = 'Message:{}/{}\n'.format(cipher, keycipher)
				messageBox = open('./users/{}/messageBox.txt'.format(receiver), 'a')
				messageBox.write(formattingMessage)
				messageBox.close()

				historyBox = open('./users/{}/history.txt'.format(loginUser), 'a')
				historyBox.write('SendMessage:'+str(math.floor(time.time()))+' '+receiver+'\n')
				historyBox.close()
				if receiver in self.onlineUsers:
					self.onlineUsersState[receiver][STATE_MSGBOX] = False

				sendResponse(clientSocket, 'Message', 'Message is sent.')
			elif header == 'MessageBox' and shellMode == 'lobby':
				if self.onlineUsersState[loginUser][STATE_MSGBOX]:
					sendResponse(clientSocket, 'Message', 'Someone is sending message to u.')
					continue
				self.onlineUsersState[loginUser][STATE_MSGBOX] = True
				
				messageBox = open('./users/{}/messageBox.txt'.format(loginUser), 'r')
				userMessagesBoxContent = messageBox.read().split('\n')[:-1]
				messageBox.close()

				if len(userMessagesBoxContent) <= 0:
					sendResponse(clientSocket, 'Message', 'No message.')
					self.onlineUsersState[loginUser][STATE_MSGBOX] = False
					continue
				sendResponse(clientSocket, 'MultiResponse', '2')
				sendResponse(clientSocket, 'ChangeShellStyle', 'M> ')
				sendResponse(clientSocket, 'Message', 'New {} message!'.format(len(userMessagesBoxContent)))
				readingPrograss = 0
				shellMode = 'messageBox'
							
			elif header == 'FetchMessage' and shellMode == 'messageBox':
				if readingPrograss >= len(userMessagesBoxContent):
					sendResponse(clientSocket, 'Message', 'No more message.')
					continue

				fetchedMessage = userMessagesBoxContent[readingPrograss]
				messageheader = fetchedMessage.split(':')[0]
				messagecontent = ':'.join(fetchedMessage.split(':')[1:])

				if messageheader == 'Message':
					sendResponse(clientSocket, 'CryptedMessage', messagecontent)
				elif messageheader == 'File':
					sendResponse(clientSocket, 'CryptedFileHint', messagecontent)
				else:
					sendResponse(clientSocket, 'Message', 'Unknown message format.')
			elif header == 'Accept' and shellMode == 'messageBox':
				if messageheader == '':
					sendResponse(clientSocket, 'Message', 'Message has not fetched yet.')
					continue

				history = open('./users/{}/history.txt'.format(loginUser), 'a')
				history.write(fetchedMessage+'/'+str(math.floor(time.time())) + '\n')
				history.close()

				if messageheader == 'Message':
					sendResponse(clientSocket, 'Message', 'Understand.')
					readingPrograss += 1
					messageheader = ''
					continue
				if messageheader == 'File':
					sendResponse(clientSocket, 'MultiResponse', '2')
					sendResponse(clientSocket, 'DownloadStart', 'Start.')
					tmpfilename = messagecontent.split('/')[0]
					fileSendingLoader = open('./users/{}/fileBox/{}'.format(loginUser, tmpfilename), 'r')
					while True:
						block = fileSendingLoader.readline()
						if block == '': break
						sendResponse(clientSocket, 'MultiResponse', '2')
						sendResponse(clientSocket, 'FileBlock', block)
#						print('Server send block')

					sendResponse(clientSocket, 'DownloadEnd', 'End.')
					fileSendingLoader.close()
					try:
						os.remove('./users/{}/fileBox/{}'.format(loginUser, tmpfilename))
					except:
						sendResponse(clientSocket, 'Message', 'Server explodes due to remove tmpfile.')
						continue
					readingPrograss += 1
					messageheader = ''
			elif header == 'Deny' and shellMode == 'messageBox':
				if messageheader == '':
					sendResponse(clientSocket, 'Message', 'Message has not fetched yet.')
					continue

				tmpfilename = messagecontent.split('/')[0]
				if messageheader == 'File':
					try:
						os.remove('./users/{}/fileBox/{}'.format(loginUser, tmpfilename))
					except:
						sendResponse(clientSocket, 'Message', 'Server explodes due to remove tmpfile.')
						continue

				readingPrograss += 1				
				messageheader = ''
				sendResponse(clientSocket, 'Message', 'Understand.')

			elif header == 'Quit' and shellMode == 'messageBox':
				messageBox = open('./users/{}/messageBox.txt'.format(loginUser), 'w')
				if readingPrograss >= len(userMessagesBoxContent):
					messageBox.close()
				else:
					for line in userMessagesBoxContent[readingPrograss:]:
						messageBox.write(line + '\n')
					messageBox.close()
				readingPrograss = 0
				userMessagesBoxContent.clear()
				self.onlineUsersState[loginUser][STATE_MSGBOX] = False
				shellMode = 'lobby'
				sendResponse(clientSocket, 'MultiResponse', '2')
				sendResponse(clientSocket, 'ChangeShellStyle', '{}> '.format(loginUser))
				sendResponse(clientSocket, 'Message', 'Leave message box.')

			elif header == 'SendFileStart' and shellMode == 'lobby':
				try:
					fileReceiver = content
				except:
					sendResponse(clientSocket, 'NAK', 'Wrong requests.')
					continue

				if fileReceiver not in self.allUsers:
					sendResponse(clientSocket, 'NAK', 'Receiver is not exists.')
					continue

				writeFileFlag = True
				tmpfilename = randomString(50)
				fileSendingLoader = open('./users/{}/fileBox/{}'.format(fileReceiver, tmpfilename), 'w')
				sendResponse(clientSocket, 'ACK', 'Good.')

			elif header == 'FileContent' and shellMode == 'lobby':
				fileBlock = content
				fileSendingLoader.write(fileBlock+'\n')
			elif header == 'SendFile' and shellMode == 'lobby':
				try:
					receiver, cipher, keycipher = content.split(' ')
				except:
					sendResponse(clientSocket, 'Message', 'Wrong format.')
					continue

				if receiver not in self.allUsers:
					sendResponse(clientSocket, 'Message', 'Receiver not exists.')
					continue

				waitCounter = 0
				maxCounter = 15
				if receiver in self.onlineUsers:
					while (self.onlineUsersState[receiver][STATE_MSGBOX]) and waitCounter < maxCounter:
						time.sleep(1)
						waitCounter += 1

				if waitCounter == maxCounter:
					sendResponse(clientSocket, 'Message', 'Receiver is busy.')
					writeFileFlag = False
					fileSendingLoader.close()
					os.remove('./users/{}/fileBox/{}'.format(fileReceiver, tmpfilename))
					continue

				if receiver in self.onlineUsers:
					self.onlineUsersState[receiver][STATE_MSGBOX] = True

				formattingMessage = 'File:{}/{}/{}\n'.format(tmpfilename, cipher, keycipher)
				messageBox = open('./users/{}/messageBox.txt'.format(receiver), 'a')
				messageBox.write(formattingMessage)
				messageBox.close()

				historyBox = open('./users/{}/history.txt'.format(loginUser), 'a')
				historyBox.write('SendFile:'+str(math.floor(time.time()))+' '+receiver+'\n')
				historyBox.close()

				if receiver in self.onlineUsers:
					self.onlineUsersState[receiver][STATE_MSGBOX] = False

				sendResponse(clientSocket, 'Message', 'File transmission completes.')

				writeFileFlag = False
				fileReceiver = ''
				tmpfilename = ''
				fileSendingLoader.close()
			elif header == 'History' and shellMode == 'lobby':
				historyBox = open('./users/{}/history.txt'.format(loginUser), 'r')
				while True:
					line = historyBox.readline()
					if line == '': break
					sendResponse(clientSocket, 'MultiResponse', '2')
					sendResponse(clientSocket, 'HistoryLine', line)
				historyBox.close()
				sendResponse(clientSocket, 'Message', 'END')

			elif header == 'Log' and shellMode == 'lobby':
				historyBox = open('./users/{}/history.txt'.format(loginUser), 'r')
				while True:
					line = historyBox.readline()
					if line == '': break
					sendResponse(clientSocket, 'MultiResponse', '2')
					sendResponse(clientSocket, 'LogLine', line)
				historyBox.close()
				historyBox = open('./users/{}/history.txt'.format(loginUser), 'w')
				historyBox.close()
				sendResponse(clientSocket, 'Message', 'History has downloaded in log.')
			elif header == 'List' and shellMode == 'lobby':
				totalResponse = ''
				for user in self.onlineUsers:
					if user == loginUser: continue
					if not self.onlineUsersState[user][STATE_MASKED]:
						totalResponse += user + '\n'
				sendResponse(clientSocket, 'Message', totalResponse)
			elif header == 'Mask' and shellMode == 'lobby':
				self.onlineUsersState[loginUser][STATE_MASKED] = True
				sendResponse(clientSocket, 'Message', 'You are masked.')
			elif header == 'Unmask' and shellMode == 'lobby':
				self.onlineUsersState[loginUser][STATE_MASKED] = False
				sendResponse(clientSocket, 'Message', 'You are unmasked.')
				
			else:
				sendResponse(clientSocket, 'Message', 'Wrong command or command in wrong shellmode.')



	def helloCounter(self):
		while True:
			while self.idlePortQueue.empty():
				print('Server is busy now', end='\r')

			threadX = self.idlePortQueue.get() - 1
			
			print(threadX, 'listen for connect')
			(clientSocket, IP) = self.helloSocket.accept()
			print('Get connect from', IP)
			
			newPort = self.port + threadX + 1
			self.clientCounter[threadX] = threading.Thread(target = self.interactWith, args = (newPort, ))
			print('Create client counter.')

			clientSocket.send(bytes('Hello. :{}'.format(newPort), 'ascii'))
			print('Send hello to', IP)
			self.clientCounter[threadX].start()

server = KATserver('127.0.0.1', 8451, 10)
server.helloCounter()