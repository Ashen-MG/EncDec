from argparse import ArgumentParser
import os
import cv2
from Crypto.Cipher import AES
from Crypto import Random
from hashlib import sha256


"""
Encryption and Decryption by password
-------------------------------------

Encrypt:
	- text file
	- image
	- video
	- files in directory

How does it work ?
------------------
Single file or directory of files

Ideas
------------------
encrypt file by name format (example: image*.jpg, *.*, *.jpg)
encrypt files by format
"""
class EncDec:

	def __init__(self):
		self.filename = []
		self.password = "root"
		self.second_key = "{key}"
		self.decryption = False

		self.argument_parser()

	def argument_parser(self):
		parser = ArgumentParser()
		parser.add_argument("-f", "--filename", nargs="*", default=self.filename, metavar="filename", help="Set files.")
		parser.add_argument("-p", "--password", nargs="?", default=self.password, const=self.password, type=str, metavar="password", help="Set password.")
		parser.add_argument("-d", "--decryption", action="store_true", help="Decryption mode.")
		args = parser.parse_args()

		self.filename = args.filename
		self.password = args.password
		self.decryption = args.decryption

		if self.filename != []:

			if not self.decryption:
				self.start_encryption_files(self.filename)
			else:
				self.start_decryption_files(self.filename)

		else:
			parser.error("File or directory of files gotta be set to start program.")

	# Main method for encryption
	def start_encryption_files(self, files, path=""):
		for file in files:
			file = path + file
			if os.path.exists(file):
				if os.path.isfile(file):
					if ".mp4" in file or ".avi" in file or ".mov" in file:
						self.encrypt_video(file)
					else:
						self.encrypt_file(file)
				elif os.path.isdir(file):
					directory_files = os.listdir(file)
					self.start_encryption_files(directory_files, file if file.endswith("/") or file.endswith("\\") else file + "/")
			else:
				print("File {} doesn't exist.".format(str(file)))

	# Second method for encryption
	# Encrypt one file by filename
	def encrypt_file(self, filename):
		iv = Random.new().read(16)
		aes = AES.new(sha256(self.password.encode("UTF-8")).digest(), AES.MODE_CBC, iv)
		print("Encrypting file '{}'".format(filename))
		with open(filename, "rb") as rf:
		    data = rf.read()
		    data = self.second_key.encode("UTF-8") + data
		    data += (16 - len(data) % 16) * b" "
		    ciphertext = aes.encrypt(data)
		    with open(filename, "wb") as wf:
		        wf.write(iv + ciphertext)
		print("File has been encrypted with password " + self.password)

	def encrypt_video(self, videoname):
		f = open(videoname + "{ENCRYPTED}", "ab")

		iv = Random.new().read(16)
		aes = AES.new(sha256(self.password.encode("UTF-8")).digest(), AES.MODE_CBC, iv)

		print("Encrypting file '{}'".format(videoname))

		for line in open(videoname, "rb"):
			line = self.second_key.encode("UTF-8") + line
			line += (16 - len(line) % 16) * b" "
			f.write(iv + aes.encrypt(line))

	# Main method for decryption
	def start_decryption_files(self, files, path=""):
		for file in files:
			file = path + file
			if os.path.exists(file):
				if os.path.isfile(file):
					self.decrypt_file(file)
				elif os.path.isdir(file):
					directory_files = os.listdir(file)
					self.start_decryption_files(directory_files, file if file.endswith("/") or file.endswith("\\") else file + "/")
			else:
				print("File {} doesn't exist.".format(str(file)))

	# Second method for decryption
	# Decrypt one file by filename
	def decrypt_file(self, filename):
		print("Decrypting file '{}'".format(filename))
		try:
			with open(filename, "rb") as rf:
				iv = rf.read(16)
				aes = AES.new(sha256(self.password.encode("UTF-8")).digest(), AES.MODE_CBC, iv)
				data = rf.read()
				decrypted_data = aes.decrypt(data)
				if decrypted_data.startswith(self.second_key.encode("UTF-8")):
					with open(filename, "wb") as wf:
						wf.write(decrypted_data.replace(b"{key}", b"").strip())
					print("File has been decrypted.")
				else:
					print("Invalid password.")
		except ValueError:
			print("ValueError\nFile is probably not encrypted.")


if __name__ == "__main__":
	encdec = EncDec()
