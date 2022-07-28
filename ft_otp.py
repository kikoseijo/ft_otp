from otp import OTP
from crypt import Encryptor
import secrets
import argparse

encryption_seed = "MZJLpBLnUNe1ejlQ9o_2Rav_nFKrxyrYyBVc-Z7cvbY="
key_file_name = "ft_otp.key"

def create_password():
	password = secrets.token_hex(32)
	return password;

def is_hex(s):
    hex_digits = set("0123456789abcdef")
    for char in s:
        if not (char.lower() in hex_digits):
            return False
    return True

def save_key(key_64_hex):
	if(is_hex(key_64_hex) and len(key_64_hex) >= 64):
		encryptor = Encryptor()
		encryptor.key_write(key_64_hex, key_file_name)
		encryptor.file_encrypt(encryption_seed, key_file_name, key_file_name)
		return True
	else:
		print("Error, Not an hexadecimal password or bellow 64 characters lenght")

def parse():
	parser = argparse.ArgumentParser(
		prog = 'python3 stockholm.py',
		description = 'One time password implementation.'
	)
	parser.add_argument('-v', '--version', action='version', version='KikOTP 1.0')
	parser.add_argument('-g', '--getkey', nargs=1, help='Save hexadecimal key', default = None)
	parser.add_argument('-k', '--keyproduce', action='store_true', help = 'Generate new otp password.', default = False)
	args = parser.parse_args()
	return args.__dict__

if __name__ == "__main__":
	dict = parse()
	new_key = dict.get("getkey")
	make_otp = dict.get("keyproduce")
	if (new_key):
		if (save_key(new_key[0])):
			print("Key succesfully encrypted into ft_otp.key")
	elif (make_otp):
		try:
			encryptor = Encryptor()
			key = encryptor.get_decrypted_key(encryption_seed, key_file_name)
			if key:
				print(key)
				otp = OTP(key)
				one_time_password = otp.generate()
				print(one_time_password)
		except Exception as e:
			print("Error loading key for getting OTP, add it with -g option")
	else:
		print("usage: python3 -g [64-hex-string] -k")


# El programa deberá llamarse ft_otp.
# • Con la opción -g , el programa recibirá como argumento una clave hexadecimal
# de al menos 64 caracteres. El programa guardará a buen recaudo esta clave en un
# archivo llamado ft_otp.key, que estará cifrado en todo momento.
# • Con la opción -k, el programa generará una nueva contraseña temporal y la mostrará en la salida estándar.
# af7058651430a1d2bbed400297fa1ba287c0709e38c7cd76dc00e44df4302954
# 1bc00f74af54174f82576d0b0524e216346b0526d93bfc35eca8795cd8d2f4e6
# 84cf6cabe49073ce1f1f477a583a6610ef29abc573214acc4fa4c575c5537dcc
# 2e96c43fe0e9c1c09e2b80180bb5a5d3b287d18a0c1e1ae6e34b19a9d3764a03
# 994dde009fd0cf37971ff9e196995d788ea7b9b597ed69fa9b8514c7a731a28f
# 74c9bdad813759fd539d42e3e0cce57ff490da61f8e57e415f0daf90e21f92a6
# MZJLpBLnUNe1ejlQ9o_2Rav_nFKrxyrYyBVc-Z7cvbY=
# oathtool –totp $(cat key.hex)
