import base64
import re
from itertools import cycle, zip_longest
from collections import defaultdict
import sys
from Crypto.Cipher import AES
import codecs

decode_hex = codecs.getdecoder("hex_codec")
encode_hex = codecs.getencoder("hex_codec")

def string_from_file(infile):
	"""
	Converts the contents of infile into a single string, sans newlines
	"""
	text = ""
	with open(infile) as f:
		text = "".join(line.strip() for line in f)
	return text

def display_hex(raw_hex_str):
	"""
	Python's `hex` function gives us a hex-formatted string, but it leaves a 
	`0x` on the front, and if it's a long, it leaves an `L` on the end.  So, 
	we strip those out here
	"""
	return hex(raw_hex_str)[2:].replace("L","")

def hex_to_b64(hex_str):
	""" Converts a hex-formatted string into b64 bytes """
	return base64.b64encode(decode_hex(hex_str)[0])

def xor_two_buffers(buffer1, buffer2):
	""" Takes two hex-formatted strings and returns a hex-formatted string """
	return display_hex(int(buffer1, 16) ^ int(buffer2, 16))

def xor_two_buffers_mod(buffer1, buffer2):
	""" Takes a string and a bytes, xors them together, and returns bytes """
	result = []
	for i, k in zip(buffer1, list(buffer2)):
		result.append(i^k)
	return bytes(result)

def score_chars(word):
	score = 0
	for char in word:
		if re.match("[A-Za-z ]", char):
			score = score+1
	return score

def decode_single_byte_xor_cypher(hex_str, retkey=False):
	#import pdb; pdb.set_trace()
	max_score = 0
	best_match = ""
	for key in range(255):
		xor_result = [chr(byte ^ key) for byte in list(decode_hex(hex_str)[0])]
		xor_result = ''.join(xor_result)
		score = score_chars(xor_result)
		if score > max_score:
			max_score = score
			best_match = xor_result
			best_key = key
	if retkey:
		return [best_match, best_key]
	else:
		return best_match

def detect_single_byte_xor_cypher(infile):
	max_score = 0
	best_match = ""
	with open(infile) as f:
		for line in f:
			xor_result = decode_single_byte_xor_cypher(line.rstrip())
			score = score_chars(xor_result)
			if score > max_score:
				max_score = score
				best_match = xor_result
	return best_match.rstrip()

def next_key(keystring):
	cycle("keystring")

def repeating_key_xor_encrypt(plaintext, key):
	keychargen = cycle(key)
	result = ""
	for plainchar in plaintext:
		# Plainchar is a unicode string.  We get the ascii value of that representation,
		# then XOR it against the next value in the key iterator.  Then we find out what the
		# resultant character is.
		result = result + str(ord(plainchar) ^ ord(next(keychargen)))
	return result

def hamming_distance(string1, string2):
	""" Finds the bitwise hamming distance between two b64-encoded strings. """
	diffs = 0
	#string1 = base64.b64decode(string1)
	#string2 = base64.b64decode(string2)
	for x, y in zip (string1, string2):
		# was x.encode("hex")
		# "t" --> hex --> int
		# before it was "t".encode("hex") got us to hex, but we can't convert "t" straight to hex
		# so we need 
		# "t" --> bytes --> hex --> int
		diffs = diffs + bin((int(encode_hex(bytes(x, 'utf-8'))[0], 16)^int(encode_hex(bytes(y, 'utf-8'))[0], 16))).count('1')
	return diffs / 1.0

def guess_keylength(cyphertext):
	smallest_so_far = 999999999999999999999
	true_keylen = None
	for keysize in range(2, 100):  # Test every key size.
		chunks = []
		normalized_distances = []
		# For each potential key, get four chunks o' bytes that are the size of the key.
		for keychunknum in range(4):
			index = keysize*keychunknum
			chunks.append([cyphertext[x] for x in range(index, index+keysize)])

		for i in range(3):
			#import pdb; pdb.set_trace()
			norm_dist = hamming_distance(''.join(chunks[i]), ''.join(chunks[i+1]))
			normalized_distances.append(norm_dist)  # To self: is the b64 stuff going to screw anything up?
		#import pdb; pdb.set_trace()
		avg = float(sum(normalized_distances))/len(normalized_distances)/keysize
		print(avg)
		if avg < smallest_so_far:
			smallest_so_far = avg
			true_keylen = keysize
	return true_keylen

def decrypt_vigenere(infile):
	cyphertext = string_from_file(infile)
	cyphertext = base64.b64decode(cyphertext)
	# keylength = guess_keylength(cyphertext)
	# LOL LET'S MEGA BRUTE FORCE INSTEAD
	max_score = 0
	best_keylen = 0
	best_key = ""
	for keylength in range(2, 40):

		# We want to create a block that contains only the first byte of
		# every block, the second byte of every block, etc, up to KEYLENGTH.
		blocks = defaultdict(str)
		keylength_cycle = cycle(range(keylength))
		for byte in cyphertext:
			index = next(keylength_cycle)
			blocks[index] = blocks[index] + byte
		decoded_chunked = ""
		
		totalkey = ""
		for i in range(keylength):
			value = decode_single_byte_xor_cypher(blocks[i].encode("hex"), retkey=True)
			decoded_text_chunk = value[0]
			totalkey = totalkey + chr(value[1])
			decoded_chunked = decoded_chunked + decoded_text_chunk
			if score_chars(decoded_chunked) > max_score:
				max_score = score_chars(decoded_chunked)
				best_keylen = keylength
				best_key = totalkey
		#print str(keylength) + " score: " + str(score_chars(decoded_chunked)) + " key: " + str(best_key)
	# We now have the best key.
	# Use it to decrypt the file.
	print("Winning")
	best_key_cycle = cycle(best_key)
	for byte in cyphertext:
		sys.stdout.write(chr(ord(byte) ^ ord(next(best_key_cycle))))

# ecb = electronic codebook. doesn't hide data patterns well
# aes: advanced encryption standard
# aside: what characters are allowed in python function definitions? why?
# TODO remove as dup
def decrypt_aes_128_in_ecb_mode(infile, key):
	cyphertext = string_from_file(infile)
	cyphertext = base64.b64decode(cyphertext)
	key = "YELLOW SUBMARINE"
	return AES.new(key).decrypt(cyphertext)

def aes_128_in_ecb_mode(infile, key, action):
	cyphertext = string_from_file(infile)
	cyphertext = base64.b64decode(cyphertext)
	key = "YELLOW SUBMARINE"
	if action == "encrypt":
		return AES.new(key).encrypt(cyphertext)
	elif action == "decrypt":
		return AES.new(key).decrypt(cyphertext)
	else:
		return

# thanks pydocs! https://docs.python.org/3/library/itertools.html#itertools-recipes
def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)

def detect_aes_128_in_ecb_mode(infile):
	""" returns the FIRST probable ciphered block (note: not all) """
	with open(infile) as f:
		for i, line in enumerate(f):
			cyphertext = decode_hex(line.strip())[0]
			# Problem hinted at doing 16 bytes at a time, so let's try that
			sets = []
			for group in grouper(cyphertext, 16):
				sets.append(group)
			if len(set(sets)) < len(sets):
				return ("Line " + str(i) + ": " + str(line.strip()))

def pkcs7_padding(utf8_string, target_length):
	# are strings utf-8 by default?
	bytetext = bytearray(bytes(utf8_string, "utf-8"))
	# is range FIXED here or is it recalculated each time?
	# diff between "append" and "extend" for bytearray?
	for i in range(len(bytetext), target_length):
		bytetext.extend(b'\x04')
	assert(len(bytetext) == target_length)
	return bytetext.decode('utf-8')

# each ciphertext block is *added* to the next plaintext block before the next call to the cipher core
# first plaintext block: has no previous ciphertext block. it's added to the IV
# each plaintext block is XORed with the previous ciphertext block before being encrypted
def decrypt_cbc_mode(infile, key, iv, from_string=False):
	# call ecb: make it encrypt instead of decrypt
	# use XOR function to combine them
	# ...????
	# First block: plaintext & XOR against IV THEN encrypt that
	plaintext = infile if from_string else string_from_file(infile)
	# todo mod iv
	keysize = len(key)
	iv = iv * keysize
	plaintext = base64.b64decode(plaintext)
	prev_block = None
	ciphertext = b''
	for group in grouper(plaintext, keysize):
		if not prev_block:
			prev_block = xor_two_buffers_mod(group, iv)
			ciphertext = ciphertext + prev_block
		else:
			prev_block = xor_two_buffers_mod(prev_block, group)
			ciphertext = ciphertext + prev_block
	import pdb; pdb.set_trace()
	print(list(ciphertext))
	print(ciphertext)
	return ciphertext.decode('utf-8')