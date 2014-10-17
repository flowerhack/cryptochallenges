import base64
import re
from itertools import cycle, zip_longest
from collections import defaultdict
import sys
from Crypto.Cipher import AES
import codecs

decode_hex = codecs.getdecoder("hex_codec")
encode_hex = codecs.getencoder("hex_codec")

# --------- Utility Functions ---------

def _string_from_file(infile):
	"""
	Converts the contents of infile into a single string, sans newlines
	"""
	text = ""
	with open(infile) as f:
		text = "".join(line.strip() for line in f)
	return text

def _display_hex(raw_hex_str):
	"""
	Python's `hex` function gives us a hex-formatted string, but it leaves a 
	`0x` on the front, and if it's a long, it leaves an `L` on the end.  So, 
	we strip those out here
	"""
	return hex(raw_hex_str)[2:].replace("L","")

def _score_chars(word):
	"""
	Assigns a integer 'score' to a string.
	A higher score indicates it is more likely to be an English phrase.
	"""
	score = 0
	for char in word:
		if re.match("[A-Za-z ]", char):
			score = score+1
	return score

def hamming_distance(string1, string2):
	"""
	Finds the bitwise hamming distance between two b64-encoded strings.
	"""
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

# From the pydocs: https://docs.python.org/3/library/itertools.html#itertools-recipes
def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)

# --------- Main Functions ---------

def hex_to_b64(hex_str):
	""" Converts a hex-formatted string into b64 bytes """
	return base64.b64encode(decode_hex(hex_str)[0])

def xor_two_buffers(buffer1, buffer2):
	""" Takes two hex-formatted strings and returns a hex-formatted string """
	return _display_hex(int(buffer1, 16) ^ int(buffer2, 16))

# TODO squash this into the previous method
def xor_two_buffers_mod(buffer1, buffer2):
	""" Takes a string and a bytes, xors them together, and returns bytes """
	result = []
	for i, k in zip(buffer1, list(buffer2)):
		result.append(i^k)
	return bytes(result)

def decode_single_byte_xor_cypher(hex_str, retkey=False):
	"""
	Takes a hex-formatted string which has been encrypted with single-byte xor.
	Returns the decrypted string.
	If retkey is True, we return [decrypted_string, key_used_to_decrypt]
	"""
	max_score = 0
	best_match = ""
	for key in range(255):
		xor_result = [chr(byte ^ key) for byte in list(decode_hex(hex_str)[0])]
		xor_result = ''.join(xor_result)
		score = _score_chars(xor_result)
		if score > max_score:
			max_score = score
			best_match = xor_result
			best_key = key
	if retkey:
		return [best_match, best_key]
	else:
		return best_match

def detect_single_byte_xor_cypher(infile):
	"""
	Given a file of hex-formatted strings, determine which one has been 
	encrypted with single-byte xor and return it 
	"""
	max_score = 0
	best_match = ""
	with open(infile) as f:
		for line in f:
			xor_result = decode_single_byte_xor_cypher(line.rstrip())
			score = _score_chars(xor_result)
			if score > max_score:
				max_score = score
				best_match = xor_result
	return best_match.rstrip()

def repeating_key_xor_encrypt(plaintext, key):
	"""
	Given plaintext and key, uses key to encrypt plaintext via repeating XOR
	and returns the result
	"""
	keychargen = cycle(key)
	result = ""
	for plainchar in plaintext:
		# Plainchar is a unicode string.  We get the ascii value of that representation,
		# then XOR it against the next value in the key iterator.  Then we find out what the
		# resultant character is.
		result = result + str(ord(plainchar) ^ ord(next(keychargen)))
	return result

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
			norm_dist = hamming_distance(''.join(chunks[i]), ''.join(chunks[i+1]))
			normalized_distances.append(norm_dist)  # To self: is the b64 stuff going to screw anything up?
		avg = float(sum(normalized_distances))/len(normalized_distances)/keysize
		print(avg)
		if avg < smallest_so_far:
			smallest_so_far = avg
			true_keylen = keysize
	return true_keylen

def decrypt_vigenere(infile):
	cyphertext = _string_from_file(infile)
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
			if _score_chars(decoded_chunked) > max_score:
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
	cyphertext = _string_from_file(infile)
	cyphertext = base64.b64decode(cyphertext)
	key = "YELLOW SUBMARINE"
	return AES.new(key).decrypt(cyphertext)

def aes_128_in_ecb_mode(infile, key, action, from_string=False, from_b64=True):
	"""
	Allows encrypt or decryption via AES-128 in ECB mode
	If action=="encrypt", this encrypts the contents of infile with key and returns the result.
	If action=="decrypt", this instead returns the *decrypted* contents of infile.
	Else, returns None.
	"""
	cyphertext = infile if from_string else _string_from_file(infile)
	cyphertext = cyphertext if not from_b64 else base64.b64decode(cyphertext)
	key = "YELLOW SUBMARINE"
	if action == "encrypt":
		return AES.new(key).encrypt(cyphertext)
	elif action == "decrypt":
		return AES.new(key).decrypt(cyphertext)
	else:
		return

def detect_aes_128_in_ecb_mode(infile):
	"""
	Detects which line in infile has been encrypted with AES-128 in ECB mode 
	and returns that line.

	Note: this returns the FIRST probable ciphered line, not ALL probable 
	ciphered lines.
	"""
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
def cbc_mode(infile, key, iv, action, from_string=False, is_b64=True):
	# call ecb: make it encrypt instead of decrypt
	# use XOR function to combine them
	# ...????
	# First block: plaintext & XOR against IV THEN encrypt that
	#import pdb; pdb.set_trace()
	text = infile if from_string else _string_from_file(infile)
	keysize = len(key)
	iv = iv * keysize  # TODO mod iv
	text = base64.b64decode(text) if is_b64 else text
	prev_block = None
	modtext = b''

	if action == "encrypt":
		for group in grouper(text, keysize):
			if not prev_block:
				prev_block = xor_two_buffers_mod(group, iv)
				modtext = modtext + aes_128_in_ecb_mode(prev_block, key, "encrypt", from_string=True, from_b64=False)
			else:
				filtered_group = [0 if i is None else i for i in group]
				prev_block = xor_two_buffers_mod(prev_block, filtered_group)
				modtext = modtext + aes_128_in_ecb_mode(prev_block, key, "encrypt", from_string=True, from_b64=False)
		return modtext

	elif action == "decrypt":
		for group in grouper(text, keysize):
			if not prev_block:
				prev_block = bytes(group)
				temp_block = aes_128_in_ecb_mode(prev_block, key, "encrypt", from_string=True, from_b64=False)
				plain_block = xor_two_buffers_mod(temp_block, iv)
				modtext = modtext + plain_block
			else:
				filtered_group = bytes([0 if i is None else i for i in group])
				temp_block = aes_128_in_ecb_mode(filtered_group, key, "encrypt", from_string=True, from_b64=False)
				plain_block = xor_two_buffers_mod(temp_block, prev_block)
				modtext = modtext + plain_block
		return modtext

	else:
		return
