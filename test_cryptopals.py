import cryptopals
import base64
import solutions

def equals(a,b):
	if a == b:
		return True
	else:
		return False

# Problem 1.1
assert equals(
	cryptopals.hex_to_b64("49276d206b696c6c696e6720796f757220627261696e206c69"\
						  "6b65206120706f69736f6e6f7573206d757368726f6f6d"),
	"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
)

# Problem 1.2
assert equals(
	cryptopals.xor_two_buffers(
		"1c0111001f010100061a024b53535009181c",
		"686974207468652062756c6c277320657965"
	),
	"746865206b696420646f6e277420706c6179"
)

# Problem 1.3
assert equals(
	cryptopals.decode_single_byte_xor_cypher(
		"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	),
	"Cooking MC's like a pound of bacon"
)

# Problem 1.4
assert equals(
	cryptopals.detect_single_byte_xor_cypher("4.txt"),
	"Now that the party is jumping"
)

# Problem 1.5
cryptopals.repeating_key_xor_encrypt("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE")

# Problem 1.6

assert equals(
	cryptopals.hamming_distance(
		"this is a test",
		"wokka wokka!!!"
	),
	37
)

#cryptopals.decrypt_vigenere("6.txt")

# key is "Terminator X: Bring the noise"
# decrypted is lyrics to "Play that Funky Music"

# Problem 1.7
assert equals(
	cryptopals.decrypt_aes_128_in_ecb_mode("7.txt", "YELLOW SUBMARINE"),
	solutions.soln_7
)

# Problem 1.8
assert equals(
	cryptopals.detect_aes_128_in_ecb_mode("8.txt"),
	solutions.soln_8
)

# Problem 2.1 (9)
assert equals(
	cryptopals.pkcs7_padding("YELLOW SUBMARINE", 20),
	"YELLOW SUBMARINE\x04\x04\x04\x04"
)

# Problem 2.2 (10)
print(cryptopals.encrypt_cbc_mode("operationsnakeeater.txt", "YELLOW SUBMARINE", b'\x00', from_string=True))
print(cryptopals.decrypt_cbc_mode())

print(cryptopals.decrypt_cbc_mode("10.txt", "YELLOW SUBMARINE", b'\x00'))

# PRoblem 2.3 (11)

# Problem 2.4 (12)