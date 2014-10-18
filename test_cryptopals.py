import cryptopals
import base64
import solutions


def equals(a, b):
    if a == b:
        return True
    else:
        return False

# Problem 1.1: Convert hex to base64
assert equals(
    cryptopals.hex_to_b64(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f6973"\
        "6f6e6f7573206d757368726f6f6d"
    ),
    b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
)

# Problem 1.2: Fixed XOR
assert equals(
    cryptopals.xor_two_buffers(
        "1c0111001f010100061a024b53535009181c",
        "686974207468652062756c6c277320657965"
    ),
    "746865206b696420646f6e277420706c6179"
)

# Problem 1.3: Single-byte XOR cipher
assert equals(
    cryptopals.decode_single_byte_xor_cypher(
        b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    ),
    "Cooking MC's like a pound of bacon"
)

# Problem 1.4: Detect single-character XOR
assert equals(
    cryptopals.detect_single_byte_xor_cypher("testfiles/4.txt"),
    "Now that the party is jumping"
)

# Problem 1.5: Implement repeating-key XOR
cryptopals.repeating_key_xor_encrypt(
    "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
    "ICE"
)

# Problem 1.6: Break repeating-key XOR
assert equals(
    cryptopals.hamming_distance(
        "this is a test",
        "wokka wokka!!!"
    ),
    37
)

# Temporarily disabled since we're using brute force and it's time-consuming
# cryptopals.decrypt_vigenere("6.txt")

# key is "Terminator X: Bring the noise"
# decrypted is lyrics to "Play that Funky Music"

# Problem 1.7: AES in ECB mode
assert equals(
    cryptopals.aes_128_in_ecb_mode("testfiles/7.txt", "YELLOW SUBMARINE", "decrypt"),
    solutions.soln_7
)

crypted = cryptopals.aes_128_in_ecb_mode(solutions.snake_wounded, "YELLOW SUBMARINE", "encrypt", from_string=True, from_b64=False)
assert equals(
    cryptopals.aes_128_in_ecb_mode(crypted, "YELLOW SUBMARINE", "decrypt", from_string=True, from_b64=False),
    solutions.snake_wounded
)

# Problem 1.8: Detect AES in ECB mode
assert equals(
    cryptopals.detect_aes_128_in_ecb_mode("testfiles/8.txt"),
    solutions.soln_8
)

# Problem 2.1 (9): Implement PKCS#7 padding
assert equals(
    cryptopals.pkcs7_padding(b'YELLOW SUBMARINE', 20),
    b'YELLOW SUBMARINE\x04\x04\x04\x04'
)

# Problem 2.2 (10): Implement CBC mode
cbc_snake = (
    cryptopals.cbc_mode(
        solutions.snake_wounded,
        "YELLOW SUBMARINE",
        b'\x00',
        "encrypt",
        from_string=True,
        from_b64=False
    )
)

decoded_cbc_snake = (
    cryptopals.cbc_mode(
        cbc_snake,
        "YELLOW SUBMARINE",
        b'\x00',
        "decrypt",
        from_string=True,
        from_b64=False
    )
)

assert equals(solutions.snake_wounded, decoded_cbc_snake)

assert equals(
    cryptopals.cbc_mode(
        "testfiles/10.txt", "YELLOW SUBMARINE", b'\x00', "decrypt"
    ).decode('utf-8'),
    solutions.soln_10
)

# Problem 2.3 (11): An ECB/CBC detection oracle
for i in range(0, 10):
    input = solutions.soln_10
    encrypted, mode = cryptopals.encryption_oracle(input)
    assert equals(cryptopals.detect_ecb_or_cbc(encrypted), mode)

# TODO: Problem 2.4 (12): Byte-at-a-time ECB decryption (Simple)
consistent_key = cryptopals.random_aes_key()
#magic_text = solutions.problem_12
#print(solutions.problem_12)
#print(cryptopals.problem12(my_input, consistent_key, magic_text))
print(cryptopals.decrypt_magic_text(solutions.problem_12, consistent_key))

# TODO: Problem 2.5 (13): ECB cut-and-paste
