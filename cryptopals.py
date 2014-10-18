import base64
import re
from itertools import cycle, zip_longest
from collections import defaultdict
import sys
from Crypto.Cipher import AES
import codecs
from random import randint

decode_hex = codecs.getdecoder("hex_codec")
encode_hex = codecs.getencoder("hex_codec")

# ------------------ Utility Functions ------------------


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
    return hex(raw_hex_str)[2:].replace("L", "")


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


# TODO clean this one up
def hamming_distance(string1, string2):
    """
    Finds the bitwise hamming distance between two b64-encoded strings.
    """
    diffs = 0
    for x, y in zip (string1, string2):
        diffs = diffs + bin((int(encode_hex(bytes(x, 'utf-8'))[0], 16) ^ int(encode_hex(bytes(y, 'utf-8'))[0], 16))).count('1')
    return diffs / 1.0


# From the pydocs: https://docs.python.org/3/library/itertools.html#itertools-recipes
def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)

# ------------------ Main Functions ------------------


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
        result.append(i ^ k)
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


# This is a "lazy" vignere decrypter; it's using brute force.
# TODO come back and make it less brute-force-y
def decrypt_vigenere(infile):
    cyphertext = _string_from_file(infile)
    cyphertext = base64.b64decode(cyphertext)
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

    # We now have the best key.
    # Use it to decrypt the file.
    best_key_cycle = cycle(best_key)
    for byte in cyphertext:
        sys.stdout.write(chr(ord(byte) ^ ord(next(best_key_cycle))))


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


def detect_ecb(cyphertext):
    """ Returns True if cyphertext appears to be ECB-encrypted; else False """
    sets = []
    for group in grouper(cyphertext, 16):
        sets.append(group)
    if len(set(sets)) < len(sets):
        return True
    return False


def detect_aes_128_in_ecb_mode(infile):
    """
    Detects which line in `infile` has been encrypted with AES-128 in ECB mode
    and returns that line.

    Note: this returns the FIRST probable ciphered line, not ALL probable
    ciphered lines.
    """
    with open(infile) as f:
        for i, line in enumerate(f):
            cyphertext = decode_hex(line.strip())[0]
            # Problem hinted at doing 16 bytes at a time, so let's try that
            if detect_ecb(cyphertext):
                return ("Line " + str(i) + ": " + str(line.strip()))


def pkcs7_padding(utf8_string, target_blocksize, padding_amount=False):
    """
    Takes a string and pads it to target_blocksize length.
    If padding_amount is set, this will instead just add that amount to the end.
    """
    bytetext = bytearray(utf8_string)
    if not padding_amount:
        padding_amount = target_blocksize - (len(bytetext) % target_blocksize)
    for i in range(0, padding_amount):
        bytetext.extend(b'\x04')
    return bytetext


# I found the diagram on the CBC wikipedia article very helpful for this!
# https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29
# TODO clean this up wow it's super ugly and I bet we're using it again too
def cbc_mode(infile, key, iv, action, from_string=False, from_b64=True):
    # Read in the string, if it's from a file
    text = infile if from_string else _string_from_file(infile)
    # b64decode the string, if it's in b64 format
    text = base64.b64decode(text) if from_b64 else text
    keysize = len(key)
    iv = iv * keysize
    # In CBC, we'll be XORing each block against the previous block, so:
    prev_block = None
    # This will hold the result of either our decryption or encryption
    modtext = b''

    if action == "encrypt":
        for group in grouper(text, keysize):
            filtered_group = bytes([0 if i is None else i for i in group])
            # If we're on the first block, XOR against IV; else, XOR against prev_block
            if not prev_block:
                temp_block = xor_two_buffers_mod(filtered_group, iv)
            else:
                temp_block = xor_two_buffers_mod(prev_block, filtered_group)
            # then encrypt & append to modtext
            prev_block = aes_128_in_ecb_mode(temp_block, key, "encrypt", from_string=True, from_b64=False)
            modtext = modtext + prev_block
        return modtext

    elif action == "decrypt":
        for group in grouper(text, keysize):
            filtered_group = bytes([0 if i is None else i for i in group])
            # Decrypt the current block
            temp_block = aes_128_in_ecb_mode(filtered_group, key, "decrypt", from_string=True, from_b64=False)
            # If we're on the first block, XOR against IV; else, XOR against prev_block
            if not prev_block:
                plain_block = xor_two_buffers_mod(temp_block, iv)
            else:
                plain_block = xor_two_buffers_mod(temp_block, prev_block)
            modtext = modtext + plain_block
            prev_block = filtered_group
        return modtext

    else:
        return

def random_aes_key():
    """ Generates a random AES key (16 bytes in length) """
    return bytes([randint(0,255) for i in range(0, 16)])

def encryption_oracle(instring):
    """
    Encrypts `instring` using either ECB or CBC (choosing between the two at random).
    """
    instring = bytes(instring, "utf-8")
    encrypted = ""
    blocksize = 16
    iv = blocksize * b'\x00'
    key = random_aes_key()

    # We want to prepend 5-10 random bytes and appends 5-10 random bytes
    to_prepend = bytes([randint(0, 255) for i in range(0, randint(5, 10))])
    to_append = bytes([randint(0, 255) for i in range(0, randint(5, 10))])

    # We'll need to pad instring s.t. len(to_prepend + instring + padding + to_append) % 16 == 0
    padding_amount = (blocksize - len(to_prepend + instring + to_append) % 16)
    instring = to_prepend + pkcs7_padding(instring, blocksize, padding_amount) + to_append
    instring = bytes(instring)

    if randint(0, 1) == 0:
        encrypted = (aes_128_in_ecb_mode(instring, key, "encrypt", from_string=True, from_b64=False), "ECB")
    else:
        encrypted = (cbc_mode(instring, key, iv, "encrypt", from_string=True, from_b64=False), "CBC")
    return encrypted

def detect_ecb_or_cbc(input):
    """
    This is super-lazy and just assumes, if it's not ECB, must be CBC! It works
    for the purpose of the cryptochallenges (so far) but could be better :D;;;
    """
    if detect_ecb(input):
        return "ECB"
    else:
        return "CBC"

def problem12(input, key, magic_text):
    aes_128_in_ecb_mode(input, key, "encrypt", from_string=True, from_b64=True)

    """
    Encrypts `input` using either ECB or CBC (choosing between the two at random).
    """
    encrypted = ""
    blocksize = 16
    iv = blocksize * b'\x00'
    magic_text = base64.b64decode(magic_text)
    input = magic_text + bytes(input)
    # Converts input to bytes, prepends 5-10 random bytes, and appends 5-10 random bytes
    to_prepend = bytes([randint(0, 255) for i in range(0, randint(5, 10))])
    to_append = bytes([randint(0, 255) for i in range(0, randint(5, 10))])
    temp = to_prepend + bytes(input, "utf-8") + to_append
    padding_amount = (blocksize - len(temp) % 16)
    input = pkcs7_padding(input, blocksize, padding_amount)
    input = to_prepend + bytes(input, "utf-8") + to_append
    input = bytes(input)
    encrypted = (aes_128_in_ecb_mode(input, key, "encrypt", from_string=True, from_b64=False), "ECB")
    return encrypted
