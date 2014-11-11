import base64
import re
from itertools import cycle, zip_longest
from collections import defaultdict
import sys
from Crypto.Cipher import AES
import codecs
from random import randint, choice

decode_hex = codecs.getdecoder("hex_codec")
encode_hex = codecs.getencoder("hex_codec")

# ------------------ Utility Functions ------------------

class PaddingException(Exception):
    """
    Thrown when a function expecting a PKCS7-padded string receives a string
    with invalid padding
    """
    pass


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


# TODO this is only used in one test
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


# TODO remove the from_b64 flag
def aes_128_in_ecb_mode(instring, key, action, from_b64=True):
    """
    Allows encrypt or decryption via AES-128 in ECB mode
    If action=="encrypt", this encrypts the contents of infile with key and returns the result.
    If action=="decrypt", this instead returns the *decrypted* contents of infile.
    Else, returns None.
    """
    cyphertext = instring
    cyphertext = cyphertext if not from_b64 else base64.b64decode(cyphertext)
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

def strip_padding(padded_string):
    """
    Strips away the PKCS7 padding from a string and returns it. If padding is
    invalid, raises a PaddingException
    """
    reversed_input = padded_string[::-1]
    # 01 is valid, 02 02 is valid, 03 03 03 is valid...
    for i in range(1, len(reversed_input)):
        if [val for val in reversed_input[0:i]] == [i for num in range(0,i)]:
            return padded_string[:-i]


def pkcs7_padding(utf8_string, target_blocksize, padding_amount=False):
    """
    Takes a string and pads it to target_blocksize length.
    If padding_amount is set, this will instead just add that amount to the end.
    """
    bytetext = bytearray(utf8_string)
    if not padding_amount:
        padding_amount = target_blocksize - (len(bytetext) % target_blocksize)
    for i in range(0, padding_amount):
        bytetext.extend(bytes([padding_amount]))
    return bytetext


# I found the diagram on the CBC wikipedia article very helpful for this!
# https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29
# TODO clean this up wow it's super ugly and I bet we're using it again too
# start by removing from_b64 flag and make iv optional
def cbc_mode(instring, key, iv, action, from_b64=True):
    # Read in the string, if it's from a file
    text = instring
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
            prev_block = aes_128_in_ecb_mode(temp_block, key, "encrypt", from_b64=False)
            modtext = modtext + prev_block
        return modtext

    elif action == "decrypt":
        for group in grouper(text, keysize):
            filtered_group = bytes([0 if i is None else i for i in group])
            # Decrypt the current block
            temp_block = aes_128_in_ecb_mode(filtered_group, key, "decrypt", from_b64=False)
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


def random_length_bytes():
    """ Generates a random sequence of bytes, with a random length between 1 and 25 """
    return bytes([randint(0,255) for i in range(0, randint(1,25))])


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
        encrypted = (aes_128_in_ecb_mode(instring, key, "encrypt", from_b64=False), "ECB")
    else:
        encrypted = (cbc_mode(instring, key, iv, "encrypt", from_b64=False), "CBC")
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


# TODO could probably squash this into something else
def magic_text_oracle(instring, key, magic_text, add_rand_chars=True, action="encrypt"):
    """
    Encrypts `instring` + `magic_text` using ECB mode and the given key.
    """
    instring = instring + magic_text
    encrypted = ""
    blocksize = 16
    iv = blocksize * b'\x00'

    if add_rand_chars:
        # We want to prepend 5-10 random bytes and appends 5-10 random bytes
        to_prepend = bytes([randint(0, 255) for i in range(0, randint(5, 10))])
        to_append = bytes([randint(0, 255) for i in range(0, randint(5, 10))])
    else:
        to_prepend = b''
        to_append = b''

    # We'll need to pad instring s.t. len(to_prepend + instring + padding + to_append) % 16 == 0
    padding_amount = (blocksize - len(to_prepend + instring + to_append) % 16)
    instring = to_prepend + pkcs7_padding(instring, blocksize, padding_amount) + to_append
    instring = bytes(instring)

    return aes_128_in_ecb_mode(instring, key, action, from_b64=False)


# TODO this is done elsewhere, use this function there rather than the dupe
# also this is wonky can't we just hand it encrypted text?
def detect_block_size(key):
    """
    Detects the blocksize used for encryption.
    If it cannot be detected, or the blocksize is not between 4 and 256,
    returns None.
    """
    for potential_blocksize in range(4, 256):
        test_str = bytes("".join([chr(i) for i in [randint(65,90) for j in range(0, potential_blocksize)]]), "utf-8")
        crypted = magic_text_oracle(test_str*25, key, b'', add_rand_chars=False)
        sets = []
        for group in grouper(crypted, potential_blocksize):
            sets.append(group)
        if len(set(sets)) == 2:
            return potential_blocksize
    return None


def craft_input_block(target_size):
    """ Returns a bytestring of 'AAA...'s, with length target_size """
    return b'A' * target_size


# could probably better separate concerns
def decrypt_magic_text(magic_text, key):
    """ Decrypts magic_text using byte-at-a-time decryption """
    magic_text = base64.b64decode(magic_text)
    block_size = detect_block_size(key)  # is 16, but we compute anyway
    input_block = craft_input_block(block_size-1)
    inputs_dict = {}
    result = b''
    magic_size = len(magic_text)

    # craft the attack dictionary
    for j in range(256):
        new_input = input_block + bytes([j])
        new_input_result = magic_text_oracle(new_input, key, magic_text, add_rand_chars=False)
        inputs_dict[new_input_result[0:block_size]] = j

    for i in range(magic_size):
        this_magic = magic_text[i:magic_size]
        byte_short_result = magic_text_oracle(input_block, key, this_magic, add_rand_chars=False)[0:block_size]
        result = result + bytes(chr(inputs_dict[byte_short_result]), "utf-8")

    return result

def fetch(block_size, random_prepend, key):
    cached_size = None
    for i in range(0, block_size+1):
        crafted_input = b'A' * i
        if not cached_size:
            cached_size = len(magic_text_oracle(random_prepend + crafted_input, key, b'', add_rand_chars=False))
        else:
            temp = len(magic_text_oracle(random_prepend + crafted_input, key, b'', add_rand_chars=False))
            if (temp > (cached_size + 1)):
                pad_for_rand = b'A' * (i-1)
                assert(((len(random_prepend) + (len(pad_for_rand)+1)) % block_size) == 0)
                return pad_for_rand

def decrypt_magic_text_harder(magic_text, key, random_prepend):
    """
    Decrypts magic_text using byte_at_a_time decryption, when random_prepend is 
    being prepended to all calls
    """
    magic_text = base64.b64decode(magic_text)
    block_size = detect_block_size(key)  # is 16, but we compute anyway
    input_block = craft_input_block(block_size-1)
    inputs_dict = {}
    result = b''
    magic_size = len(magic_text)

    # We need to figure out the size of the random_prepend.  We can probably
    # do this by figuring out at what point the block size "jumps"...
    # Suppose block size 8.  3 + 5 --> 8.  4 + 4 --> 8... 8 + 1 --> 16!
    # So we need to find when block size "jumps" by n-1, where n is block size\
    pad_for_rand = fetch(block_size, random_prepend, key)

    # Now we know that random_prepend + pad_for_rand gets us a nice block with one free byte at the end.
    # We can craft an attack dictionary based on this.
    size_to_slice = len(random_prepend) + len(pad_for_rand) + 1
    for j in range(256):
        # new_input is going to be random_prepend + pad_for_rand + a target byte
        new_input = random_prepend + pad_for_rand + bytes([j])
        new_input_result = magic_text_oracle(new_input, key, magic_text, add_rand_chars=False)
        inputs_dict[new_input_result[0:size_to_slice]] = j

    for i in range(magic_size):
        this_magic = magic_text[i:magic_size]
        byte_short_result = magic_text_oracle(random_prepend + pad_for_rand, key, this_magic, add_rand_chars=False)[0:size_to_slice]
        result = result + bytes(chr(inputs_dict[byte_short_result]), "utf-8")

    return result


def parse_kv(instring):
    # this is the silliest dictionary comprehension
    return {i[0]: i[1] for i in [j.split("=") for j in [i for i in instring.split("&")]]}

def profile_for(email):
    email = email.replace("&", "\&").replace("=", "\=")
    uid = 10  # being lazy :D;;;
    role = 'user'
    return ("email=" + email + "&uid=" + str(uid) + "&role=" + role)

def copypasta_attack():
    key = random_aes_key()
    my_plaintext = profile_for("julia@flowerhack.com")
    my_encrypted_text = magic_text_oracle(bytes(my_plaintext, "utf-8"), key, b'', add_rand_chars=False)
    my_decrypted_text = magic_text_oracle(my_encrypted_text, key, b'', add_rand_chars=False, action="decrypt")

    # only use user input for profile_for and ciphertexts to make an admin

def strip_padding(padded_string):
    """
    Strips away the PKCS7 padding from a string and returns it. If padding is
    invalid, raises a PaddingException
    """
    reversed_input = padded_string[::-1]
    # 01 is valid, 02 02 is valid, 03 03 03 is valid...
    for i in range(1, len(reversed_input)):
        if [val for val in reversed_input[0:i]] == [i for num in range(0,i)]:
            return padded_string[:-i]
    raise PaddingException

def insert_in_query_and_cbc_encrypt(inbytes, key):
    """ Inserts user input into the querystring provided in challenge 16 """
    prepend = b'comment1=cooking%20MCs;userdata='
    append = b';comment2=%20like%20a%20pound%20of%20bacon'
    newbytes = (prepend + inbytes.replace(b';', b'\;').replace(b'=', b'\=') + append)
    paddedbytes = pkcs7_padding(newbytes, 16)
    crypted = cbc_mode(paddedbytes, key, b'\x00', "encrypt", from_b64=False)
    return crypted

def find_admin_user_in_cbc_encrypted_text(inbytes, key):
    """
    Takes a CBC encrypted byte object and sees if the decrypted result has an
    admin user
    """
    decrypted = cbc_mode(inbytes, key, b'\x00', "decrypt", from_b64=False)
    if b';admin=true' in decrypted:
        return True
    else:
        return False

def bitfip_attack(inbytes, key):
    """
    Very narrowly focused on the attack in challenge 16.
    Could mod later to make reusable probs
    """
    byte_pos_first = None
    byte_pos_second = None
    for i in range(0, 256):
        temp = cbc_mode(inbytes[0:37] + bytes([i]) + inbytes[38:], key, b'\x00', "decrypt", from_b64=False)
        if b';admin' in temp:
            byte_pos_first = i
    for i in range(0, 256):
        temp = cbc_mode(inbytes[0:43] + bytes([i]) + inbytes[44:], key, b'\x00', "decrypt", from_b64=False)
        if b'admin=' in temp:
            byte_pos_second = i
    return (inbytes[0:37] + bytes([byte_pos_first]) + inbytes[38:43] + bytes([byte_pos_second]) + inbytes[44:])

def cbc_crypt_random_line(infile, key, from_b64=False):
    random_line = bytes(choice(open(infile).readlines()), "utf-8")
    iv = b'\x00'
    crypted = cbc_mode(pkcs7_padding(random_line, 16), key, iv, "encrypt", from_b64=from_b64)
    return (crypted, iv)

def cbc_padding_oracle(cyphertext, key, iv):
    decrypted = cbc_mode(cyphertext, key, iv, "decrypt", from_b64=False)
    try:
        strip_padding(decrypted)
        return True
    except PaddingException:
        return False

def attack_cbc(cyphertext, key, iv, ref):
    #last_cypherblock = cyphertext[-16:]
    #nextlast_cypherblock = cyphertext[-32:-16]
    # ASSUMING KEYSIZE=16 FOR LIKE EVERYTHING i am a terrible hardcoding person sorry
    plaintext = bytearray(16)
    last_cypherblock = cyphertext[-16:]
    nextlast_cypherblock = cyphertext[:-16][-16:]
    guessed_bytes = bytes(0)
    expected_byte = 1
    for position in reversed(range(16)):
        # We are currently decoding the plaintext that corresponds to last cypherblock.
        for i in range(0, 256):
            fake_cyphertext = bytes(position) + bytes([i]) + guessed_bytes + last_cypherblock
            if cbc_padding_oracle(fake_cyphertext, key, iv):
                # in this case we think i must be the value of th plaintext at that spot?
                #import pdb; pdb.set_trace()
                # that is, p = p'[16] ^ i/c'[16] ^ c[16]
                plaintext[position] = expected_byte ^ i ^ nextlast_cypherblock[position]
                expected_byte = expected_byte + 1
                # we want a new c'[16] such that p'[16] is 2, so
                #  c'[16] = p'[16] ^ p[16] ^ c[16]
                #last = bytes([expected_byte ^ plaintext[position] ^ nextlast_cypherblock[position]])
                guessed_bytes = bytes([expected_byte ^ plaintext[position] ^ nextlast_cypherblock[position]]) + guessed_bytes
    return plaintext
