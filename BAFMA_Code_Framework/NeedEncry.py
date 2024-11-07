
import random
import string
def generate_random_key(min:int,max:int)->bytearray:
    """
    parameter specification:
        min: int, the minimum size of key
        max: int, the maximum size of key
    return specification:
        key: bytearray, the key
        kSize: int, the size of key
    """
    key = []
    kSize = random.randint(min,max)
    for i in range(kSize):
        key.append(random.randint(0,255))
    return bytearray(key),kSize


# generate a random string with length n, and store it in output
def generate_random_string(min:int,max:int)->str:
    n = random.randint(min,max)
    output = ""

    # uppercase letters + lowercase letters + numbers + punctuation
    choice_chars = string.ascii_letters + string.digits + '!@#$%^&()_+=-'

    for i in range(n):
        output += random.choice(choice_chars)
    return output    



# need to add decryption code here (Corresponding encryption code in NeedEncry.py file)
def encrypt(pBuffer: bytearray, bSize: int, pKey: bytearray, kSize: int) -> (bytearray, int):
    """
    parameter specification:
        pBuffer: bytearray, the buffer of plain text
        bSize: int, the size of plain text
        pKey: bytearray, the key
        kSize: int, the size of key
    
    return specification
        EncData: bytearray, the buffer of encrypted text
        EncDataSize: int, the size of encrypted text
    """
    pNewBuffer = pBuffer
    return pNewBuffer, bSize * 2

