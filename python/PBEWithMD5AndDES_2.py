import base64
import hashlib
import re
import os
from Crypto.Cipher import DES

"""
Note about PBEWithMD5AndDES in java crypto library:
Encrypt:
  Generate a salt (random): 8 bytes
  <start derived key generation>
  Append salt to the password
  MD5 Hash it, and hash the result, hash the result ... 1000 times
  MD5 always gives us a 16 byte hash
  Final result: first 8 bytes is the "key" and the next is the "initialization vector"
  (there is something about the first 8 bytes needing to be of odd paraity, therefore
  the least significant bit needs to be changed to 1 if required. We don't do it,
  maybe the python crypto library does it for us)
  <end derived key generation>
  Pad the input string with 1-8 bytes (note: not 0-7, so we always have padding)
    so that the result is a multiple of 8 bytes. Padding byte value is same as number of
    bytes being padded, eg, \x07 if 7 bytes need to be padded.
  Use the key and iv to encrypt the input string, using DES with CBC mode.
  Prepend the encrypted value with the salt (needed for decrypting since it is random)
  Base64 encode it -> this is your result
Decrypt:
  Base64 decode the input message
  Extract the salt (first 8 bytes). The rest is the encoded text.
  Use derived key generation as in Encrypt above to get the key and iv
  Decrypt the encoded text using key and iv
  Remove padding -> this is your result
"""

def get_derived_key(password, salt, count):
    print(list(salt))
    key = bytes(password, encoding="UTF-8") + bytes(salt)
    for i in range(count):
        m = hashlib.md5(key)
        key = m.digest()


    print(list(key))
    return (key[:8], key[8:])

def decrypt(msg, password):
    msg_bytes = base64.b64decode(msg)
    salt = msg_bytes[:8]
    enc_text = msg_bytes[8:]
    (dk, iv) = get_derived_key(password, salt, 1000)
    crypter = DES.new(dk, DES.MODE_CBC, iv)
    text = crypter.decrypt(enc_text)
    # remove the padding at the end, if any
    print(text.decode("UTF-8"))
    return re.sub(r'[\x01-\x08]','',text.decode("UTF-8"))

def encrypt(msg, password):
    salt = os.urandom(8)
    pad_num = 8 - (len(msg) % 8)
    for i in range(pad_num):
        msg += chr(pad_num)


    (dk, iv) = get_derived_key(password, salt, 1000)

    crypter = DES.new(dk, DES.MODE_CBC, iv)

    enc_text = crypter.encrypt(msg.encode('UTF-8'))
    return base64.b64encode(salt + enc_text)

def main():


    msg = ""
    passwd = ""

    passwd += input("输入口令：")
    print("你输入的口令是：%s" % passwd)
    par_type = input("输入D：解密  E:加密 其他：退出")
    if (par_type == "D"):
        msg = input("请输入密文：")
        print(decrypt(msg, passwd))

    elif (par_type == "E"):
        msg = input("请输入明文：")
        print(re.sub(r'[\x01-\x08]', '', encrypt(msg, passwd).decode("UTF-8")))




if __name__ == "__main__":
    main()
